# src/graph.py
from __future__ import annotations
from typing import Dict, List, Optional
from langgraph.graph import StateGraph, START, END
from domains import SOCState, ActionLog, Alert
from tools import search_internal_data, search_external_osint, XSOARClient, notify_soc
from agents import validity_agent, severity_agent, exploitability_agent, playbook_agent, decision_agent
from config import load_policy
import json, os, time
from datetime import datetime


xsoar = XSOARClient()
OBS_LOG = os.getenv("A2A_OBS_LOG", "a2a_observability.log")

# --------- Graph Node Implementations ---------

def _emit_observable(event: str, **details):
    rec = {"ts": datetime.utcnow().isoformat(), "event": event, "details": details}
    try:
        with open(OBS_LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass

# Emit a single log entry as a delta (list), so the reducer can append it
def log_event(event: str, **details):
    """Return a delta list AND write to audit file."""
    _emit_observable(event, **details)
    return [ActionLog(event=event, details=details)]

def log(state: SOCState, event: str, **details) -> List[ActionLog]:
    logs = state.get("logs", [])
    logs.append(ActionLog(event=event, details=details))
    _emit_observable(event, **details)
    return logs

def enrich_node(state: SOCState) -> SOCState:
    alert: Alert = state["alert"]
    internal_hits, external_hits = [], []
    for ind in alert.indicators:
        internal_hits.extend(search_internal_data(ind.value))
        if ind.type in ("ip", "domain", "url"):
            external_hits.extend(search_external_osint(ind.value))
    enrichment = {"internal": internal_hits, "external": external_hits}
    return {
        "enrichment": enrichment,
        "logs": log_event("enriched", internal=len(internal_hits), external=len(external_hits)),
    }
from a2a_clients import (
    call_validity_a2a,
    call_severity_a2a,
    call_exploitability_a2a,
)
def validity_node(state: SOCState) -> SOCState:
    alert = state["alert"]
    enrichment = state["enrichment"]
    score = call_validity_a2a(alert, enrichment)
    return {
        "validity": score,
        "logs": log_event("scored_validity_a2a", score=score.model_dump()),
    }
    #score = validity_agent(state["alert"], state["enrichment"])
    #return {"validity": score, "logs": log_event("scored_validity", score=score.model_dump())}

def severity_node(state: SOCState) -> SOCState:
    alert = state["alert"]
    enrichment = state["enrichment"]
    score = call_severity_a2a(alert, enrichment)
    return {
        "severity": score,
        "logs": log_event("scored_severity_a2a", score=score.model_dump()),
    }
    #score = severity_agent(state["alert"], state["enrichment"])
    #return {"severity": score, "logs": log_event("scored_severity", score=score.model_dump())}

def exploitability_node(state: SOCState) -> SOCState:
    alert = state["alert"]
    enrichment = state["enrichment"]
    score = call_exploitability_a2a(alert, enrichment)
    return {
        "exploitability": score,
        "logs": log_event("scored_exploitability_a2a", score=score.model_dump()),
    }
    #score = exploitability_agent(state["alert"], state["enrichment"])
    #return {"exploitability": score, "logs": log_event("scored_exploitability", score=score.model_dump())}

def playbooks_node(state: SOCState) -> SOCState:
    # idempotent; may be called multiple times as scores arrive
    required = ("validity", "severity", "exploitability")
    if not all(k in state and state[k] is not None for k in required):
        return {}

    # Load policy so playbook_agent can use rule hints / thresholds
    policy = load_policy()

    alert = state["alert"]
    v = state["validity"]
    s = state["severity"]
    e = state["exploitability"]

    # Pass policy into the agent (updated signature)
    pb = playbook_agent(alert, v, s, e, policy=policy)

    # Include some lightweight policy metadata in the audit log
    return {
        "playbooks": pb,
        "logs": log_event(
            "selected_playbooks",
            playbooks=pb.model_dump(),
            policy_version=policy.get("policy_version"),
            rules_count=len(policy.get("playbook_rules", [])),
        ),
    }

def decision_node(state: SOCState) -> SOCState:
    if not all(k in state for k in ("validity", "severity", "exploitability")):
        return {}
    dec = decision_agent(state["validity"], state["severity"], state["exploitability"], state.get("policy"))
    return {"decision": dec, "logs": log_event("decision_made", decision=dec.model_dump())}

def upload_xsoar_node(state: SOCState) -> SOCState:
    payload = {
        "alert": state["alert"].model_dump(),
        "scores": {
            "validity": state["validity"].model_dump(),
            "severity": state["severity"].model_dump(),
            "exploitability": state["exploitability"].model_dump(),
        },
        "playbooks": state.get("playbooks", {} if "playbooks" not in state else state["playbooks"].model_dump()),
    }
    res = xsoar.upload_incident(payload)
    return {"status": "Uploaded to XSOAR", "logs": log_event("xsoar_uploaded", api_response=res)}

def soc_triage_node(state: SOCState) -> SOCState:
    payload = {
        "alert": state["alert"].model_dump(),
        "note": "Low automation confidence; please triage.",
        "scores": {
            "validity": state.get("validity").model_dump() if "validity" in state else {},
            "severity": state.get("severity").model_dump() if "severity" in state else {},
            "exploitability": state.get("exploitability").model_dump() if "exploitability" in state else {},
        },
    }
    res = notify_soc(payload)
    return {"status": "Queued for human triage", "logs": log_event("triage_notified", response=res)}

def update_status_node(state: SOCState) -> SOCState:
    decision_path = state.get("decision").path if "decision" in state else None
    if decision_path == "UPLOAD_XSOAR":
        res = xsoar.update_status("INC-PLACEHOLDER", "Open")
        return {"status": "XSOAR Open", "logs": log_event("xsoar_status_updated", response=res)}
    return {"logs": log_event("status_noop", status=state.get("status", "unknown"))}

def route_after_decision(state: SOCState):
    return "upload_xsoar" if state["decision"].path == "UPLOAD_XSOAR" else "soc_triage"

# --------- Build Graph ---------

def build_graph(parallel: bool = True, checkpointer = None):
    g = StateGraph(SOCState)

    g.add_node("enrich", enrich_node)
    g.add_node("validity", validity_node)
    g.add_node("severity", severity_node)
    g.add_node("exploitability", exploitability_node)
    g.add_node("playbooks", playbooks_node)
    g.add_node("decision", decision_node)
    g.add_node("upload_xsoar", upload_xsoar_node)
    g.add_node("soc_triage", soc_triage_node)
    g.add_node("update_status", update_status_node)

    # Topology matches the slide
    g.add_edge(START, "enrich")

    if parallel:
        # Fork after enrich
        g.add_edge("enrich", "validity")
        g.add_edge("enrich", "severity")
        g.add_edge("enrich", "exploitability")
    else:
        g.add_edge("enrich", "validity")
        g.add_edge("validity", "severity")
        g.add_edge("severity", "exploitability")

    # Converge to playbooks/decision (idempotent nodes handle repeated triggers)
    g.add_edge("validity", "playbooks")
    g.add_edge("severity", "playbooks")
    g.add_edge("exploitability", "playbooks")
    g.add_edge("playbooks", "decision")

    # SOC Attention diamond (conditional)
    g.add_conditional_edges("decision", route_after_decision,
                            {"upload_xsoar": "upload_xsoar", "soc_triage": "soc_triage"})

    # Both paths converge to status update → END
    g.add_edge("upload_xsoar", "update_status")
    g.add_edge("soc_triage", "update_status")
    g.add_edge("update_status", END)

    return g.compile(checkpointer=checkpointer)



# --------- Programmatically generate DOT/Mermaid ---------

def describe_topology():
    return {
        "nodes": ["enrich","validity","severity","exploitability","playbooks","decision",
                  "upload_xsoar","soc_triage","update_status"],
        "edges": [
            ("enrich","validity"),
            ("validity","severity"),
            ("severity","exploitability"),
            ("exploitability","playbooks"),
            ("playbooks","decision"),
            ("decision","upload_xsoar"),
            ("decision","soc_triage"),
            ("upload_xsoar","update_status"),
            ("soc_triage","update_status")
        ]
    }
