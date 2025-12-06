# src/agents.py
from __future__ import annotations
from typing import Dict, List, Tuple
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI  # swap with your provider if needed
from domains import (
    Alert, ValidityScore, SeverityScore, ExploitabilityScore, PlaybookChoice, Decision
)
from config import load_policy

# Single model instance reused by all agents (swap provider or params)
def get_llm():
    return ChatOpenAI(model="gpt-4o-mini", temperature=0)  # deterministic scoring

# ---- Prompts: structured outputs ----

def validity_agent(alert: Alert, enrichment: Dict) -> ValidityScore:
    llm = get_llm().with_structured_output(ValidityScore)
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system",
             "You are the Validity agent in a SOC. Decide if the alert is real.\n"
             "Return a label (FP/FN/TP/TN), likelihood (0..1 for TP), and a short rationale."),
            ("human",
             "ALERT:\n{alert}\nENRICHMENT (internal & external):\n{enrichment}\n"
             "Rules of thumb:\n- Penalize alerts with poor evidence and conflicting signals.\n"
             "- Reward corroboration across multiple sensors.\n- Prefer TP vs TN when indicators map to active hosts.")
        ]
    )
    return llm.invoke(prompt.format(alert=alert.model_dump(), enrichment=enrichment))

def severity_agent(alert: Alert, enrichment: Dict) -> SeverityScore:
    llm = get_llm().with_structured_output(SeverityScore)
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system",
             "You are the Severity agent. Score organizational impact.\n"
             "Level 1=Low, 2=Moderate, 3=High. Include impact label and rationale."),
            ("human", "ALERT:\n{alert}\nENRICHMENT:\n{enrichment}")
        ]
    )
    return llm.invoke(prompt.format(alert=alert.model_dump(), enrichment=enrichment))

def exploitability_agent(alert: Alert, enrichment: Dict) -> ExploitabilityScore:
    llm = get_llm().with_structured_output(ExploitabilityScore)
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system",
             "You are the Exploitability agent. Estimate likelihood and level:\n"
             "Levels: Not Exploitable, Low, Medium, Critical."),
            ("human", "ALERT:\n{alert}\nENRICHMENT:\n{enrichment}")
        ]
    )
    return llm.invoke(prompt.format(alert=alert.model_dump(), enrichment=enrichment))

# ---------- Rule-aware Playbook Agent helpers ----------

def _infer_alert_meta(alert: Alert) -> Dict[str, str]:
    """
    Heuristic extraction of coarse metadata from title/description to match rules.
    This keeps code changes minimal while enabling config-only rule control.
    """
    text = f"{alert.title} {alert.description}".lower()
    product = "CrowdStrike" if ("crowdstrike" in text or "edr" in text) else ""
    if "brute" in text or "password spray" in text:
        alert_type = "Auth/BruteForce"
    elif "edr" in text or "endpoint" in text:
        alert_type = "EDR"
    else:
        alert_type = ""
    return {"product": product, "alert_type": alert_type}

def _rule_matches(meta: Dict[str, str],
                  validity: ValidityScore,
                  severity: SeverityScore,
                  exploitability: ExploitabilityScore,
                  rule: Dict) -> bool:
    """Deterministic evaluator for the small 'when' DSL in policy.playbook_rules."""
    if not rule.get("enabled", True):
        return False
    w = rule.get("when", {}) or {}

    # string exact matches
    if "product" in w and w["product"]:
        if meta.get("product") != w["product"]:
            return False
    if "alert_type" in w and w["alert_type"]:
        if meta.get("alert_type") != w["alert_type"]:
            return False

    # numeric thresholds
    if "severity_max_level" in w and severity.level > int(w["severity_max_level"]):
        return False
    if "validity_tp_min" in w and float(validity.likelihood) < float(w["validity_tp_min"]):
        return False
    if "validity_tp_max" in w and float(validity.likelihood) > float(w["validity_tp_max"]):
        return False

    # categorical exploitability
    if "exploitability_levels_in" in w:
        if str(exploitability.level) not in set(w["exploitability_levels_in"]):
            return False
    if "exploitability_levels_not_in" in w:
        if str(exploitability.level) in set(w["exploitability_levels_not_in"]):
            return False

    return True

def _select_matching_rules(policy: Dict, alert: Alert,
                           validity: ValidityScore,
                           severity: SeverityScore,
                           exploitability: ExploitabilityScore) -> List[Dict]:
    meta = _infer_alert_meta(alert)
    rules = policy.get("playbook_rules", [])
    matches = [r for r in rules if _rule_matches(meta, validity, severity, exploitability, r)]
    if not matches:
        return []
    # precedence: lower priority value first
    matches = sorted(matches, key=lambda r: int(r.get("priority", policy.get("default_rule_priority", 100))))
    if policy.get("collect_all_matches", False):
        return matches
    return [matches[0]]

def playbook_agent(alert: Alert, validity: ValidityScore,
                   severity: SeverityScore, exploitability: ExploitabilityScore,
                   policy: dict | None = None) -> PlaybookChoice:
    """
    Rule-aware playbook selection.
    - Deterministically pre-select candidate rules from policy.playbook_rules.
    - Provide candidates to the LLM as hints; LLM returns 1-4 concise playbook names.
    """
    cfg = policy or load_policy()
    matched = _select_matching_rules(cfg, alert, validity, severity, exploitability)
    # compact view for prompt: (rule_id, auto_action)
    matched_view: List[Tuple[str, str | None]] = [
        (m.get("id", ""), (m.get("do") or {}).get("auto_action")) for m in matched
    ]

    llm = get_llm().with_structured_output(PlaybookChoice)
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system",
             "Select SOC playbooks based on scores and (if present) the candidate rule hints. "
             "Return concise names (e.g., 'Block IP', 'Quarantine Host', 'Reset Credential', 'Forensics')."),
            ("human",
             "ALERT: {alert}\nVALIDITY: {validity}\nSEVERITY: {severity}\n"
             "EXPLOITABILITY: {exploit}\nCANDIDATE_RULES: {rule_hints}\n"
             "Pick 1-4 playbooks and justify. Prefer actions aligned with candidate rules when appropriate.")
        ]
    )
    return llm.invoke(
        prompt.format(
            alert=alert.model_dump(),
            validity=validity.model_dump(),
            severity=severity.model_dump(),
            exploit=exploitability.model_dump(),
            rule_hints=matched_view,
        )
    )

def decision_agent(validity: ValidityScore,
                   severity: SeverityScore,
                   exploitability: ExploitabilityScore,
                   policy: dict | None = None) -> Decision:
    """
    SOC Attention rule-of-thumb:
    - Escalate when validity.likelihood >= 0.6 and (severity.level >= 2 or exploitability.level in {Medium, Critical})
    - Otherwise route to human triage queue for confirmation.
    The LLM explains the rationale.
    """
    # quick deterministic gate, then LLM writes rationale & path for auditability
    cfg = policy or load_policy()
    thr = cfg.get("thresholds", {})
    v_min = float(thr.get("validity_tp_min", 0.6))
    s_min = int(thr.get("severity_min", 2))
    esc_levels = set(thr.get("exploit_levels_escalate", ["Medium", "Critical"]))

    soc_attention = bool(
        (validity.likelihood >= v_min)
        and (severity.level >= s_min or exploitability.level in esc_levels)
    )
    path = "UPLOAD_XSOAR" if soc_attention else "SOC_TRIAGE"

    llm = get_llm().with_structured_output(Decision)
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system",
             "You are the Orchestration agent. Given precomputed scores and policy thresholds, "
             "decide whether to upload to XSOAR or route to human triage."),
            ("human",
             "POLICY: {policy}\nVALIDITY: {v}\nSEVERITY: {s}\nEXPLOITABILITY: {e}\n"
             "Preliminary decision: {soc_attention}\nChosen path: {path}\n"
             "Explain briefly.")
        ]
    )
    return llm.invoke(
        prompt.format(
            policy=cfg, v=validity.model_dump(), s=severity.model_dump(),
            e=exploitability.model_dump(), soc_attention=soc_attention, path=path
        )
    )
