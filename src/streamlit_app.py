"""
Testing results:

1. Native streaming (parallel) - No Force HITL - Run - everything works as expected

2. Native streaming (parallel) - No Force HITL - Replay Last - everything works as expected

3. Native streaming (parallel) - Force HITL - Run - everything works as expected

4. Native streaming (parallel) - Force HITL - Replay Last - everything works as expected

5. Sequential stepper - No Force HITL - Run - everything works as expected

6. Sequential stepper - No Force HITL - Replay Last - everything works as expected

7. Sequential stepper - Force HITL - Run - everything works as expected 

8. Sequential stepper - Force HITL - Replay Last - everything works as expected 
"""


from __future__ import annotations
import json, time, io
from datetime import datetime
from typing import Dict, List
import shutil

from dotenv import load_dotenv
load_dotenv()

import warnings
warnings.filterwarnings("ignore")

import streamlit as st
from graphviz import Digraph

from domains import Alert, Indicator
from config import load_policy
from graph import (
    build_graph,
    enrich_node,
    validity_node,
    severity_node,
    exploitability_node,
    playbooks_node,
    decision_node,
    upload_xsoar_node,
    soc_triage_node,
    update_status_node,
)

import re
from datetime import datetime
from typing import Any
from domains import ActionLog


st.set_page_config(page_title="AI SOC – A2A LangGraph Flow", page_icon="🛰️", layout="wide")

# ---------- Helpers ----------

# ---------- Per-mode isolation helpers (DROP-IN) ----------

import os
import uuid
import shutil as _shutil

# Use distinct keys for native vs stepper so histories never mix
MODE_NATIVE = "native"
MODE_STEPPER = "stepper"

def _mode_from_run_mode(run_mode: str) -> str:
    """Map the UI radio label to internal mode keys."""
    return MODE_NATIVE if run_mode.strip().lower().startswith("native") else MODE_STEPPER

def _mode_prefix(mode: str) -> str:
    """Prefix used for st.session_state keys."""
    return "_native" if mode == MODE_NATIVE else "_stepper"

def _set_last_state(mode: str, *, thread_id: str | None, final_state: dict | None, decision_path: str | None):
    """Write last-run info for THIS mode only."""
    pref = _mode_prefix(mode)
    if thread_id is not None:
        st.session_state[f"{pref}_last_thread_id"] = thread_id
    if final_state is not None:
        st.session_state[f"{pref}_last_final_state"] = final_state
    if decision_path is not None:
        st.session_state[f"{pref}_last_decision_path"] = decision_path

def _get_last_state(mode: str):
    """Read last-run info for THIS mode only."""
    pref = _mode_prefix(mode)
    return (
        st.session_state.get(f"{pref}_last_thread_id"),
        st.session_state.get(f"{pref}_last_final_state"),
        st.session_state.get(f"{pref}_last_decision_path"),
    )

def _clear_last_state_all_modes():
    """Clear any remembered last states for BOTH modes."""
    for pref in ("_native", "_stepper"):
        for suffix in ("_last_thread_id", "_last_final_state", "_last_decision_path"):
            st.session_state.pop(f"{pref}{suffix}", None)

def _fresh_thread_id(prefix: str = "thr") -> str:
    """Always start fresh on Run so we don't reuse old checkpoints."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"



# ---------- Checkpoint management (DROP-IN) ----------

# Use distinct DB files per mode; this prevents accidental cross-mode replay bleed-through.
SQLITE_DB_NATIVE = "a2a_checkpoints_native.sqlite"
# Stepper is deterministic UI; do not persist checkpoints for it. We'll keep a stub path for symmetry.
SQLITE_DB_STEPPER = "a2a_checkpoints_stepper.sqlite"

def _build_checkpointer_for_mode(mode: str, *, ephemeral_for_run: bool = False):
    """
    Returns a LangGraph checkpointer appropriate for the mode.
    - Native streaming: SQLite saver for replay; during RUN we still want a clean thread, so fresh thread_id suffices.
      If you set ephemeral_for_run=True, we fallback to MemorySaver to ensure a totally fresh in-memory run
      (replay then depends on SQLite not being used in that run).
    - Stepper: no need for a checkpointer; return None.
    """
    if mode == MODE_STEPPER:
        return None, "none"

    try:
        from langgraph.checkpoint.sqlite import SqliteSaver  # type: ignore
        if ephemeral_for_run:
            # For a true "ignore memory/checkpoints", use MemorySaver in RUN (keeps replay isolated to that app lifetime)
            try:
                from langgraph.checkpoint.memory import MemorySaver  # type: ignore
                return MemorySaver(), "memory"
            except Exception:
                # If MemorySaver unavailable, fall back to a one-off sqlite file per run caller
                return SqliteSaver.from_conn_string(SQLITE_DB_NATIVE), "sqlite"
        return SqliteSaver.from_conn_string(SQLITE_DB_NATIVE), "sqlite"
    except Exception:
        try:
            from langgraph.checkpoint.memory import MemorySaver  # type: ignore
            return MemorySaver(), "memory"
        except Exception:
            return None, "none"

def _delete_sqlite_if_exists(path: str):
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

def clear_all_checkpoints_and_memory():
    """
    Hard-wipe ALL remembered app state & checkpoint storage.
    - Deletes per-mode sqlite DBs (if present)
    - Clears per-mode last-state session keys
    """
    _clear_last_state_all_modes()
    _delete_sqlite_if_exists(SQLITE_DB_NATIVE)
    _delete_sqlite_if_exists(SQLITE_DB_STEPPER)

    # Clear any cached checkpointers
    for key in ("_checkpointer_native", "_checkpoint_backend_native",
                "_checkpointer_stepper", "_checkpoint_backend_stepper"):
        st.session_state.pop(key, None)



def ensure_graphviz_or_warn() -> bool:
    has_dot = shutil.which("dot") is not None
    if not has_dot:
        st.error(
            "Graphviz 'dot' executable not found. Install Graphviz and ensure 'dot' is on PATH.\n"
            "- Ubuntu/WSL: `sudo apt-get install -y graphviz`\n"
            "- macOS: `brew install graphviz`\n"
            "- Windows: `winget install Graphviz.Graphviz` or `choco install graphviz`\n\n"
            "After installing, restart this app."
        )
    return has_dot

# early exit if not available
if not ensure_graphviz_or_warn():
    st.stop()

def get_checkpointer():
    """
    Try persistent SQLite saver; if unavailable, fall back to in-memory saver.
    Returns (saver_or_none, backend_str).
    """
    try:
        # Newer LangGraph
        from langgraph.checkpoint.sqlite import SqliteSaver  # type: ignore
        return SqliteSaver.from_conn_string("a2a_checkpoints.sqlite"), "sqlite"
    except Exception:
        try:
            # Works on older versions
            from langgraph.checkpoint.memory import MemorySaver  # type: ignore
            return MemorySaver(), "memory"
        except Exception:
            return None, "none"

# -------- tolerant serialization helpers --------
STATE_KEYS = {"enrichment","validity","severity","exploitability","playbooks","decision","status","logs"}

def as_dict(obj: Any) -> Any:
    """Best-effort turn Pydantic/TypedDict/repr-string into a dict."""
    if obj is None:
        return None
    if hasattr(obj, "model_dump"):            # pydantic v2
        return obj.model_dump()
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, str) and "(" in obj and ")" in obj:
        m = re.match(r"^[A-Za-z_]\w*\((.*)\)$", obj.strip(), flags=re.S)
        if m:
            body = m.group(1)
            pairs = re.findall(r"(\w+)\s*=\s*(\"[^\"]*\"|'[^']*'|[0-9.]+|True|False|None)", body)
            out = {}
            for k, v in pairs:
                v = v.strip()
                if v in ("True","False"):
                    out[k] = (v == "True")
                elif v == "None":
                    out[k] = None
                elif (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
                    out[k] = v[1:-1]
                else:
                    try:
                        out[k] = float(v) if "." in v else int(v)
                    except Exception:
                        out[k] = v
            return out
    return obj

def get_field(obj: Any, key: str, default=None):
    """Read attribute/field from BaseModel, dict, or repr-string."""
    if hasattr(obj, key):
        try: return getattr(obj, key)
        except Exception: pass
    if isinstance(obj, dict) and key in obj:
        return obj[key]
    if isinstance(obj, str):
        m = re.search(rf"{re.escape(key)}\s*=\s*(\"[^\"]*\"|'[^']*'|[0-9.]+|True|False|None)", obj)
        if m:
            raw = m.group(1)
            if raw in ("True","False"): return raw == "True"
            if raw == "None": return None
            if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
                return raw[1:-1]
            try: return float(raw) if "." in raw else int(raw)
            except Exception: return raw
    return default

def _coerce_logs(items):
    """Turn list of dicts or repr-strings into ActionLog instances."""
    out = []
    for it in (items or []):
        if isinstance(it, ActionLog):
            out.append(it); continue
        if isinstance(it, dict):
            at = it.get("at")
            if isinstance(at, str):
                try: it["at"] = datetime.fromisoformat(at.replace("Z","+00:00"))
                except Exception: it.pop("at", None)
            try:
                out.append(ActionLog(**it)); continue
            except Exception:
                pass
        if isinstance(it, str):
            ev = get_field(it, "event", "log")
            at = get_field(it, "at", None)
            if isinstance(at, str):
                try: at = datetime.fromisoformat(at.replace("Z","+00:00"))
                except Exception: at = None
            dm = re.search(r"details\s*=\s*(\{.*\})\)?\s*$", it, flags=re.S)
            details = {}
            if dm:
                blob = dm.group(1)
                try:
                    import json
                    details = json.loads(re.sub(r"'", '"', blob))
                except Exception:
                    details = {"raw": blob}
            out.append(ActionLog(event=str(ev), details=details)); continue
        out.append(ActionLog(event="log", details={"raw": str(it)}))
    return out

def apply_delta(state: dict, delta: dict) -> dict:
    """Merge snapshot delta into local state (and append logs)."""
    for k, v in (delta or {}).items():
        if k == "logs":
            state["logs"] = state.get("logs", []) + _coerce_logs(v)
        else:
            state[k] = v
    return state

def _append_hitl_log(state: dict, event: str, extra: dict | None = None):
    """Record HITL events in the same log stream used by nodes."""
    try:
        state.setdefault("logs", [])
        details = dict(extra or {})
        state["logs"].append(ActionLog(
            event=event,
            at=datetime.utcnow(),
            details=details
        ))
    except Exception:
        # best-effort fallback
        state.setdefault("logs", [])
        state["logs"].append(ActionLog(event=event, details=extra or {}))


# map state keys to diagram node names so we can mark them "done"
STATE_TO_NODE = {
    "enrichment": "enrich",
    "validity": "validity",
    "severity": "severity",
    "exploitability": "exploitability",
    "playbooks": "playbooks",
    "decision": "decision",
    "status": "update_status",
}


def default_alert() -> Alert:
    return Alert(
        id="ALRT-1001",
        title="Outbound connection to known brute-force IP",
        description="FW logs show repeated egress to suspicious IP by host srv-42.",
        indicators=[
            Indicator(type="ip", value="203.0.113.55"),
            Indicator(type="host", value="srv-42"),
            Indicator(type="user", value="svc-backup"),
        ],
    )

NODES = [
    "enrich", "validity", "severity", "exploitability",
    "playbooks", "decision", "upload_xsoar", "soc_triage", "update_status"
]
NODE_FUNCS = {
    "enrich": enrich_node,
    "validity": validity_node,
    "severity": severity_node,
    "exploitability": exploitability_node,
    "playbooks": playbooks_node,
    "decision": decision_node,
    "upload_xsoar": upload_xsoar_node,
    "soc_triage": soc_triage_node,
    "update_status": update_status_node,
}

def _palette():
    return {
        "pending": dict(fillcolor="#F5F5F5", color="#606060", style="rounded,filled"),
        "running": dict(fillcolor="#FFF2CC", color="#B8860B", style="rounded,filled,bold"),
        "done":    dict(fillcolor="#C6EFCE", color="#2E7D32", style="rounded,filled,bold"),
        "skipped": dict(fillcolor="#E0E0E0", color="#9E9E9E", style="rounded,filled,dashed"),
    }

def build_gv(status_by_node: Dict[str, str], decision_path: str | None) -> Digraph:
    dot = Digraph(comment="AI SOC Flow", engine="dot")
    dot.attr(rankdir="LR", labelloc="t", pad="0.2", ranksep="1", nodesep="0.6")
    dot.attr(
        "node",
        shape="box",
        style="rounded,filled",
        color="black",
        fontcolor="black",
        penwidth="1",
        fontsize="10",
        fillcolor="#F5F5F5",
        margin="0.08",
    )
    dot.attr("edge", color="black", arrowsize="0.7", fontsize="9", fontcolor="black")

    labels = {
        "enrich": "Enrich\n(Internal + External)",
        "validity": "Validity",
        "severity": "Severity",
        "exploitability": "Exploitability",
        "playbooks": "Playbooks",
        "decision": "SOC Attention?",
        "upload_xsoar": "Upload to XSOAR",
        "soc_triage": "SOC Triage\n(Human)",
        "update_status": "Update Incident Status",
    }

    pal = _palette()

    # draw nodes (status determines color)
    for k, lab in labels.items():
        style = pal.get(status_by_node.get(k, "pending"))
        shape = "diamond" if k == "decision" else "box"
        dot.node(k, lab, shape=shape, **style)

    # edges
    dot.edge("enrich", "validity")
    dot.edge("enrich", "severity")
    dot.edge("enrich", "exploitability")
    dot.edge("validity", "playbooks")
    dot.edge("severity", "playbooks")
    dot.edge("exploitability", "playbooks")
    dot.edge("playbooks", "decision")

    # Branch edges — new semantics:
    #   Yes  -> SOC_TRIAGE
    #   No   -> UPDATE_STATUS (automation, no upload)
    yes_green = "#2E7D32"
    gray = "#9E9E9E"

    # decision -> SOC_TRIAGE (Yes)  [solid; highlight when SOC_TRIAGE]
    dot.edge(
        "decision", "soc_triage", label="Yes",
        color=(yes_green if decision_path == "SOC_TRIAGE" else gray),
        fontcolor=(yes_green if decision_path == "SOC_TRIAGE" else gray),
        penwidth=("2" if decision_path == "SOC_TRIAGE" else "1"),
    )

    # decision -> UPLOAD_XSOAR (No) [solid; highlight when UPLOAD_XSOAR]
    dot.edge(
        "decision", "upload_xsoar", label="No",
        color=(yes_green if decision_path == "UPLOAD_XSOAR" else gray),
        fontcolor=(yes_green if decision_path == "UPLOAD_XSOAR" else gray),
        penwidth=("2" if decision_path == "UPLOAD_XSOAR" else "1"),
    )

    # post-branch flows
    # automated continuation (solid)
    dot.edge("upload_xsoar", "update_status")

    # human outcomes from SOC Triage (dashed)
    dot.edge("soc_triage", "upload_xsoar", label="Approved",  style="dashed")
    dot.edge("soc_triage", "update_status", label="Dismissed", style="dashed")

    return dot


def to_json(obj):
    try:
        return json.dumps(obj.model_dump(), indent=2, default=str)
    except Exception:
        return json.dumps(obj, indent=2, default=str)

def render_diagram(ph, status_by_node, decision_path: str | None):
    # Do not mutate statuses here; just render and highlight the chosen path.
    from copy import deepcopy
    import re

    ph.empty()
    nonce = st.session_state.get("_diagram_nonce", 0)

    # ensure we don’t carry in-place mutations across runs
    status_by_node = deepcopy(status_by_node)

    dot = build_gv(status_by_node, decision_path)

    # Make the *graph identity* unique per render. This defeats any reuse of the previous SVG/layout.
    if hasattr(dot, "name"):           # graphviz.Digraph path
        dot.name = f"G_{nonce}"
        try:
            dot.graph_attr["_nonce"] = str(nonce)  # harmless attribute
        except Exception:
            pass
        ph.graphviz_chart(dot, width='stretch')
    else:                               # DOT string path
        # rename: "digraph G { ... }" -> "digraph G_<nonce> { ... }"
        dot = re.sub(r'^(digraph|graph)\s+\w+', lambda m: f"{m.group(1)} G_{nonce}", str(dot), count=1, flags=re.IGNORECASE)
        # (keep your comment too; it’s harmless)
        dot = f"{dot}\n// nonce:{nonce}\n"
        ph.graphviz_chart(dot, width='stretch')


def _bust_diagram_cache():
    try:
        # Clear Streamlit’s data/resource caches ONLY for diagram builders
        from streamlit.runtime.caching import cache_data as _cd
        from streamlit.runtime.caching import cache_resource as _cr
        _cd.clear()
        _cr.clear()
    except Exception:
        # Older Streamlit: best-effort
        pass



def _ensure_timeline_blocks():
    """
    Create one placeholder per step inside the Execution Timeline so each
    step renders once and can be refreshed without duplication.
    """
    if "_timeline_blocks" in st.session_state:
        return st.session_state["_timeline_blocks"]

    blocks = {}
    with timeline_ph:
        blocks["validity"]       = st.empty()
        blocks["severity"]       = st.empty()
        blocks["exploitability"] = st.empty()
        blocks["playbooks"]      = st.empty()
        blocks["decision"]       = st.empty()
    st.session_state["_timeline_blocks"] = blocks
    return blocks


def _render_timeline_section(ph, title: str, content: dict | str | None = None):
    """Refresh a single step section with a heading and compact body."""
    try:
        ph.empty()
    except Exception:
        pass
    with ph.container():
        st.markdown(f"### {title}")
        if isinstance(content, dict):
            st.json(content)
        elif content:
            st.write(content)
        else:
            st.caption("—")


def reset_layout(initial_status=None, decision_path=None):
    """Hard reset all UI areas so subsequent runs/replays render into live containers."""
    if initial_status is None:
        initial_status = {k: "pending" for k in NODES}

    # Clear all major regions
    try: diagram_ph.empty()
    except: pass
    try: metrics_ph.empty()
    except: pass
    try: enrich_ph1.empty()
    except: pass
    try: enrich_ph2.empty()
    except: pass
    try: timeline_ph.empty()
    except: pass
    try: eventlog_ph.empty()
    except: pass
    try: final_state_ph.empty()
    except: pass

    # Force timeline blocks to be recreated next time
    if "_timeline_blocks" in st.session_state:
        del st.session_state["_timeline_blocks"]

    # Recreate headers/containers
    render_diagram(diagram_ph, initial_status, decision_path)


# Keys that must exist before upload/update
REQUIRED_FOR_UPLOAD = (
    "enrichment", "validity", "severity", "exploitability", "playbooks", "decision"
)

def ensure_upload_ready(state: dict, avoid_logs: bool = True) -> dict:
    """
    Idempotently ensure the state has all fields needed by upload_xsoar/update_status.
    - Uses *presence* checks ("key not in s") so existing falsy values don't retrigger nodes.
    - Optionally drops 'logs' produced by hydration nodes to avoid duplicates.
    """
    s = dict(state or {})

    def merge_without_logs(delta: dict):
        if not isinstance(delta, dict):
            return
        d = {k: v for k, v in delta.items() if not (avoid_logs and k == "logs")}
        # Use the same merge semantics as your stepper, but without logs
        for k, v in d.items():
            if k == "logs":
                continue
            s[k] = v

    try:
        # Enrichment first
        if "enrichment" not in s:
            merge_without_logs(enrich_node(s))

        # Scorers
        if "validity" not in s:
            merge_without_logs(validity_node(s))
        if "severity" not in s:
            merge_without_logs(severity_node(s))
        if "exploitability" not in s:
            merge_without_logs(exploitability_node(s))

        # Playbooks then decision
        if "playbooks" not in s:
            merge_without_logs(playbooks_node(s))
        if "decision" not in s:
            merge_without_logs(decision_node(s))

    except Exception as e:
        st.warning(f"State hydration warning: {e}")

    return s


def _dedupe_logs(items):
    """Return ActionLog[] with stable de-dup by (at,event,details)."""
    logs = _coerce_logs(items)
    seen, out = set(), []
    for l in logs or []:
        at = getattr(l, "at", None)
        ev = getattr(l, "event", None)
        det = json.dumps(getattr(l, "details", {}), sort_keys=True, default=str)
        key = (str(at), ev, det)
        if key in seen:
            continue
        seen.add(key)
        out.append(l)
    return out

def render_event_log_full(items):
    """Render full Event Log list (no header). Accepts dicts or ActionLog."""
    logs = _dedupe_logs(items)
    with eventlog_ph:
        for log in logs:
            at = getattr(log, "at", None)
            ev = getattr(log, "event", "log")
            details = getattr(log, "details", {})
            with st.expander(f"{at} — {ev}", expanded=False):
                st.json(details, expanded=False)


def latest_hitl_outcome(fs: dict) -> str:
    """
    Decide the most recent HITL outcome:
      'approved' | 'dismissed' | 'pending'

    Behavior:
    - If Replay is explicitly unlocking HITL (sandbox), force 'pending'
      so buttons are enabled and the graph pauses at triage.
    - Otherwise, derive strictly from logs (no session flags), choosing the
      newest by (has_time, timestamp, rightmost_index). Robust to dict/model/str logs
      and missing/ill-formed timestamps.
    """
    from datetime import datetime, timezone
    import re, json

    fs = fs or {}
    logs = fs.get("logs") or []

    # 0) Replay sandbox: always allow action (do not auto-finish)
    try:
        import streamlit as st  # safe when running in Streamlit; ignored in tests
        if st.session_state.get("_replay_unlock_hitl"):
            return "pending"
    except Exception:
        pass

    # Tolerant getters
    def _get(obj, key, default=None):
        if hasattr(obj, key):
            try: return getattr(obj, key)
            except Exception: pass
        if isinstance(obj, dict) and key in obj:
            return obj[key]
        if isinstance(obj, str):
            m = re.search(
                rf"{re.escape(key)}\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s,)\]]+)",
                obj
            )
            if m:
                val = m.group(1).strip()
                if val[:1] in "'\"" and val[-1:] in "'\"":
                    return val[1:-1]
                return val
        return default

    def _parse_dt(v):
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, str) and v:
            # ISO first
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
            except Exception:
                pass
            # loose fallbacks
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
                except Exception:
                    continue
        return None

    # 1) Compute the newest human decision from logs only
    best_key = None  # (has_time:int, timestamp:datetime, rightmost_index:int)
    best_out = "pending"

    for idx, log in enumerate(logs):
        ev = _get(log, "event", None)
        if ev not in ("human_approved", "human_dismissed"):
            continue

        # Try 'at' from the log or inside 'details'
        raw_at = _get(log, "at", None)
        if raw_at is None:
            details = _get(log, "details", {}) or {}
            if isinstance(details, str):
                try: details = json.loads(details)
                except Exception: details = {}
            if isinstance(details, dict):
                raw_at = details.get("at")

        dt = _parse_dt(raw_at)
        has_time = 1 if dt is not None else 0
        key = (has_time, dt or datetime.min.replace(tzinfo=timezone.utc), idx
        )  # rightmost wins on tie/missing time
        out = "approved" if ev == "human_approved" else "dismissed"

        if (best_key is None) or (key > best_key):
            best_key = key
            best_out = out

    return best_out


def _bump_diagram_nonce():
    st.session_state["_diagram_nonce"] = st.session_state.get("_diagram_nonce", 0) + 1


def _resolve_thread_id(final_state: dict | None = None) -> str:
    # Prefer recent session thread ids first
    tid = (
        st.session_state.get("fresh_tid")
        or st.session_state.get("thread_id")
        or st.session_state.get("_last_thread_id")
    )

    if not tid:
        # Safely pull alert.id from dicts or objects
        alert_obj = None
        if isinstance(final_state, dict):
            alert_obj = final_state.get("alert")
        elif final_state is not None:
            alert_obj = getattr(final_state, "alert", None)

        if isinstance(alert_obj, dict):
            tid = alert_obj.get("id")
        elif alert_obj is not None:
            tid = getattr(alert_obj, "id", None)

    tid = tid or "default"
    st.session_state["_last_thread_id"] = tid
    return tid


from dataclasses import is_dataclass, asdict as _asdict
from collections.abc import Mapping

def _is_mapping(x) -> bool:
    return isinstance(x, Mapping)

def _to_dict(obj) -> dict:
    """Best-effort: dict → dict; dataclass → asdict; pydantic → dict()/model_dump(); generic object → attr dict."""
    if obj is None:
        return {}
    if _is_mapping(obj):
        return dict(obj)
    if is_dataclass(obj):
        try:
            return _asdict(obj)
        except Exception:
            pass
    # pydantic v1 / v2
    for meth in ("model_dump", "dict"):
        if hasattr(obj, meth):
            try:
                return getattr(obj, meth)()
            except Exception:
                pass
    # generic attribute bag
    out = {}
    for k in dir(obj):
        if k.startswith("_"):
            continue
        try:
            v = getattr(obj, k)
            if callable(v):
                continue
            out[k] = v
        except Exception:
            pass
    return out

def _gx(obj, path, default=None):
    """dict-or-object safe nested getter; path is list/tuple of keys/attrs."""
    cur = obj
    for key in path:
        if cur is None:
            return default
        if _is_mapping(cur):
            cur = cur[key] if key in cur else default
        else:
            cur = getattr(cur, key, default)
    return cur

def _as_list(x):
    if x is None:
        return []
    if isinstance(x, (list, tuple)):
        return list(x)
    return [x]



import requests

GREEN_VALUES = {"done", "green", "success", "completed", "ok", "true", "1"}

def _post_to_slack(text: str, blocks: list | None = None):
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if webhook:
        r = requests.post(webhook, json={"text": text, "blocks": blocks} if blocks else {"text": text}, timeout=5)
        r.raise_for_status()
        return
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("SLACK_CHANNEL")
    if token and channel:
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json; charset=utf-8"}
        payload = {"channel": channel, "text": text}
        if blocks:
            payload["blocks"] = blocks
        r = requests.post("https://slack.com/api/chat.postMessage", headers=headers, json=payload, timeout=5)
        # Slack Web API returns 200 with {"ok":false,...} on failure, so check json too:
        r.raise_for_status()
        if not (r.json().get("ok", False)):
            raise RuntimeError(f"Slack API error: {r.text}")

def _find_xsoar_node_key(status: dict) -> str | None:
    """Return the key in `status` that represents the XSOAR upload node."""
    if not status:
        return None
    candidates = ("upload_xsoar", "xsoar_upload", "upload_to_xsoar", "xsoar")
    for k in candidates:
        if k in status:
            return k
    # fallback: best-effort heuristic
    for k in status.keys():
        if "xsoar" in k.lower() and ("upload" in k.lower() or "sync" in k.lower()):
            return k
    return None

def _is_green(v) -> bool:
    if v is True:
        return True
    if v is False or v is None:
        return False
    s = str(v).strip().lower()
    return s in GREEN_VALUES

def _maybe_notify_xsoar_green(final_state, status: dict, decision_path: str | None, thread_id: str | None):
    """
    Fire exactly once per thread when the XSOAR node transitions to green.
    Also writes a tiny debug dict in session_state for visibility.
    """
    node_key = _find_xsoar_node_key(status or {})
    curr_val = (status or {}).get(node_key) if node_key else None
    curr_green = _is_green(curr_val)

    ss_key = f"_xsoar_green_state:{thread_id or 'default'}"
    prev_green = bool(st.session_state.get(ss_key, False))
    st.session_state[ss_key] = curr_green  # store for next render

    # debug breadcrumbs (visible via st.caption in caller)
    st.session_state["_xsoar_notify_debug"] = {
        "node_key": node_key,
        "curr_val": curr_val,
        "curr_green": curr_green,
        "prev_green": prev_green,
        "thread_id": thread_id,
        "decision_path": decision_path,
        "types": {
            "final_state": type(final_state).__name__,
            "status": type(status).__name__,
            "alert": type(_gx(final_state, ["alert"])).__name__,
        },
    }

    if not prev_green and curr_green:
        fs = final_state  # may be dict or object

        # Pull fields safely (never .get on non-dict)
        alert_obj = _gx(fs, ["alert"])
        sev  = _gx(fs, ["severity", "level"]) or _gx(fs, ["severity", "impact"], "—")
        exp  = _gx(fs, ["exploitability", "level"], "—")
        val  = _gx(fs, ["validity", "level"]) or _gx(fs, ["validity", "likelihood"], "—")

        pbooks_obj = _gx(fs, ["playbooks"], {})
        pbooks = _to_dict(pbooks_obj)
        pb_names = _as_list(_gx(pbooks, ["names"], []))
        pb_rat   = _gx(pbooks, ["rationale"], "") or ""

        decision_obj = _gx(fs, ["decision"], {})
        decided  = _gx(decision_obj, ["path"], decision_path) or "—"
        # --- pretty decision label ---
        pretty_decision = {"UPLOAD_XSOAR":"Upload to XSOAR", "SOC_TRIAGE":"SOC Triage"}.get(str(decided).upper(), str(decided))

        alert = _to_dict(alert_obj)
        a_id    = _gx(alert, ["id"], "—")
        a_title = _gx(alert, ["title"], "—")
        a_desc  = _gx(alert, ["description"], "")

        # indicators: accept list of dicts or list of objects
        # --- indicators capping (optional) ---
        inds_raw = _as_list(_gx(alert_obj if alert_obj is not None else alert, ["indicators"], []))
        inds = [_to_dict(it) for it in inds_raw]
        ind_lines = []
        for it in inds:
            t = _gx(it, ["type"], "")
            v = _gx(it, ["value"], "")
            if t and v:
                ind_lines.append(f"• {t}: `{v}`")
        MAX_IOCS = 10
        if len(ind_lines) > MAX_IOCS:
            ind_text = "\n".join(ind_lines[:MAX_IOCS] + [f"… and *{len(ind_lines) - MAX_IOCS}* more"])
        else:
            ind_text = "\n".join(ind_lines) if ind_lines else "—"

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "✅ Uploaded to XSOAR", "emoji": True}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Thread ID:*\n`{thread_id or '—'}`"},
                {"type": "mrkdwn", "text": f"*Decision:*\n`{pretty_decision}`"},
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Severity:*\n{sev}"},
                {"type": "mrkdwn", "text": f"*Exploitability:*\n{exp}"},
                {"type": "mrkdwn", "text": f"*Validity:*\n{val}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Alert:* `{a_id}` – *{a_title}*\n{a_desc or ''}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Indicators:*\n{ind_text}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Playbooks Applied:*\n{', '.join(map(str, pb_names)) if pb_names else '—'}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Rule Rationale:*\n{pb_rat or '—'}"}},
        ]

        _post_to_slack(f"XSOAR updated to GREEN for `{a_id}` – {a_title}", blocks)






# ---------- HITL enforcement & validation (DROP-IN) ----------

def _enforce_force_hitl_on_decision(state: dict) -> dict:
    """
    If forced HITL is enabled (policy.force_hitl or sidebar toggle), force decision.path='SOC_TRIAGE'.
    IMPORTANT: Only enforce AFTER a decision object exists, to avoid pre-decision graph highlight.
    """
    try:
        pol = state.get("policy") or {}
        force = False
        if isinstance(pol, dict):
            force = bool(pol.get("force_hitl", False))
        if st.session_state.get("force_hitl"):
            force = True

        # Do NOT create a decision early; only enforce if decision already exists
        if not force or ("decision" not in state) or (state.get("decision") is None):
            return state

        d = as_dict(state.get("decision")) or {}
        if d.get("path") != "SOC_TRIAGE":
            rat = get_field(d, "rationale", "") or ""
            d["path"] = "SOC_TRIAGE"
            d["rationale"] = f"{rat} [forced HITL]".strip()
            state["decision"] = d
        return state
    except Exception:
        return state



def _validate_decision_path(decision_path: str | None):
    """
    Soft guard: warn if decision path is unexpected.
    Does not mutate behavior; just surfaces a warning to help debugging.
    """
    allowed = {None, "UPLOAD_XSOAR", "SOC_TRIAGE"}
    if decision_path not in allowed:
        st.warning(f"Unexpected decision path '{decision_path}'. Expected one of {sorted(allowed - {None})}.")



# ---------- Sidebar ----------
st.sidebar.title("Alert Input")
mode = st.sidebar.radio("Input mode", ["Form", "JSON"], horizontal=True)
thread_id = st.sidebar.text_input("Thread ID (for checkpointing)", value="demo-thread")
run_mode = st.sidebar.radio("Run mode", ["Native streaming (parallel)", "Sequential stepper"], horizontal=False)
delay = st.sidebar.slider("Step delay (sequential mode)", 0.1, 1.5, 0.6, 0.1)
policy = load_policy()

# show policy summary + edit affordance
with st.sidebar.expander("Policy (from config.yaml)", expanded=False):
    st.json(policy)

if "alert_json_text" not in st.session_state:
    st.session_state.alert_json_text = json.dumps(default_alert().model_dump(), indent=2, default=str)

if mode == "Form":
    st.sidebar.subheader("Quick form")
    a_id = st.sidebar.text_input("Alert ID", value="ALRT-1001")
    a_title = st.sidebar.text_input("Title", value="Outbound connection to known brute-force IP")
    a_desc = st.sidebar.text_area("Description", value="FW logs show repeated egress to suspicious IP by host srv-42.", height=80)
    ip = st.sidebar.text_input("IOC: ip", value="203.0.113.55")
    host = st.sidebar.text_input("IOC: host", value="srv-42")
    user = st.sidebar.text_input("IOC: user", value="svc-backup")
    alert = Alert(id=a_id, title=a_title, description=a_desc,
                  indicators=[Indicator(type="ip", value=ip),
                              Indicator(type="host", value=host),
                              Indicator(type="user", value=user)])
else:
    st.sidebar.subheader("Paste Alert JSON")
    txt = st.sidebar.text_area("Alert JSON", value=st.session_state.alert_json_text, height=300)
    try:
        payload = json.loads(txt)
        alert = Alert(**payload)
        st.session_state.alert_json_text = txt
        st.sidebar.success("Valid")
    except Exception as e:
        st.sidebar.error(f"Invalid JSON: {e}")
        st.stop()

# HITL
with st.sidebar.expander("Dev / Test", expanded=False):
    force_hitl = st.checkbox("Force HITL (show SOC_TRIAGE controls)")
st.session_state["force_hitl"] = force_hitl

col_run1, col_run2, col_run3 = st.sidebar.columns(3)
run_btn = col_run1.button("Run ▶️", type="primary")
replay_btn = col_run2.button("Replay last")
clear_btn = col_run3.button("Clear logs")

# ---------- Main ----------
st.title("AI SOC – Multi-Agent (A2A LangGraph) Orchestration")
st.caption("Parallel scoring → Playbooks → Decision → XSOAR / Human → Status")

info_l, info_r = st.columns([2, 1])
with info_l:
    st.subheader("Alert")
    st.json(alert.model_dump(mode="json"))
with info_r:
    st.subheader("How it works")
    st.write("- **Native streaming** mode uses LangGraph events.")
    st.write("- **Sequential** mode uses a stepper for deterministic UI.")

diagram_ph = st.empty()
metrics_ph = st.empty()
progress_ph = st.empty()
eta_ph = st.empty()
playbook_ph = st.empty()
enrich_col1, enrich_col2 = st.columns(2)
enrich_ph1 = enrich_col1.empty()
enrich_ph2 = enrich_col2.empty()
timeline_ph = st.container()
final_state_ph = st.empty()
download_ph = st.empty()
human_actions_ph = st.empty()
eventlog_ph = st.container()  # ← NEW: dedicated area for the raw events list


def render_metrics(state: dict):
    """
    Render Validity / Severity / Exploitability / Playbooks / Decision
    in a horizontal (3-column) layout inside metrics_ph.
    """
    import streamlit as st

    # Use the dedicated placeholder so updates replace in-place
    ph = globals().get("metrics_ph", None)
    if ph is not None:
        try:
            ph.empty()
            container = ph.container()
        except Exception:
            container = st.container()
    else:
        container = st.container()

    def fmt_num(x):
        if x is None:
            return "—"
        try:
            return f"{float(x):.2f}"
        except Exception:
            return str(x)

    # tolerant getters from your helpers
    v = state.get("validity")
    s = state.get("severity")
    e = state.get("exploitability")
    p = state.get("playbooks")
    d = state.get("decision")

    v_label       = get_field(v, "label", "—")
    v_likelihood  = get_field(v, "likelihood", None)
    v_rationale   = get_field(v, "rationale", "")

    s_level       = get_field(s, "level", "—")
    s_impact      = get_field(s, "impact", "—")
    s_rationale   = get_field(s, "rationale", "")

    e_level       = get_field(e, "level", "—")
    e_likelihood  = get_field(e, "likelihood", None)
    e_rationale   = get_field(e, "rationale", "")

    pb_names      = get_field(p, "names", None)
    pb_rationale  = get_field(p, "rationale", "")

    dec_path      = get_field(d, "path", None)
    dec_soc       = get_field(d, "soc_attention", None)
    dec_rat       = get_field(d, "rationale", "")

    with container:
        st.subheader("Scores & Decision")

        # --- 3 horizontal columns for the key scores ---
        col1, col2, col3 = st.columns([1, 1, 1])

        with col1:
            st.caption("Validity")
            st.metric(label=str(v_label), value=fmt_num(v_likelihood), help=v_rationale or None)

        with col2:
            st.caption("Severity")
            st.metric(label=str(s_impact), value=str(s_level), help=s_rationale or None)

        with col3:
            st.caption("Exploitability")
            st.metric(label=str(e_level), value=fmt_num(e_likelihood), help=e_rationale or None)

        # Playbooks (single row under metrics)
        st.caption("Playbooks")
        if isinstance(pb_names, (list, tuple)) and pb_names:
            st.write(", ".join(map(str, pb_names)))
        elif pb_names:
            st.write(str(pb_names))
        else:
            st.write(as_dict(p) or "—")
        if pb_rationale:
            st.caption(pb_rationale)

        # Decision (single row)
        st.caption("Decision")
        if dec_path:
            line = f"Path: {dec_path}"
            if dec_soc is not None:
                line += f" · SOC attention: {dec_soc}"
            st.write(line)
            if dec_rat:
                st.caption(dec_rat)
        else:
            st.caption("Decision pending…")


def render_enrichment(state: dict):
    """Render enrichment once per update (clears previous content and de-dupes for display)."""
    data = state.get("enrichment")
    if not data:
        return

    # Optional: de-dup entries by their JSON signature, for cleaner display
    def _dedupe(seq):
        seen, out = set(), []
        for item in (seq or []):
            sig = json.dumps(as_dict(item), sort_keys=True, default=str)
            if sig not in seen:
                seen.add(sig)
                out.append(item)
        return out

    internal = _dedupe(data.get("internal"))
    external = _dedupe(data.get("external"))

    # Clear the previous content in each placeholder, then re-draw
    try:
        enrich_ph1.empty()
        enrich_ph2.empty()
    except Exception:
        pass

    with enrich_ph1.container():
        st.subheader("Enrichment — Internal")
        st.json(internal)

    with enrich_ph2.container():
        st.subheader("Enrichment — External")
        st.json(external)


def append_timeline(state: dict):
    """Append the latest event to the Event Log (separate from the timeline sections)."""
    if "logs" in state and state["logs"]:
        last = state["logs"][-1]
        with eventlog_ph.expander(f"{last.at} — {last.event}", expanded=False):
            st.json(last.details, expanded=False)


def stepper_run(alert: Alert, delay: float = 0.6, policy: dict | None = None):
    state: dict = {"alert": alert, "logs": [], "policy": policy or load_policy()}
    status = {k: "pending" for k in NODES}
    decision_path = None

    # --- dynamic progress accounting ---
    # base: enrich (1) + validity + severity + exploitability (3) + playbooks (1) + decision (1) = 6
    total_steps_base = 6
    # branch steps are unknown until decision: No => 1 (update), Yes => 2 (triage + update)
    total_steps_branch = 2  # optimistic default; we'll downshift to 1 once we see "UPLOAD_XSOAR"
    total_steps = total_steps_base + total_steps_branch

    completed = 0
    pb = progress_ph.progress(0.0)
    eta_placeholder = eta_ph.empty()
    t0 = time.time()

    def _update_total_steps_for_decision(dp: str | None):
        nonlocal total_steps_branch, total_steps
        if dp == "UPLOAD_XSOAR":
            total_steps_branch = 1
        elif dp == "SOC_TRIAGE":
            total_steps_branch = 1  # triage only; status updates via HITL action

        total_steps = total_steps_base + total_steps_branch

    def tick():
        nonlocal completed
        completed += 1
        frac = min(completed / max(total_steps, 1), 1.0)
        pb.progress(frac)
        elapsed = time.time() - t0
        remaining = (elapsed / max(frac, 1e-6)) * (1 - frac)
        eta_placeholder.caption(f"Progress: {int(frac*100)}% — Elapsed {elapsed:.1f}s — ETA {remaining:.1f}s")

    # Initial diagram + timeline header and per-step placeholders
    render_diagram(diagram_ph, status, decision_path)
    with timeline_ph:
        st.subheader("Execution Timeline")
    tl_blocks = _ensure_timeline_blocks()
    # Clear any previous run's blocks
    for ph in tl_blocks.values():
        try: ph.empty()
        except Exception: pass

    # Reset/label the Event Log area
    eventlog_ph.empty()
    with eventlog_ph:
        st.subheader("Event Log")

    linear = ["enrich", "validity", "severity", "exploitability", "playbooks", "decision"]
    for node in linear:
        status[node] = "running"
        render_diagram(diagram_ph, status, decision_path)
        time.sleep(delay)

        delta = NODE_FUNCS[node](state)      # run node
        state = apply_delta(state, delta)    # merge update
        status[node] = "done"
        append_timeline(state)               # write latest event to Event Log

        if node == "enrich":
            render_enrichment(state)

        if node in {"validity", "severity", "exploitability", "playbooks", "decision"}:
            render_metrics(state)

        if node == "validity":
            _render_timeline_section(tl_blocks["validity"], "Validity", as_dict(state.get("validity")))
        elif node == "severity":
            _render_timeline_section(tl_blocks["severity"], "Severity", as_dict(state.get("severity")))
        elif node == "exploitability":
            _render_timeline_section(tl_blocks["exploitability"], "Exploitability", as_dict(state.get("exploitability")))
        elif node == "playbooks":
            p = state.get("playbooks")
            content = {"names": get_field(p, "names", None), "rationale": get_field(p, "rationale", None)}
            content = {k: v for k, v in content.items() if v not in (None, "", [])}
            _render_timeline_section(tl_blocks["playbooks"], "Playbooks", as_dict(content) if content else None)
        elif node == "decision":
            d = state.get("decision")
            content = {
                "path": get_field(d, "path", None),
                "soc_attention": get_field(d, "soc_attention", None),
                "rationale": get_field(d, "rationale", None),
            }
            _render_timeline_section(tl_blocks["decision"], "Decision", content)
            decision_path = get_field(d, "path", None)
            if decision_path:
                decision_path = str(decision_path).strip().upper()
            # ▶ Enforce & validate after decision appears
            state = _enforce_force_hitl_on_decision(state)
            decision_path = get_field(state.get("decision"), "path", decision_path)
            _validate_decision_path(decision_path)

            _update_total_steps_for_decision(decision_path)  # <-- add this line

        render_diagram(diagram_ph, status, decision_path)
        time.sleep(delay)
        tick()

    # -------- Branch after decision (updated semantics) --------
    if decision_path == "UPLOAD_XSOAR":
        # No SOC attention → automation WITHOUT upload, skip upload_xsoar
        status["upload_xsoar"] = "done"
        status["soc_triage"] = "skipped"

        # Directly update status
        node = "update_status"
        status[node] = "running"
        render_diagram(diagram_ph, status, decision_path); time.sleep(delay)
        delta = update_status_node(state)
        state = apply_delta(state, delta)
        status[node] = "done"
        append_timeline(state)
        render_diagram(diagram_ph, status, decision_path); time.sleep(delay)
        tick()

    else:
        # SOC attention = Yes → Human triage first
        status["upload_xsoar"] = "pending"  # not executed unless approved
        node = "soc_triage"
        status[node] = "running"
        render_diagram(diagram_ph, status, decision_path); time.sleep(delay)
        delta = soc_triage_node(state)
        state = apply_delta(state, delta)
        status[node] = "done"
        append_timeline(state)
        render_diagram(diagram_ph, status, decision_path); time.sleep(delay)
        tick()

    return state




def native_stream_run(alert: Alert, thread_id: str, policy: dict | None = None, checkpointer=None):
    """Run the graph with streaming snapshots and live UI updates, honoring SOC-attention rules:
       - decision == 'UPLOAD_XSOAR' (SOC attention = No): UI skips upload; finalize with update_status marked done.
       - decision == 'SOC_TRIAGE'   (Yes): triage is running until analyst acts; upload/update only after action.
    """
    # --- use provided checkpointer if available (important for MemorySaver) ---
    if checkpointer is None:
        try:
            from langgraph.checkpoint.sqlite import SqliteSaver
            checkpointer = SqliteSaver.from_conn_string("a2a_checkpoints.sqlite")
        except Exception:
            try:
                from langgraph.checkpoint.memory import MemorySaver
                checkpointer = MemorySaver()
            except Exception:
                checkpointer = None

    app = build_graph(parallel=True, checkpointer=checkpointer)
    cfg = {"configurable": {"thread_id": thread_id}}

    # --- local UI state ---
    local_state: dict = {
        "alert": alert,
        "logs": [],
        "policy": policy or load_policy(),
    }
    status = {k: "pending" for k in NODES}
    decision_path = None  # 'UPLOAD_XSOAR' or 'SOC_TRIAGE'

    # progress bar (we'll finalize to 100% after stream ends)
    total_steps = 7
    completed = 0
    pb = progress_ph.progress(0.0)

    def mark_done_by_key(key: str):
        """Mark node 'done' for UI unless rules say to skip (esp. HITL gating)."""
        nonlocal completed, decision_path

        node = STATE_TO_NODE.get(key)
        if not node:
            return

        # If HITL dismissed, never allow upload_xsoar to turn green later in the stream.
        if (
            decision_path == "SOC_TRIAGE"
            and node == "upload_xsoar"
            and latest_hitl_outcome(local_state) == "dismissed"
        ):
            return

        # Do NOT override branch visuals for upload_xsoar on the No path.
        # (Branch logic already set upload_xsoar=done; leave it alone.)
        if decision_path == "UPLOAD_XSOAR" and node == "upload_xsoar":
            return

        # On the HITL branch, do NOT mark update_status as done until human acts.
        if decision_path == "SOC_TRIAGE" and node == "update_status":
            if latest_hitl_outcome(local_state) == "pending":
                return

        if status.get(node) != "done":
            status[node] = "done"
            completed += 1
            pb.progress(min(completed / total_steps, 1.0))


    # initial diagram + timeline header + per-step placeholders
    render_diagram(diagram_ph, status, decision_path)
    with timeline_ph:
        st.subheader("Execution Timeline")
    eventlog_ph.empty()
    with eventlog_ph:
        st.subheader("Event Log")
    tl_blocks = _ensure_timeline_blocks()

    # --- stream *values* snapshots and merge ---
    for ev in app.stream(local_state, cfg, stream_mode="values"):
        snap = ev if isinstance(ev, dict) else (getattr(ev, "data", {}) or {}).get("values", {})
        if not isinstance(snap, dict):
            continue

        # Merge known keys into our local_state
        delta = {k: snap[k] for k in STATE_KEYS if k in snap}
        local_state = apply_delta(local_state, delta)

        # Update decision_path ONLY when a decision delta arrives
        dp = None
        if "decision" in delta:
            dp = get_field(local_state.get("decision"), "path")
            local_state = _enforce_force_hitl_on_decision(local_state)
            cand = get_field(local_state.get("decision"), "path", dp)
            cand = str(cand).strip().upper() if cand else None

            if decision_path is None:
                decision_path = cand
            elif decision_path == "SOC_TRIAGE":
                pass  # never downgrade
            elif cand == "SOC_TRIAGE":
                decision_path = "SOC_TRIAGE"

            _validate_decision_path(decision_path)


        # Compute current outcome (approved/dismissed/pending) from recorded logs
        outcome = latest_hitl_outcome(local_state)

        # Mirror visuals per current decision/outcome (native streaming)
        if decision_path == "UPLOAD_XSOAR":
            status["upload_xsoar"]  = "done"
            status["soc_triage"]    = "skipped"
            status["update_status"] = "done"

        elif decision_path == "SOC_TRIAGE":
            # Awaiting human unless there's a recorded outcome
            if outcome == "approved":
                status["soc_triage"]    = "done"
                status["upload_xsoar"]  = "done"
                status["update_status"] = "done"
            elif outcome == "dismissed":
                status["soc_triage"]    = "done"
                status["upload_xsoar"]  = "skipped"
                status["update_status"] = "done"
            else:
                status["soc_triage"]    = "running"
                status["upload_xsoar"]  = "pending"
                status["update_status"] = "pending"

        # Mark nodes done based on which keys appear (with HITL gating)
        for k in delta.keys():
            # Prevent premature green for update_status while waiting on HITL
            if (
                k == "status"
                and decision_path == "SOC_TRIAGE"
                and latest_hitl_outcome(local_state) == "pending"
            ):
                continue
            mark_done_by_key(k)

        # Live enrichment (two-column area)
        if local_state.get("enrichment"):
            render_enrichment(local_state)

        # Live metrics panel (separate from timeline)
        render_metrics(local_state)

        # Update step sections in the timeline (each renders once and refreshes)
        if "validity" in delta and tl_blocks.get("validity"):
            _render_timeline_section(tl_blocks["validity"], "Validity", as_dict(local_state.get("validity")))

        if "severity" in delta and tl_blocks.get("severity"):
            _render_timeline_section(tl_blocks["severity"], "Severity", as_dict(local_state.get("severity")))

        if "exploitability" in delta and tl_blocks.get("exploitability"):
            _render_timeline_section(tl_blocks["exploitability"], "Exploitability", as_dict(local_state.get("exploitability")))

        if "playbooks" in delta and tl_blocks.get("playbooks"):
            p = local_state.get("playbooks")
            names = get_field(p, "names", None)
            rat   = get_field(p, "rationale", "")
            content = {}
            if names:
                content["names"] = names
            if rat:
                content["rationale"] = rat
            _render_timeline_section(tl_blocks["playbooks"], "Playbooks", as_dict(content) if content else None)

        if "decision" in delta and tl_blocks.get("decision"):
            d = local_state.get("decision")
            content = {
                "path": get_field(d, "path", None),
                "soc_attention": get_field(d, "soc_attention", None),
                "rationale": get_field(d, "rationale", None),
            }
            _render_timeline_section(tl_blocks["decision"], "Decision", content)

        # Redraw diagram with any new status/path
        render_diagram(diagram_ph, status, decision_path)

    # --- Final state (checkpoint snapshot → fallback to assembled) ---
    try:
        final_state = app.get_state(cfg).values
        if not isinstance(final_state, dict) or not final_state:
            final_state = local_state
    except Exception:
        final_state = local_state

    # Render full raw event list separately (no duplication in timeline)
    eventlog_ph.empty()
    with eventlog_ph:
        for log in final_state.get("logs", []) or []:
            with st.expander(f"{log.at} — {log.event}", expanded=False):
                st.json(log.details, expanded=False)

    # -------- Finalize branch visuals (recompute from final_state) --------
    outcome = latest_hitl_outcome(final_state)

    if decision_path == "UPLOAD_XSOAR":
        status["upload_xsoar"]  = "done"
        status["soc_triage"]    = "skipped"
        status["update_status"] = "done"

    elif decision_path == "SOC_TRIAGE":
        if outcome == "approved":
            status["soc_triage"]    = "done"
            status["upload_xsoar"]  = "done"
            status["update_status"] = "done"
        elif outcome == "dismissed":
            status["soc_triage"]    = "done"
            status["upload_xsoar"]  = "skipped"
            status["update_status"] = "done"
        else:
            status["soc_triage"]    = "running"
            status.setdefault("upload_xsoar", "pending")
            status.setdefault("update_status", "pending")

    # Final diagram + progress completion
    render_diagram(diagram_ph, status, decision_path)
    pb.progress(1.0)

    return final_state






# -------- actions --------
def render_outputs(final_state: dict, decision_path: str | None):
    """
    Final panel with Playbooks, Final State JSON, diagram download,
    and Human-in-the-loop actions when path == SOC_TRIAGE (or forced via Dev/Test).

    IMPORTANT: When a human approves during HITL, we DO NOT flip the visual branch
    to UPLOAD_XSOAR. We keep the decision path on SOC_TRIAGE but still perform
    upload_xsoar + update_status under the hood. This avoids changing the graph
    highlight while preventing double-green branches.
    """
    import streamlit as st
    from datetime import datetime
    import json, re
    from domains import ActionLog

    # ---------- Helpers ----------
    def _get(obj, key, default=None):
        if hasattr(obj, key):
            try:
                return getattr(obj, key)
            except Exception:
                pass
        if isinstance(obj, dict) and key in obj:
            return obj[key]
        if isinstance(obj, str):
            m = re.search(rf"{re.escape(key)}\s*=\s*(\"[^\"]*\"|'[^']*'|[0-9.]+|True|False|None)", obj)
            if m:
                raw = m.group(1)
                if raw in ("True", "False"): return raw == "True"
                if raw == "None": return None
                if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
                    return raw[1:-1]
                try: return float(raw) if "." in raw else int(raw)
                except Exception: return raw
        return default

    def _jsonable(x):
        if hasattr(x, "model_dump"):  # pydantic v2
            return _jsonable(x.model_dump())
        if isinstance(x, dict):
            return {k: _jsonable(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)):
            return [_jsonable(v) for v in x]
        if isinstance(x, datetime):
            return x.isoformat()
        if isinstance(x, ActionLog):
            return {
                "at": x.at.isoformat() if isinstance(getattr(x, "at", None), datetime) else getattr(x, "at", None),
                "event": getattr(x, "event", None),
                "details": _jsonable(getattr(x, "details", {})),
            }
        if isinstance(x, str) and "(" in x and ")" in x:
            m = re.match(r"^[A-Za-z_]\w*\((.*)\)$", x.strip(), flags=re.S)
            if m:
                body = m.group(1)
                pairs = re.findall(r"(\w+)\s*=\s*(\"[^\"]*\"|'[^']*'|[0-9.]+|True|False|None)", body)
                out = {}
                for k, v in pairs:
                    v = v.strip()
                    if v in ("True", "False"):
                        out[k] = (v == "True")
                    elif v == "None":
                        out[k] = None
                    elif (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
                        out[k] = v[1:-1]
                    else:
                        try:
                            out[k] = float(v) if "." in v else int(v)
                        except Exception:
                            out[k] = v
                return out
        return x

    def _merge_like_stepper(state: dict, delta_or_state: dict) -> dict:
        """Merge node returns (delta/full) like stepper."""
        try:
            from copy import deepcopy
            base = deepcopy(state)
        except Exception:
            base = dict(state)
        if not isinstance(delta_or_state, dict):
            return base
        looks_full = any(k in delta_or_state for k in ("alert", "validity", "playbooks", "decision", "status"))
        if looks_full:
            for k, v in delta_or_state.items():
                base[k] = v
            return base
        try:
            return apply_delta(base, delta_or_state)
        except Exception:
            base.update(delta_or_state)
            return base

    # ---------- Resolve path (respect "Force HITL") ----------
    resolved_path = decision_path or _get(final_state.get("decision"), "path", None)
    # Normalize for stable comparisons
    if resolved_path:
        resolved_path = str(resolved_path).strip().upper()
    if st.session_state.get("force_hitl"):
        resolved_path = "SOC_TRIAGE"

    # In Replay when unlocked, always pause in triage
    if st.session_state.get("_replay_unlock_hitl"):
        resolved_path = "SOC_TRIAGE"

    # ---------- Diagram coloring (Run & Replay, Stepper & Native) ----------
    # Start with all pending
    status = {k: "pending" for k in NODES}

    # Mark nodes done if present in final_state
    for k in ("enrichment", "validity", "severity", "exploitability", "playbooks", "decision"):
        if final_state.get(k) is not None:
            node = STATE_TO_NODE.get(k)
            if node:
                status[node] = "done"

    # Branch visuals based on recorded outcome (avoid premature green)
    if resolved_path == "UPLOAD_XSOAR":
        status["upload_xsoar"]  = "done"
        status["soc_triage"]    = status.get("soc_triage", "skipped")
        status["update_status"] = "done"

    elif resolved_path == "SOC_TRIAGE":
        # Strict logs-only outcome to avoid premature green
        outcome = latest_hitl_outcome(final_state)
        # In Replay when unlocked, do not auto-finish from prior logs
        if st.session_state.get("_replay_unlock_hitl"):
            outcome = "pending"

        if outcome == "approved":
            status["soc_triage"]    = "done"
            status["upload_xsoar"]  = "done"
            status["update_status"] = "done"
        elif outcome == "dismissed":
            status["soc_triage"]    = "done"
            status["upload_xsoar"]  = "skipped"
            status["update_status"] = "done"
        else: # pending
            status["soc_triage"]    = "running"
            status["upload_xsoar"]  = "pending"
            status["update_status"] = "pending"

    # Slack: notify on transition to GREEN for XSOAR
    try:
        tid = _resolve_thread_id(final_state)
        _maybe_notify_xsoar_green(final_state, status, resolved_path, tid)
        dbg = st.session_state.get("_xsoar_notify_debug", {})
        st.caption(
            "🔎 XSOAR notify probe → "
            f"node={dbg.get('node_key')} "
            f"curr={dbg.get('curr_val')} "
            f"curr_green={dbg.get('curr_green')} "
            f"prev_green={dbg.get('prev_green')} "
            f"tid={dbg.get('thread_id')} "
            f"types={dbg.get('types')}"
        )
    except Exception as e:
        st.warning(f"Slack notify error: {e}")

    # Draw the live diagram with the computed statuses
    render_diagram(diagram_ph, status, resolved_path)

    # ---------- Playbooks ----------
    st.subheader("Playbooks")
    pb = final_state.get("playbooks")
    pb_names = _get(pb, "names", None)
    pb_rationale = _get(pb, "rationale", "")
    if isinstance(pb_names, (list, tuple)) and pb_names:
        st.write(", ".join(map(str, pb_names)))
    elif pb_names:
        st.write(str(pb_names))
    else:
        st.write(_jsonable(pb) or "—")
    if pb_rationale:
        with st.expander("Playbook rationale"):
            st.write(pb_rationale)

    # ---------- Final State (INLINE JSON) ----------
    st.subheader("Final State")
    keys = ["alert","enrichment","validity","severity","exploitability","playbooks","decision","status","logs"]
    jsonish = {}
    for k in keys:
        if k not in final_state:
            continue
        v = final_state[k]
        jsonish[k] = [_jsonable(x) for x in (v or [])] if k == "logs" else _jsonable(v)

    if resolved_path:
        if isinstance(jsonish.get("decision"), dict):
            jsonish["decision"]["path_resolved"] = resolved_path
        else:
            jsonish["decision"] = {
                "path_resolved": resolved_path,
                **({"raw": str(final_state.get("decision"))} if final_state.get("decision") is not None else {})
            }

    try:
        st.json(jsonish, expanded=False)
    except Exception:
        st.code(json.dumps(jsonish, indent=2, ensure_ascii=False, default=str), language="json")

    # Quick export
    st.download_button(
        "Download Final State (JSON)",
        data=json.dumps(jsonish, indent=2, ensure_ascii=False).encode(),
        file_name="final_state.json",
        mime="application/json",
    )

    # Diagram export (keep as-is per your original: full-green snapshot with branch highlight)
    dot = build_gv(status, resolved_path)
    try:
        svg_bytes = dot.pipe(format="svg")
        st.download_button(
            "Download diagram (SVG)",
            svg_bytes,
            file_name="a2a_flow.svg",
            mime="image/svg+xml",
        )
    except Exception as e:
        st.warning(f"Diagram download unavailable: {e}")

    # ---------- Human-in-the-loop ----------
    if resolved_path == "SOC_TRIAGE":

        outcome = latest_hitl_outcome(final_state)

        # Use per-thread key if present; if still pending, clear stale "actioned" flag (enables buttons on Replay)
        mode = _mode_from_run_mode(run_mode)
        last_tid, _, _ = _get_last_state(mode)
        thread_id = last_tid or "default"
        hitl_key  = f"_hitl_action:{thread_id}"
        if outcome == "pending":
            st.session_state.pop(hitl_key, None)

        hitl_action = st.session_state.get(hitl_key)

        # Compact context banner
        sev_level = _get(final_state.get("severity"), "level", "—")
        exp_level = _get(final_state.get("exploitability"), "level", "—")
        host = None
        ip   = None
        inds = _jsonable(_get(final_state.get("alert") or {}, "indicators", []) or [])
        for it in inds or []:
            t = _get(it, "type", "")
            if (t or "").lower() == "host" and not host:
                host = _get(it, "value", None)
            if (t or "").lower() == "ip" and not ip:
                ip = _get(it, "value", None)

        st.markdown("### Human actions")
        st.info(
            f"**HITL required.** Severity: **{sev_level}**, Exploitability: **{exp_level}**"
            + (f" — Host: **{host}**" if host else "")
            + (f", IP: **{ip}**" if ip else "")
            + ("  _(Forced via Dev/Test toggle)_" if st.session_state.get("force_hitl") else "")
        )

        # Action bar
        colA, colB = st.columns(2)
        # Only disable if outcome finalized AND we're not explicitly unlocking for Replay
        disable_all = (outcome in ("approved", "dismissed")) and not st.session_state.get("_replay_unlock_hitl", False)

        approve = colA.button("Approve & Upload to XSOAR ✅",
                            key=f"hitl_approve:{thread_id}", disabled=disable_all)
        dismiss  = colB.button("Dismiss Incident 🛑",
                            key=f"hitl_dismiss:{thread_id}",  disabled=disable_all)

        # Approve → upload_xsoar -> update_status; persist + rerun
        if approve and not disable_all:
            try:
                with st.spinner("Uploading to XSOAR and updating status…"):
                    safe = ensure_upload_ready(final_state, avoid_logs=True)
                    # Coerce 'decision' back to model if it’s a plain dict (stepper path safeguard)
                    try:
                        from domains import Decision as _Decision
                        if isinstance(safe.get("decision"), dict):
                            safe["decision"] = _Decision(**safe["decision"])
                    except Exception:
                        pass

                    fs1 = upload_xsoar_node(safe)
                    fs2 = update_status_node(_merge_like_stepper(safe, fs1))
                    merged = _merge_like_stepper(safe, fs2)

                    # Preserve all prior logs, then add any node logs, then the human_approved marker
                    prior_logs = _dedupe_logs(final_state.get("logs", []) or [])
                    new_logs   = _dedupe_logs(merged.get("logs", []) or [])
                    try:
                        human_log = ActionLog(event="human_approved", details={"by": "analyst", "action": "upload_xsoar"})
                    except Exception:
                        human_log = ActionLog(event="human_approved", details={"by": "analyst"})
                    merged["logs"] = _dedupe_logs([*prior_logs, *new_logs, human_log])


                    _set_last_state(mode, thread_id=thread_id, final_state=merged, decision_path="SOC_TRIAGE")
                    st.session_state[hitl_key] = "approved"

                    if st.session_state.get("force_hitl"):
                        st.session_state["force_hitl"] = False

                st.success("Approved & uploaded to XSOAR.")
                _bump_diagram_nonce()
                _bust_diagram_cache()
                # one-shot flag so the outer view retains all sections after rerun (Stepper & Native)
                st.session_state["_post_hitl_render"] = True
                st.rerun()
            except Exception as e:
                st.error(f"Upload action failed: {e}")

        # Dismiss → set status; persist + rerun
        if dismiss and not disable_all:
            try:
                with st.spinner("Dismissing incident…"):
                    merged = dict(final_state)
                    merged["status"] = "Dismissed by analyst"
                    logs = merged.get("logs", []) or []
                    try:
                        logs.append(ActionLog(event="human_dismissed", details={"by": "analyst"}))
                    except Exception:
                        pass
                    merged["logs"] = logs
                    merged.pop("upload_xsoar", None)  # ensure visual stays grey on dismiss
                    _set_last_state(mode, thread_id=thread_id, final_state=merged, decision_path="SOC_TRIAGE")
                    st.session_state[hitl_key] = "dismissed"

                st.warning("Incident dismissed. (No external action taken)")
                _bump_diagram_nonce()
                _bust_diagram_cache()
                # one-shot flag so the outer view retains all sections after rerun (Stepper & Native)
                st.session_state["_post_hitl_render"] = True
                st.rerun()
            except Exception as e:
                st.error(f"Dismiss action failed: {e}")

        # Status pill when already actioned
        if disable_all:
            if hitl_action == "approved":
                st.success("Already approved and uploaded for this thread.")
            elif hitl_action == "dismissed":
                st.warning("Already dismissed for this thread.")
    else:
        st.info("Automation path selected (UPLOAD_XSOAR). No human action required here.")





# ---------- RUN handler ----------
if run_btn:
    # Determine current UI mode
    mode = _mode_from_run_mode(run_mode)

    # Start from scratch visually
    reset_layout()  # clears all placeholders/containers for current view

    # Always mint a fresh thread id to avoid mixing with old checkpoints
    fresh_tid = _fresh_thread_id(prefix="native" if mode == MODE_NATIVE else "stepper")
    st.session_state["fresh_tid"] = fresh_tid   # <-- add this line

    # Build a checkpointer suited for this run:
    # - For Native, use persistent sqlite so REPLAY can retrieve; fresh thread id keeps it isolated.
    # - For true "ignore memory" semantics, we don't *read* any old state; the fresh thread id suffices.
    # - For Stepper, no checkpointer.
    cp, backend = _build_checkpointer_for_mode(mode, ephemeral_for_run=False)

    # Remember which backend is tied to the current mode (for diagnostics only)
    st.session_state[f"_checkpointer_{mode}"] = cp
    st.session_state[f"_checkpoint_backend_{mode}"] = backend

    st.sidebar.caption(f"Checkpoint backend ({mode}): **{backend}**")

    # Execute according to mode
    if mode == MODE_NATIVE:
        with st.status("Streaming with LangGraph (parallel)…", expanded=True) as sb:
            final_state = native_stream_run(alert, thread_id=fresh_tid, policy=policy, checkpointer=cp)
            sb.update(label="Flow completed", state="complete")
    else:
        with st.status("Sequential stepper…", expanded=True) as sb:
            final_state = stepper_run(alert, delay=delay, policy=policy)
            sb.update(label="Flow completed", state="complete")

    if not isinstance(final_state, dict):
        final_state = as_dict(final_state) or {}

    # Extract decision path safely (only for the active mode)
    decision_path = get_field(final_state.get("decision"), "path", None)

    # Store last state ONLY for this mode (so the other mode stays clean)
    _set_last_state(mode, thread_id=fresh_tid, final_state=final_state, decision_path=decision_path)

    # Render outputs for this run
    render_outputs(final_state, decision_path=decision_path)



# ---------- REPLAY handler (DROP-IN) ----------
elif replay_btn:
    mode = _mode_from_run_mode(run_mode)

    reset_layout()  # fresh containers for a clean replay render

    last_tid, last_state, last_path = _get_last_state(mode)
    if not last_tid and not last_state:
        st.error("No replayable state for this mode. Run once in this mode, then Replay.")
    else:
        if mode == MODE_NATIVE:
            # Build graph/checkpointer for this mode and thread_id
            cp = st.session_state.get(f"_checkpointer_{mode}")
            backend = st.session_state.get(f"_checkpoint_backend_{mode}", "unknown")

            # Fallback: if cp missing (e.g., after restart), recreate sqlite-based cp so get_state works
            if cp is None:
                cp, backend = _build_checkpointer_for_mode(mode, ephemeral_for_run=False)

            app = build_graph(parallel=True, checkpointer=cp)
            cfg = {"configurable": {"thread_id": last_tid}}

            st.info(f"Replaying last state for thread_id='{last_tid}' (backend: {backend}).")

            # Try checkpoint first
            state = None
            try:
                st_obj = app.get_state(cfg)
                state = getattr(st_obj, "values", None)
                if not isinstance(state, dict) or not state:
                    state = None
            except Exception:
                state = None

            # Fallback to in-session remembered state if checkpoints are unavailable
            if state is None:
                state = last_state

            if not state:
                st.error("No checkpointed or cached state available for this mode. Run again, then Replay.")
            else:
                # Normalize & render
                state = as_dict(state) or {}
                decision_path = get_field(state.get("decision"), "path", last_path)
                if decision_path:
                    decision_path = str(decision_path).strip().upper()

                # Build branch-aware status (mirror stepper semantics), logs-aware for HITL
                base_done = ["enrich", "validity", "severity", "exploitability", "playbooks", "decision"]
                status = {k: "done" for k in base_done}

                if decision_path == "UPLOAD_XSOAR":
                    # No SOC attention → automation WITHOUT upload
                    status["upload_xsoar"]  = "done"
                    status["soc_triage"]    = "skipped"
                    status["update_status"] = "done"

                elif decision_path == "SOC_TRIAGE":
                    outcome = latest_hitl_outcome(state)
                    if outcome == "approved":
                        status["soc_triage"]    = "done"
                        status["upload_xsoar"]  = "done"
                        status["update_status"] = "done"
                    elif outcome == "dismissed":
                        status["soc_triage"]    = "done"
                        status["upload_xsoar"]  = "skipped"
                        status["update_status"] = "done"
                    else:
                        status["soc_triage"]    = "running"
                        status["upload_xsoar"]  = "pending"
                        status["update_status"] = "pending"
                else:
                    # Unknown/missing path → keep both branches pending
                    status["upload_xsoar"]  = "pending"
                    status["soc_triage"]    = "pending"
                    status["update_status"] = "pending"


                # Diagram
                render_diagram(diagram_ph, status, decision_path)

                # Timeline placeholders and sections
                with timeline_ph:
                    st.subheader("Execution Timeline")
                tl_blocks = _ensure_timeline_blocks()
                if state.get("validity") is not None:
                    _render_timeline_section(tl_blocks["validity"], "Validity", as_dict(state["validity"]))
                if state.get("severity") is not None:
                    _render_timeline_section(tl_blocks["severity"], "Severity", as_dict(state["severity"]))
                if state.get("exploitability") is not None:
                    _render_timeline_section(tl_blocks["exploitability"], "Exploitability", as_dict(state["exploitability"]))
                if state.get("playbooks") is not None:
                    p = state.get("playbooks")
                    content = {
                        "names": get_field(p, "names", None),
                        "rationale": get_field(p, "rationale", None),
                    }
                    content = {k: v for k, v in content.items() if v not in (None, "", [])}
                    _render_timeline_section(tl_blocks["playbooks"], "Playbooks", as_dict(content) if content else None)
                if state.get("decision") is not None:
                    d = state.get("decision")
                    content = {
                        "path": get_field(d, "path", None),
                        "soc_attention": get_field(d, "soc_attention", None),
                        "rationale": get_field(d, "rationale", None),
                    }
                    _render_timeline_section(tl_blocks["decision"], "Decision", content)

                # Event log area
                with eventlog_ph:
                    st.subheader("Event Log")
                    for log in state.get("logs", []) or []:
                        with st.expander(f"{log.at} — {log.event}", expanded=False):
                            st.json(log.details, expanded=False)

                # Enrichment & metrics
                render_enrichment(state)
                render_metrics(state)

                # Final panel
                render_outputs(state, decision_path=decision_path)

        else:
            # Stepper replay: use the in-session last state only (no checkpoints)
            state = last_state
            if not state:
                st.error("No cached state for stepper mode. Run once in stepper mode, then Replay.")
            else:
                state = as_dict(state) or {}
                decision_path = get_field(state.get("decision"), "path", last_path)  # ← fallback to last_path
                if decision_path:
                    decision_path = str(decision_path).strip().upper()

                # --- Replay HITL controller (single source of truth) ---
                # If Force HITL is ON, unlock HITL and pause in triage; otherwise respect original decision and clear stale flags.
                unlock = bool(st.session_state.get("force_hitl", False))
                st.session_state["_replay_unlock_hitl"] = unlock
                if unlock:
                    decision_path = "SOC_TRIAGE"
                    _bump_diagram_nonce()
                    _bust_diagram_cache()
                else:
                    # Respect original decision; remove any stale unlock or thread action that could keep UI paused/disabled
                    st.session_state.pop("_replay_unlock_hitl", None)
                    st.session_state.pop(f"_hitl_action:{last_tid or 'default'}", None)


                # Reset and render consistently
                diagram_ph.empty(); metrics_ph.empty(); enrich_ph1.empty(); enrich_ph2.empty()
                timeline_ph.empty(); eventlog_ph.empty()
                if "_timeline_blocks" in st.session_state:
                    del st.session_state["_timeline_blocks"]

                # Build branch-aware status for stepper replay
                status = {k: "pending" for k in NODES}
                for k in ("enrichment","validity","severity","exploitability","playbooks","decision"):
                    if state.get(k) is not None:
                        node = STATE_TO_NODE.get(k)
                        if node: status[node] = "done"

                # Re-enable HITL buttons on Stepper Replay when outcome is still pending
                outcome = latest_hitl_outcome(state)  # ← use the existing helper
                if outcome == "pending":
                    st.session_state.pop(f"_hitl_action:{last_tid or 'default'}", None)

                if decision_path == "UPLOAD_XSOAR":
                    status["upload_xsoar"]  = "done"
                    status["soc_triage"]    = "skipped"
                    status["update_status"] = "done"
                elif decision_path == "SOC_TRIAGE":
                    outcome = latest_hitl_outcome(state)
                    # During Replay with HITL unlocked, never auto-finish based on old logs
                    if st.session_state.get("_replay_unlock_hitl"):
                        outcome = "pending"
                    if outcome == "approved":
                        status["soc_triage"]    = "done"
                        status["upload_xsoar"]  = "done"
                        status["update_status"] = "done"
                    elif outcome == "dismissed":
                        status["soc_triage"]    = "done"
                        status["upload_xsoar"]  = "skipped"
                        status["update_status"] = "done"
                    else:
                        status["soc_triage"]    = "running"
                        status["upload_xsoar"]  = "pending"
                        status["update_status"] = "pending"
                else:
                    status["upload_xsoar"]  = "pending"
                    status["soc_triage"]    = "pending"
                    status["update_status"] = "pending"

                render_diagram(diagram_ph, status, decision_path)

                with timeline_ph:
                    st.subheader("Execution Timeline")
                tl_blocks = _ensure_timeline_blocks()

                if state.get("validity") is not None:
                    _render_timeline_section(tl_blocks["validity"], "Validity", as_dict(state["validity"]))
                if state.get("severity") is not None:
                    _render_timeline_section(tl_blocks["severity"], "Severity", as_dict(state["severity"]))
                if state.get("exploitability") is not None:
                    _render_timeline_section(tl_blocks["exploitability"], "Exploitability", as_dict(state["exploitability"]))
                if state.get("playbooks") is not None:
                    p = state.get("playbooks")
                    content = {
                        "names": get_field(p, "names", None),
                        "rationale": get_field(p, "rationale", None),
                    }
                    content = {k: v for k, v in content.items() if v not in (None, "", [])}
                    _render_timeline_section(tl_blocks["playbooks"], "Playbooks", as_dict(content) if content else None)
                if state.get("decision") is not None:
                    d = state.get("decision")
                    content = {
                        "path": get_field(d, "path", None),
                        "soc_attention": get_field(d, "soc_attention", None),
                        "rationale": get_field(d, "rationale", None),
                    }
                    _render_timeline_section(tl_blocks["decision"], "Decision", content)

                with eventlog_ph:
                    st.subheader("Event Log")
                    for log in state.get("logs", []) or []:
                        with st.expander(f"{log.at} — {log.event}", expanded=False):
                            st.json(log.details, expanded=False)

                render_enrichment(state)
                render_metrics(state)
                # Only unlock/pause HITL in Replay when Force HITL is enabled
                if st.session_state.get("force_hitl"):
                    st.session_state["_replay_unlock_hitl"] = True
                    _bump_diagram_nonce()
                    _bust_diagram_cache()
                    try:
                        render_outputs(state, decision_path=decision_path)
                    finally:
                        st.session_state.pop("_replay_unlock_hitl", None)
                else:
                    # Respect the real decision path; do NOT force triage
                    render_outputs(state, decision_path=decision_path)



# ---------- CLEAR handler ----------
elif clear_btn:
    # Clear UI containers first
    eventlog_ph.empty()
    if "_timeline_blocks" in st.session_state:
        del st.session_state["_timeline_blocks"]
    diagram_ph.empty(); metrics_ph.empty(); progress_ph.empty(); eta_ph.empty()
    playbook_ph.empty(); enrich_ph1.empty(); enrich_ph2.empty(); timeline_ph.empty()
    final_state_ph.empty(); download_ph.empty(); human_actions_ph.empty()

    # Hard wipe memory + checkpoints for ALL modes
    clear_all_checkpoints_and_memory()
    # Also clear any previous XSOAR green dedupe flags
    for k in list(st.session_state.keys()):
        if str(k).startswith("_xsoar_green_state:"):
            st.session_state.pop(k, None)
    # Show neutral diagram/state
    render_diagram(diagram_ph, {k: "pending" for k in NODES}, None)
    st.success("Cleared all memory and checkpoints.")




# ---------- IDLE (no button) ----------
else:
    mode = _mode_from_run_mode(run_mode)
    last_tid, last_state, last_path = _get_last_state(mode)

    if last_state:
        fs = as_dict(last_state) or {}
        decision_path = get_field(fs.get("decision"), "path", last_path)
        if decision_path:
            decision_path = str(decision_path).strip().upper()

        outc = latest_hitl_outcome(fs)

        # Clear any stale per-thread action flag if outcome is still pending (enables buttons on Replay)
        mode_ = _mode_from_run_mode(run_mode)
        tid_, _, _ = _get_last_state(mode_)
        st.session_state.pop(f"_hitl_action:{tid_ or 'default'}", None) if outc == "pending" else None

        # 1) Diagram (branch-aware)
        status = {k: "pending" for k in NODES}
        for k in ("enrichment","validity","severity","exploitability","playbooks","decision"):
            if fs.get(k) is not None:
                node = STATE_TO_NODE.get(k)
                if node:
                    status[node] = "done"

        if decision_path == "UPLOAD_XSOAR":
            status["upload_xsoar"]  = "done"
            status["soc_triage"]    = "skipped"
            status["update_status"] = "done"
        elif decision_path == "SOC_TRIAGE":
            if outc == "approved":
                status["soc_triage"]    = "done"
                status["upload_xsoar"]  = "done"
                status["update_status"] = "done"
            elif outc == "dismissed":
                status["soc_triage"]    = "done"
                status["upload_xsoar"]  = "skipped"
                status["update_status"] = "done"
            else:
                status["soc_triage"]    = "running"
                status["upload_xsoar"]  = "pending"
                status["update_status"] = "pending"

        render_diagram(diagram_ph, status, decision_path)

        # 2) Timeline sections
        with timeline_ph:
            st.subheader("Execution Timeline")
        tl_blocks = _ensure_timeline_blocks()
        if fs.get("validity") is not None:
            _render_timeline_section(tl_blocks["validity"], "Validity", as_dict(fs["validity"]))
        if fs.get("severity") is not None:
            _render_timeline_section(tl_blocks["severity"], "Severity", as_dict(fs["severity"]))
        if fs.get("exploitability") is not None:
            _render_timeline_section(tl_blocks["exploitability"], "Exploitability", as_dict(fs["exploitability"]))
        if fs.get("playbooks") is not None:
            p = fs.get("playbooks")
            content = {
                "names": get_field(p, "names", None),
                "rationale": get_field(p, "rationale", None),
            }
            content = {k: v for k, v in content.items() if v not in (None, "", [])}
            _render_timeline_section(tl_blocks["playbooks"], "Playbooks", as_dict(content) if content else None)
        if fs.get("decision") is not None:
            d = fs.get("decision")
            content = {
                "path": get_field(d, "path", None),
                "soc_attention": get_field(d, "soc_attention", None),
                "rationale": get_field(d, "rationale", None),
            }
            _render_timeline_section(tl_blocks["decision"], "Decision", content)

        # 3) Event log (full)
        eventlog_ph.empty()
        with eventlog_ph:
            st.subheader("Event Log")
            for log in fs.get("logs", []) or []:
                with st.expander(f"{log.at} — {log.event}", expanded=False):
                    st.json(log.details, expanded=False)

        # 4) Enrichment + metrics
        render_enrichment(fs)
        render_metrics(fs)

        # 5) Final panel (includes HITL buttons if pending)
        render_outputs(fs, decision_path=decision_path)

        st.info("Showing the most recent results. Use Replay for details, or Run to start fresh.")
    else:
        render_diagram(diagram_ph, {k: "pending" for k in NODES}, None)
        st.info("Configure the alert and click **Run ▶️**.")
