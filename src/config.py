from __future__ import annotations
from functools import lru_cache
from pathlib import Path
import os, yaml
from typing import Any, Dict, List

_DEFAULT: Dict[str, Any] = {
    "policy_version": 1,
    "collect_all_matches": False,
    "default_rule_priority": 100,
    "thresholds": {
        "validity_tp_min": 0.60,
        "severity_min": 2,
        "exploit_levels_escalate": ["Medium", "Critical"],
    },
    # future: playbook_rules mapping
    "playbook_rules": [],
}

_ALLOWED_PLAYBOOK_WHEN_KEYS = {
    "product",
    "alert_type",
    "severity_max_level",
    "validity_tp_min",
    "validity_tp_max",
    "exploitability_levels_in",
    "exploitability_levels_not_in",
}

_ALLOWED_PLAYBOOK_DO_KEYS = {"decision", "auto_action", "phases"}
_PHASE_KEYS = {"identification", "containment", "recovery"}
_DECISION_VALUES = {"UPLOAD_XSOAR", "SOC_TRIAGE"}

def _coerce_bool(v: Any, default: bool) -> bool:
    if isinstance(v, bool): return v
    if isinstance(v, str): return v.strip().lower() in {"1","true","yes","y","on"}
    return default

def _as_list(v: Any) -> List[Any]:
    if v is None: return []
    if isinstance(v, list): return v
    return [v]

def _validate_and_normalize_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(policy)

    # --- top-level toggles ---
    out["policy_version"] = int(out.get("policy_version", _DEFAULT["policy_version"]))
    out["collect_all_matches"] = _coerce_bool(out.get("collect_all_matches", _DEFAULT["collect_all_matches"]),
                                              _DEFAULT["collect_all_matches"])
    out["default_rule_priority"] = int(out.get("default_rule_priority", _DEFAULT["default_rule_priority"]))

    # --- thresholds ---
    thr = dict(_DEFAULT["thresholds"])
    thr.update(out.get("thresholds", {}) or {})
    thr["validity_tp_min"] = float(thr.get("validity_tp_min", _DEFAULT["thresholds"]["validity_tp_min"]))
    thr["severity_min"] = int(thr.get("severity_min", _DEFAULT["thresholds"]["severity_min"]))
    esc = _as_list(thr.get("exploit_levels_escalate", _DEFAULT["thresholds"]["exploit_levels_escalate"]))
    thr["exploit_levels_escalate"] = [str(x) for x in esc]
    out["thresholds"] = thr

    # --- playbook_rules ---
    rules_in = out.get("playbook_rules", []) or []
    if not isinstance(rules_in, list):
        raise ValueError("playbook_rules must be a list")

    rules_out: List[Dict[str, Any]] = []
    for i, r in enumerate(rules_in):
        if not isinstance(r, dict):
            raise ValueError(f"playbook_rules[{i}] must be a mapping")
        rid = r.get("id") or f"RULE_{i+1}"
        enabled = _coerce_bool(r.get("enabled", True), True)
        priority = int(r.get("priority", out["default_rule_priority"]))

        # when
        when = r.get("when", {}) or {}
        if not isinstance(when, dict):
            raise ValueError(f"{rid}: when must be a mapping")
        unknown_when = set(when.keys()) - _ALLOWED_PLAYBOOK_WHEN_KEYS
        if unknown_when:
            raise ValueError(f"{rid}: unknown 'when' keys: {sorted(unknown_when)}")

        # normalize when fields
        w_norm: Dict[str, Any] = {}
        if "product" in when:
            w_norm["product"] = str(when["product"])
        if "alert_type" in when:
            w_norm["alert_type"] = str(when["alert_type"])
        if "severity_max_level" in when:
            w_norm["severity_max_level"] = int(when["severity_max_level"])
        if "validity_tp_min" in when:
            w_norm["validity_tp_min"] = float(when["validity_tp_min"])
        if "validity_tp_max" in when:
            w_norm["validity_tp_max"] = float(when["validity_tp_max"])
        if "exploitability_levels_in" in when:
            w_norm["exploitability_levels_in"] = [str(x) for x in _as_list(when["exploitability_levels_in"])]
        if "exploitability_levels_not_in" in when:
            w_norm["exploitability_levels_not_in"] = [str(x) for x in _as_list(when["exploitability_levels_not_in"])]

        # do
        do = r.get("do", {}) or {}
        if not isinstance(do, dict):
            raise ValueError(f"{rid}: do must be a mapping")
        unknown_do = set(do.keys()) - _ALLOWED_PLAYBOOK_DO_KEYS
        if unknown_do:
            raise ValueError(f"{rid}: unknown 'do' keys: {sorted(unknown_do)}")

        decision = do.get("decision")
        if decision is not None:
            if str(decision) not in _DECISION_VALUES:
                raise ValueError(f"{rid}: do.decision must be one of {sorted(_DECISION_VALUES)}")
        auto_action = do.get("auto_action")
        if auto_action is not None:
            auto_action = str(auto_action)

        phases = do.get("phases", {}) or {}
        if not isinstance(phases, dict):
            raise ValueError(f"{rid}: do.phases must be a mapping")
        # ensure only known phase keys present and lists inside
        for k in list(phases.keys()):
            if k not in _PHASE_KEYS:
                raise ValueError(f"{rid}: unknown phase '{k}'. Allowed: {sorted(_PHASE_KEYS)}")
            steps = _as_list(phases[k])
            phases[k] = [str(s) for s in steps]

        rules_out.append({
            "id": rid,
            "enabled": enabled,
            "priority": priority,
            "description": r.get("description", ""),
            "when": w_norm,
            "do": {
                "decision": decision,
                "auto_action": auto_action,
                "phases": phases,
            }
        })

    # sort by priority (lower first)
    rules_out.sort(key=lambda x: x.get("priority", out["default_rule_priority"]))
    out["playbook_rules"] = rules_out
    return out

@lru_cache
def load_policy() -> dict:
    path = os.getenv("A2A_POLICY", str(Path(__file__).resolve().parent.parent / "config.yaml"))
    p = Path(path)
    if p.exists():
        with open(p, "r") as f:
            data = yaml.safe_load(f) or {}
        # shallow-merge onto defaults
        out = _DEFAULT.copy()
        out.update(data)
        if "thresholds" in data:
            out["thresholds"] = {**_DEFAULT["thresholds"], **(data.get("thresholds") or {})}
        # validate & normalize
        return _validate_and_normalize_policy(out)
    # default policy also normalized
    return _validate_and_normalize_policy(_DEFAULT)
