# Mini-README: Introducing `playbook_rules`

This document explains what changed to add **rule-driven playbook selection**, how to **configure** the rules in `config.yaml`, and how to **test** them safely.

---

## 1) What changed (scope of edits)

**Files updated**

* `config.yaml`

  * Added top-level `playbook_rules` list (rules are pure config).
  * (Optional hardening) Added `policy_version`, `collect_all_matches`, `default_rule_priority`, rule `enabled` & `priority`.

**Files minimally touched to use the rules**

* `src/agents.py`

  * `playbook_agent(...)` now accepts `policy` and biases the LLM with **deterministically matched rule hints**.
  * Added tiny helpers `_infer_alert_meta(...)`, `_rule_matches(...)`, `_select_matching_rules(...)`.
* `src/graph.py`

  * `playbooks_node(...)` loads policy via `load_policy()` and **passes it** to `playbook_agent(...)`.
  * Log now includes `policy_version` and `rules_count` for observability.

**Files *not* changed**

* All others (domain objects, tools, etc.) remain untouched.

> Backward-compatible: if `playbook_rules` is empty or missing, behavior stays as before. The decision agent still uses thresholds; the playbook agent just won’t get rule hints.

---

## 2) Policy & Rules: structure

### 2.1 Top-level policy keys (in `config.yaml`)

```yaml
policy_version: 1                 # optional metadata
collect_all_matches: false        # false = first matching rule wins; true = pass all matches as hints
default_rule_priority: 100        # lower number = higher precedence
thresholds:
  validity_tp_min: 0.65           # used by decision_agent
  severity_min: 3                 # used by decision_agent
  exploit_levels_escalate: ["Medium", "Critical"]  # used by decision_agent
```

### 2.2 `playbook_rules` schema

Each item is a mapping with three parts: `id`, `when`, and `do` (+ optional toggles).

```yaml
playbook_rules:
  - id: <STRING>                  # unique rule name
    enabled: true                 # optional; default true
    priority: 90                  # optional; default default_rule_priority
    description: <STRING>         # free text
    when:                         # deterministic match conditions
      product: CrowdStrike        # optional exact match
      alert_type: EDR             # optional exact match (see “meta inference” note below)
      severity_max_level: 2       # optional; 1..3 per domains.SeverityScore.level
      validity_tp_min: 0.60       # optional; float 0..1
      validity_tp_max: 0.30       # optional; float 0..1
      exploitability_levels_in: ["Critical"]          # optional; exact set inclusion
      exploitability_levels_not_in: ["Medium","Critical"]  # optional; exclusion
    do:
      decision: UPLOAD_XSOAR | SOC_TRIAGE   # hint for orchestration/actioning
      auto_action: <STRING>         # free text hint, e.g., escalate / auto_close / guarded_reset_mfa
      phases:                       # optional: doc the intended steps by incident phase
        identification: [ ... ]
        containment: [ ... ]
        recovery: [ ... ]
```

**Severity & exploitability enums**

* `SeverityScore.level`: **1=Low**, **2=Moderate**, **3=High**
* `ExploitabilityScore.level`: **"Not Exploitable" | "Low" | "Medium" | "Critical"**

> **Meta inference:** The matcher derives `product` and `alert_type` heuristically from the alert **title/description** today:
>
> * `product: "CrowdStrike"` if the text mentions “crowdstrike” or “edr”
> * `alert_type: "EDR"` if text mentions “edr” or “endpoint”
> * `alert_type: "Auth/BruteForce"` if text mentions “brute” or “password spray”
>   For high fidelity, ensure your alert titles/descriptions include those tokens or extend this mapping later.

---

## 3) How matching works (deterministic pre-filter)

1. Compute meta: `_infer_alert_meta(alert)` → `{product, alert_type}` from strings in title/description.
2. For each rule (sorted by `priority` ascending), evaluate `when` conditions against:

   * `ValidityScore.likelihood` (0..1)
   * `SeverityScore.level` (1..3)
   * `ExploitabilityScore.level` (enum names)
3. Collect matches:

   * If `collect_all_matches: false` → take **the first** match.
   * If `true` → pass **all** matches.
4. Pass compact hints to the LLM: `[(rule_id, auto_action), ...]`.
   The LLM then selects **1–4 playbooks** but is **biased** toward rule hints.

---

## 4) Configure: examples

### 4.1 Minimal rule (auto-close benign low-sev EDR)

```yaml
- id: EDR_LOW_SEV_AUTO_CLOSE_SAFE
  enabled: true
  priority: 90
  description: Auto-close benign low-severity EDR alerts.
  when:
    product: CrowdStrike
    alert_type: EDR
    severity_max_level: 1
    validity_tp_max: 0.30
    exploitability_levels_not_in: ["Medium","Critical"]
  do:
    decision: SOC_TRIAGE
    auto_action: auto_close
    phases:
      identification:
        - Record auto-dismiss rationale
        - Attach enrichment summary
```

### 4.2 Escalate critical exploitability even if severity is low

```yaml
- id: EDR_LOW_SEV_CRITICAL_EXPLOIT_ESCALATE
  enabled: true
  priority: 50
  description: Escalate any EDR alert with Critical exploitability.
  when:
    product: CrowdStrike
    alert_type: EDR
    severity_max_level: 2
    exploitability_levels_in: ["Critical"]
    validity_tp_min: 0.50
  do:
    decision: UPLOAD_XSOAR
    auto_action: escalate
    phases:
      containment:
        - Immediate host isolation (if not business-critical)
        - Block IOC in EDR and firewall
```

---

## 5) Test: quick smoke-tests (no LLM run)

Open a Python REPL from repo root (after installing deps or at least making the code importable):

```python
from config import load_policy
from domains import Alert, Indicator, ValidityScore, SeverityScore, ExploitabilityScore
from agents import _infer_alert_meta, _select_matching_rules

policy = load_policy()

def match(alert, v, s, e):
    print("META:", _infer_alert_meta(alert))
    print("MATCHED:", [m["id"] for m in _select_matching_rules(policy, alert, v, s, e)])

# 1) auto-close benign low-sev EDR
a1 = Alert(id="A1", title="EDR benign telemetry", description="CrowdStrike EDR benign", indicators=[Indicator(type="host", value="srv-1")])
v1 = ValidityScore(label="False Positive", likelihood=0.20, rationale="low")
s1 = SeverityScore(level=1, impact="Low", rationale="low")
e1 = ExploitabilityScore(level="Low", likelihood=0.2, rationale="low")
match(a1, v1, s1, e1)   # -> ["EDR_LOW_SEV_AUTO_CLOSE_SAFE"]

# 2) escalate critical exploitability
a2 = Alert(id="A2", title="EDR critical signal", description="CrowdStrike EDR shows critical exploit", indicators=[])
v2 = ValidityScore(label="True Positive", likelihood=0.55, rationale="ok")
s2 = SeverityScore(level=2, impact="Medium", rationale="med")
e2 = ExploitabilityScore(level="Critical", likelihood=0.9, rationale="high")
match(a2, v2, s2, e2)   # -> ["EDR_LOW_SEV_CRITICAL_EXPLOIT_ESCALATE"]
```

If you see the correct rule IDs in `MATCHED`, your config is wired correctly.

---

## 6) Test: full pipeline (LLM + graph)

1. Install requirements:

```bash
pip install -r requirements.txt
```

2. (Optional) point explicitly to your policy:

```bash
export A2A_POLICY="$(pwd)/config.yaml"
```

3. Run a CLI demo:

```bash
python -m src.run_demo
```

4. Or launch the UI:

```bash
streamlit run src/streamlit_app.py
```

**Observability**

* The graph logs to `a2a_observability.log` (or `A2A_OBS_LOG` env var).
* The `playbooks_node` adds metadata in logs:

  * `policy_version` and `rules_count`
  * Event name: `selected_playbooks` with the chosen list.

---

## 7) Operational guidance

* **Enable/disable quickly**: flip `enabled: true/false` per rule.
* **Control precedence**: lower `priority` = earlier evaluation.
* **Many matches**: set `collect_all_matches: true` to pass multiple rule hints to the LLM.
* **LLM vs. Determinism**: rules **bias** the LLM’s playbook selection. If you want hard enforcement (e.g., always isolate host on match), add a deterministic “execute-actions” node and map `do.auto_action` to real functions (e.g., in `tools.py`).

---

## 8) Troubleshooting

* **No rule fires**

  * Check `title/description` contains tokens for meta inference (“crowdstrike”, “edr”, “brute”, “password spray”).
  * Verify numeric bounds (`validity_tp_min/max`, `severity_max_level`) and enums (“Critical”, “Medium”).
* **LLM ignores hint**

  * Increase specificity or lower the `priority` of the desired rule; consider deterministic enforcement for safety-critical paths.
* **ImportError: langgraph**

  * Install deps: `pip install -r requirements.txt`.
* **Policy not picked up**

  * Ensure you’re editing the repo-root `config.yaml` **or** set `A2A_POLICY` to your custom path.
* **YAML mistakes**

  * If you adopted the optional `config.py` hardening, you’ll get clear validation errors (unknown keys, wrong types, etc.). Fix and retry.

---

## 9) Future extensions

* Add richer meta extraction (map product/alert\_type from structured alert fields instead of heuristics).
* Add `conditions` for counts/time-windows (e.g., “≥3 similar alerts in 1h”).
* Wire an “execute actions” node that reads `do.auto_action` and calls real APIs (EDR isolate, IdP MFA enforce, block IOC).

---

**That’s it!** With `playbook_rules` you can iterate quickly on SOC automation behavior by editing **only** `config.yaml`, and you now have a thin runtime layer that converts those rules into clear hints the LLM will follow.
