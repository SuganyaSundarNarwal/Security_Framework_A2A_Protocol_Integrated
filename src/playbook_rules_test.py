# Quick rule-matcher smoke tests (no LLM calls)
from config import load_policy
from domains import Alert, Indicator, ValidityScore, SeverityScore, ExploitabilityScore
from agents import _infer_alert_meta, _select_matching_rules

policy = load_policy()

def match(alert, v, s, e):
    meta = _infer_alert_meta(alert)
    matches = _select_matching_rules(policy, alert, v, s, e)
    print("META:", meta)
    print("MATCHED:", [m["id"] for m in matches])

# 1) EDR_LOW_SEV_AUTO_CLOSE_SAFE
alert1 = Alert(id="A1", title="EDR benign telemetry", description="CrowdStrike EDR flagged benign pattern", indicators=[Indicator(type="host", value="srv-1")])
v1 = ValidityScore(label="False Positive", likelihood=0.20, rationale="low evidence")
s1 = SeverityScore(level=1, impact="Low", rationale="low impact")
e1 = ExploitabilityScore(level="Low", likelihood=0.2, rationale="not exploitable")
match(alert1, v1, s1, e1)

# 2) EDR_LOW_SEV_INVESTIGATE_MEDIUM_EXPLOIT
alert2 = Alert(id="A2", title="EDR suspicious process", description="CrowdStrike EDR Medium exploitability", indicators=[])
v2 = ValidityScore(label="True Positive", likelihood=0.70, rationale="multiple signals")
s2 = SeverityScore(level=2, impact="Medium", rationale="moderate impact")
e2 = ExploitabilityScore(level="Medium", likelihood=0.6, rationale="medium exploitability")
match(alert2, v2, s2, e2)

# 3) AUTH_BRUTEFORCE_LOW_SEV_GUARDED
alert3 = Alert(id="A3", title="Brute force attempt", description="password spray from unusual ASN", indicators=[])
v3 = ValidityScore(label="True Positive", likelihood=0.70, rationale="clear pattern")
s3 = SeverityScore(level=2, impact="Medium", rationale="auth risk")
e3 = ExploitabilityScore(level="Low", likelihood=0.3, rationale="auth context")
match(alert3, v3, s3, e3)

# 4) EDR_LOW_SEV_CRITICAL_EXPLOIT_ESCALATE
alert4 = Alert(id="A4", title="EDR critical signal", description="CrowdStrike EDR shows critical exploit", indicators=[])
v4 = ValidityScore(label="True Positive", likelihood=0.55, rationale="credible signal")
s4 = SeverityScore(level=2, impact="Medium", rationale="moderate impact")
e4 = ExploitabilityScore(level="Critical", likelihood=0.9, rationale="high risk")
match(alert4, v4, s4, e4)
