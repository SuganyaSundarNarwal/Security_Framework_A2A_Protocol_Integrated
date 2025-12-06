# src/run_demo.py
from __future__ import annotations
from domains import Alert, Indicator
from graph import build_graph
from dotenv import load_dotenv
load_dotenv()

if __name__ == "__main__":
    # Example alert (replace with real SIEM payload)
    alert = Alert(
        id="ALRT-1001",
        title="Outbound connection to known brute-force IP",
        description="FW logs show repeated egress to suspicious IP by host srv-42.",
        indicators=[
            Indicator(type="ip", value="203.0.113.55"),
            Indicator(type="host", value="srv-42"),
            Indicator(type="user", value="svc-backup"),
        ],
    )

    app = build_graph()
    final_state = app.invoke({"alert": alert, "logs": []})

    # Minimal console report
    print("\n=== DECISION ===")
    print(final_state["decision"])
    print("\n=== STATUS ===")
    print(final_state["status"])
    print("\n=== PLAYBOOKS ===")
    print(final_state["playbooks"])
    print("\n=== AUDIT LOGS ===")
    for l in final_state["logs"]:
        print(l.at, l.event, l.details)