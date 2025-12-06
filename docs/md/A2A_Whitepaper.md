# A2A Security Framework — Whitepaper
**Date:** September 05, 2025

## Executive Summary
Security Operations Centers (SOCs) struggle with alert volume, context gaps, and inconsistent triage. The A2A Security Framework (Agents→Automation) is an open accelerator that combines **typed LLM agents** with a **deterministic policy gate** and **graph‑based orchestration**. It produces explainable decisions, auditable timelines, and a clean path from AI‑assisted scoring to **safe automation** (SOAR) or **human triage**.

## Problem
Traditional pipelines either automate too aggressively (risking false positives) or under‑automate (increasing toil). Pure LLM triage lacks controls, while rule‑only systems lack generalization. A2A bridges the gap: agents enrich and score, **policy** decides.

## Design Principles
1. **Contracts First** — Pydantic models define every input/output (`Alert`, scores, `Decision`, `SOCState`).2. **Deterministic Gates** — Policy thresholds in `config.yaml` control automation, never the LLM.3. **Composable Graphs** — LangGraph nodes encapsulate enrichment, scoring, and actions.4. **Observability** — JSONL logs + UI timeline for transparency and reproducibility.5. **Pluggable** — Integrations are stubs you can swap for SIEM/EDR/CMDB/SOAR/OSINT.6. **Human‑in‑the‑Loop** — Branch to **SOC triage** when gates aren’t met or context is ambiguous.

## Architecture Overview
**Flow:** `enrich → validity → severity → exploitability → playbooks → decision → (upload_xsoar | soc_triage) → update_status`

- **Enrichment:** Queries internal (SIEM/EDR/CMDB) and external OSINT for indicators.- **Scoring Agents:** LLMs estimate validity, business impact, and exploitability with structured output.- **Playbook Selection:** Proposes playbooks that match context and risk.- **Policy Gate:** `decision_agent()` applies thresholds from `load_policy()` to compute `Decision.path`.- **Automation Hand‑off:** If gated, raise an incident in SOAR; else notify human queue.- **Audit & Timeline:** Every node appends `ActionLog` items with time, event, and details.

## Data Contracts
- `Alert(id, title, description, indicators, created_at)`- `Indicator(type, value, context?)`- `ValidityScore(label, likelihood, rationale)`- `SeverityScore(level, impact, rationale)`- `ExploitabilityScore(level, likelihood, rationale)`- `PlaybookChoice(names, rationale)`- `Decision(soc_attention, path, rationale)`- `ActionLog(at, event, details)`- `SOCState` holds all of the above; reducers append `logs` safely in parallel runs.

## Orchestration with LangGraph
Each node in `src/graph.py` returns a **state delta**. A reducer merges deltas, enabling **parallelism** where feasible (e.g., enrichment sub‑queries) and **streaming** updates to the UI. `build_graph()` registers nodes, wires edges, and compiles an app compatible with memory or SQLite checkpointing.

### Deterministic Decisioning
The final `decision_node` does **not** let the LLM decide whether to automate. Instead:
- Thresholds (e.g., `validity_tp_min`, `severity_min`, `exploit_levels_escalate`) are loaded from `config.yaml`.- If the alert scores pass policy gates, `Decision.path = UPLOAD_XSOAR`; otherwise `SOC_TRIAGE`.- The LLM provides a natural‑language **rationale** only.

## Integrations
`src/tools.py` contains stubs that demonstrate the integration patterns:
- **Internal Search** — your SIEM/EDR/CMDB/ticketing.- **External OSINT** — VirusTotal, GreyNoise, AbuseIPDB, etc.- **SOAR** — `XSOARClient.upload_incident()` and `update_status()`.- **Notifications** — `notify_soc()` for human hand‑off.

Swap these with real clients and add standard production concerns (retries, timeouts, auth rotation, rate limiting).

## Observability & Governance
- **JSONL Audit** — All runs append to `a2a_observability.log`.- **Timeline** — Streamlit UI renders logs chronologically.- **Reproducibility** — Checkpointing (SQLite/Memory) enables replays and drift analysis.- **Change Management** — Policies live in `config.yaml`; PRs can gate changes via code review.

## Security Considerations
- **Secrets** in `.env`; never hard‑code keys.- **PII** — Redact upstream or add filters before prompts.- **Vendor Lock‑in** — LLM is abstracted in `get_llm()`; swap providers easily.- **Fail‑Safe Defaults** — If policy cannot be loaded, default to **no automation** and require approval.

## Performance & Scaling
- **Parallel enrichment** and streaming reduce time‑to‑context.- **Checkpoint reuse** supports iterative investigation and testing.- **Throughput** scales horizontally by running multiple worker processes behind the Streamlit/CLI edge.- **Cold‑start** mostly dependent on LLM latency and OSINT APIs; cache recommended (not included in scaffold).

## Example Walkthrough (Hypothetical)
1. **Input**: `Alert` referencing an egress IP, host, and service account.2. **Enrich**: internal EDR shows brute‑force attempts; OSINT flags the IP as abusive.3. **Score**: `Validity=0.82 (TP)`, `Severity=2/Medium`, `Exploitability=Medium 0.6`.4. **Policy Gate**: thresholds satisfied → `UPLOAD_XSOAR`.5. **Automate**: Create incident in SOAR; post link to SOC channel.6. **Update**: Status set to “Containment in progress”; timeline logs persisted.

## Implementation Roadmap
- **Crawl**: Keep stubs; tune thresholds; use UI for training SOC analysts.- **Walk**: Wire SIEM/EDR/OSINT; start with triage‑only, no automation.- **Run**: Enable specific playbooks (contain host, reset creds) behind strict policy.- **Optimize**: Add test harness, data redaction, and provider‑agnostic LLM clients.

## Limitations & Future Work
- No built‑in redaction or caching yet.- Policy covers thresholds; a richer rules engine (DSL) is on the roadmap.- Benchmarks vary by provider; load testing required before production.- UI is Streamlit; production deployments may need a hardened web front‑end.

## Conclusion
A2A offers a practical path to adopt LLMs in SOC workflows without surrendering control. By combining contracts, policy gates, a composable graph, and clear observability, it accelerates safe automation while keeping humans in the loop where it matters.
