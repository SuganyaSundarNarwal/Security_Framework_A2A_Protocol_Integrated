# A2A Security Framework — Technical Feature Release
**Date:** September 05, 2025

## Summary
The A2A Security Framework is an LLM‑assisted SOC orchestration accelerator that turns **Agents → Automation** safely. It combines **typed domain models (Pydantic)**, a **LangGraph** orchestration pipeline, **deterministic policy gating** from `config.yaml`, and a lightweight **Streamlit UI** with streaming and checkpointing. This release packages the scaffold, demo, and integration stubs so teams can plug in their SIEM/EDR/CMDB and XSOAR (or any SOAR) quickly.

## Highlights
- **End‑to‑end graph** with nodes for `enrich → validity → severity → exploitability → playbooks → decision → (upload_xsoar | soc_triage) → update_status` defined in `src/graph.py`.
- **LLM agents** in `src/agents.py`: `validity_agent`, `severity_agent`, `exploitability_agent`, `playbook_agent`, `decision_agent`, all returning **typed** results.
- **Typed contracts** in `src/domains.py`: `Alert`, `Indicator`, scores, `Decision`, and `SOCState`.
- **Policy & governance** via `config.yaml` and `src/config.py`: thresholds for validity/severity/exploitability and future playbook rules.
- **Observability & audit** through JSONL events to `a2a_observability.log` and in‑UI timeline.
- **Pluggable integrations** in `src/tools.py`: internal/external search, `XSOARClient`, and `notify_soc` stubs.
- **Streamlit UI** (`src/streamlit_app.py`) with Graphviz topology, native streaming, sequential stepping, checkpoint reuse, and JSON/Form inputs.
- **CLI demo** (`src/run_demo.py`) to run the pipeline once against a sample `Alert`.
- **Checkpointing** (SQLite or in‑memory) for resumability and experiment tracking.

## Components
### Orchestration (src/graph.py)
- Node implementations for enrichment, scoring, playbook choice, decision, automation hand‑off, and status updates.
- **Parallelizable** segments (via LangGraph streaming) with a reducer for `logs` that preserves exact sequence of events.

### Agents (src/agents.py)
- Shared `get_llm()` client and prompts with structured output guarantees.
- Deterministic **gating** in `decision_agent()` based on `config.yaml` thresholds; LLM supplies rationale only.

### Domain Models (src/domains.py)
- Schemas for alerts, indicators, scores, decisions, action logs, and the shared `SOCState`.

### Policy (src/config.py & config.yaml)
- `load_policy()` merges repo defaults with local overrides so security teams can enforce minimum gates without editing code.

### Integrations (src/tools.py)
- Replace stubs with calls to your SIEM/EDR/CMDB/OSINT/SOAR. Pattern shows auth, payloads, and return contracts.

### UI (src/streamlit_app.py)
- Graph view, metrics panels, enrichment details, timeline, and downloadable final state JSON. Supports **Thread ID** to revisit previous runs.

### Demo (src/run_demo.py)
- Minimal sample run that prints decision, status, playbooks, and action timeline.

## Compatibility & Requirements
- **Python** 3.11+ (tested on 3.12)
- **Graphviz** for topology rendering in Streamlit
- **LLM provider key** via `.env` (OpenAI by default)

## Installation & Setup
```bash
git clone <repo>
cd security_framework_a2a
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # or create .env with OPENAI_API_KEY
streamlit run src/streamlit_app.py
```

## Security & Privacy
- Keys in `.env`; no secrets in source.
- Data contracts make PII handling explicit; redact or hash upstream if needed.
- Deterministic gating ensures **no automation** occurs unless policy thresholds are met.

## Known Issues
- Stubs are placeholders; production deployments must add retries, timeouts, and error handling.
- Graphviz must be installed locally for UI topology rendering.

## Deprecations / Breaking Changes
- None in this initial accelerator release.

## Roadmap (Selected)
- Playbook rules DSL in `config.yaml`
- Richer SOAR adapters (XSOAR, Torq, Tines, Chronicle SOAR)
- Batch evaluation harness and unit tests
- RBAC and multi‑tenant policy overlays
- Built‑in redaction filters for LLM prompts

---

**Repository Map**
```
src/
  agents.py        # LLM agents and decision gate
  config.py        # policy loader
  domains.py       # typed models & SOCState
  graph.py         # LangGraph nodes & wiring
  run_demo.py      # CLI demo
  streamlit_app.py # Streamlit UI
  tools.py         # integration stubs
```
