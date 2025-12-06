from typing_extensions import override

import json
import os
import sys

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentSkill

# Ensure local project imports work when run as a script
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)

from domains import Alert, SeverityScore
from agents import severity_agent


class SeverityAgentExecutor(AgentExecutor):
    """
    A2A AgentExecutor wrapper around your existing severity_agent(alert, enrichment)
    """

    @override
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        raw_input = context.get_user_input()

        try:
            payload = json.loads(raw_input)
        except json.JSONDecodeError as e:
            await event_queue.enqueue_event(
                new_agent_text_message(
                    f"Invalid JSON payload for severity agent: {e}",
                    context_id=context.context_id,
                )
            )
            await event_queue.close()
            return

        alert_data = payload.get("alert")
        enrichment = payload.get("enrichment", {}) or {}

        if not isinstance(alert_data, dict):
            await event_queue.enqueue_event(
                new_agent_text_message(
                    "Severity agent expected 'alert' as object in payload.",
                    context_id=context.context_id,
                )
            )
            await event_queue.close()
            return

        alert = Alert.model_validate(alert_data)

        score: SeverityScore = severity_agent(alert, enrichment)

        await event_queue.enqueue_event(
            new_agent_text_message(
                json.dumps(score.model_dump(mode="json")),
                context_id=context.context_id,
            )
        )
        await event_queue.close()

    @override
    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        await event_queue.close()


def build_severity_agent_card() -> AgentCard:
    skill = AgentSkill(
        id="severity_scoring",
        name="Alert severity scoring",
        description=(
            "Scores SOC alerts for organizational impact (level/impact/rationale)."
        ),
        tags=["soc", "security", "severity"],
        examples=['{"alert": {"id": "ALRT-1001", "...": "..."}, "enrichment": {...}}'],
    )

    return AgentCard(
        name="SOC Severity Agent",
        description="Evaluates organizational impact (severity) of SOC alerts.",
        url=os.getenv("A2A_SEVERITY_URL", "http://localhost:9102/"),
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],
    )


if __name__ == "__main__":
    severity_agent_card = build_severity_agent_card()

    severity_request_handler = DefaultRequestHandler(
        agent_executor=SeverityAgentExecutor(),
        task_store=InMemoryTaskStore(),
    )

    severity_server = A2AStarletteApplication(
        agent_card=severity_agent_card,
        http_handler=severity_request_handler,
    )

    import uvicorn

    uvicorn.run(
        severity_server.build(),
        host="0.0.0.0",
        port=9102,
        log_level="info",
    )
