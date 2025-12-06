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

from domains import Alert, ValidityScore
from agents import validity_agent


class ValidityAgentExecutor(AgentExecutor):
    """
    A2A AgentExecutor wrapper around your existing validity_agent(alert, enrichment)
    """

    @override
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        # Client sends a JSON string: {"alert": {...}, "enrichment": {...}}
        raw_input = context.get_user_input()

        try:
            payload = json.loads(raw_input)
        except json.JSONDecodeError as e:
            await event_queue.enqueue_event(
                new_agent_text_message(
                    f"Invalid JSON payload for validity agent: {e}",
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
                    "Validity agent expected 'alert' as object in payload.",
                    context_id=context.context_id,
                )
            )
            await event_queue.close()
            return

        alert = Alert.model_validate(alert_data)

        # Call your existing LLM-based validity agent
        score: ValidityScore = validity_agent(alert, enrichment)

        # Send the ValidityScore back as JSON string in a single text message
        await event_queue.enqueue_event(
            new_agent_text_message(
                json.dumps(score.model_dump(mode="json")),
                context_id=context.context_id,
            )
        )
        await event_queue.close()

    @override
    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        # No long-running tasks in this simple executor
        await event_queue.close()


def build_validity_agent_card() -> AgentCard:
    skill = AgentSkill(
        id="validity_scoring",
        name="Alert validity scoring",
        description=(
            "Scores SOC alerts as True/False Positive/Negative with likelihood and rationale."
        ),
        tags=["soc", "security", "validity"],
        examples=['{"alert": {"id": "ALRT-1001", "...": "..."}, "enrichment": {...}}'],
    )

    return AgentCard(
        name="SOC Validity Agent",
        description="Evaluates whether SOC alerts correspond to real incidents.",
        url=os.getenv("A2A_VALIDITY_URL", "http://localhost:9101/"),
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],
    )


if __name__ == "__main__":
    validity_agent_card = build_validity_agent_card()

    validity_request_handler = DefaultRequestHandler(
        agent_executor=ValidityAgentExecutor(),
        task_store=InMemoryTaskStore(),
    )

    validity_server = A2AStarletteApplication(
        agent_card=validity_agent_card,
        http_handler=validity_request_handler,
    )

    import uvicorn

    uvicorn.run(
        validity_server.build(),
        host="0.0.0.0",
        port=9101,
        log_level="info",
    )
