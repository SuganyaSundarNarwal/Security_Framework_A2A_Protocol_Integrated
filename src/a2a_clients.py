# a2a_clients.py
import os
import json
from uuid import uuid4
from datetime import datetime

import requests

from domains import Alert, ValidityScore, SeverityScore, ExploitabilityScore


A2A_VALIDITY_URL = os.getenv("A2A_VALIDITY_URL", "http://localhost:9101/")
A2A_SEVERITY_URL = os.getenv("A2A_SEVERITY_URL", "http://localhost:9102/")
A2A_EXPLOITABILITY_URL = os.getenv("A2A_EXPLOITABILITY_URL", "http://localhost:9103/")


def _default_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def _post_a2a(url: str, text_payload: str) -> str:
    """Shared JSON-RPC 2.0 call helper returning the first text part."""
    request_body: dict = {
        "jsonrpc": "2.0",
        "id": uuid4().hex,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [
                    {"kind": "text", "text": text_payload},
                ],
                "messageId": uuid4().hex,
            }
        },
    }

    base_url = url.rstrip("/")
    resp = requests.post(base_url, json=request_body, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    if "error" in data and data["error"] is not None:
        raise RuntimeError(f"A2A error from server: {data['error']}")

    result = data.get("result")
    if not result:
        raise RuntimeError(f"A2A: missing 'result' in response: {data}")

    parts = result.get("parts") or []
    if not parts or "text" not in parts[0]:
        raise RuntimeError(f"A2A: unexpected 'result' format: {result}")

    return parts[0]["text"]


def call_validity_a2a(alert: Alert, enrichment: dict) -> ValidityScore:
    """
    Synchronously call the Validity A2A agent and return a ValidityScore.
    """
    text_payload = json.dumps(
        {
            "alert": alert.model_dump(mode="json"),
            "enrichment": enrichment or {},
        },
        default=_default_serializer,
    )

    text = _post_a2a(A2A_VALIDITY_URL, text_payload)

    try:
        score_dict = json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Validity A2A: could not decode score JSON: {e}; text={text!r}"
        )

    return ValidityScore(**score_dict)


def call_severity_a2a(alert: Alert, enrichment: dict) -> SeverityScore:
    """
    Synchronously call the Severity A2A agent and return a SeverityScore.
    """
    text_payload = json.dumps(
        {
            "alert": alert.model_dump(mode="json"),
            "enrichment": enrichment or {},
        },
        default=_default_serializer,
    )

    text = _post_a2a(A2A_SEVERITY_URL, text_payload)

    try:
        score_dict = json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Severity A2A: could not decode score JSON: {e}; text={text!r}"
        )

    return SeverityScore(**score_dict)


def call_exploitability_a2a(alert: Alert, enrichment: dict) -> ExploitabilityScore:
    """
    Synchronously call the Exploitability A2A agent and return an ExploitabilityScore.
    """
    text_payload = json.dumps(
        {
            "alert": alert.model_dump(mode="json"),
            "enrichment": enrichment or {},
        },
        default=_default_serializer,
    )

    text = _post_a2a(A2A_EXPLOITABILITY_URL, text_payload)

    try:
        score_dict = json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Exploitability A2A: could not decode score JSON: {e}; text={text!r}"
        )

    return ExploitabilityScore(**score_dict)
