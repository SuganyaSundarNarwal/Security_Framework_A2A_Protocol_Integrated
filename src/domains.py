# src/domains.py
from __future__ import annotations
from typing import List, Literal, Optional, TypedDict, Dict, Annotated
import operator
from pydantic import BaseModel, Field
from datetime import datetime

# ---------- Domain objects (strict, LLM-friendly) ----------

class Indicator(BaseModel):
    type: Literal["ip", "domain", "hash", "url", "email", "user", "process", "file", "host"]
    value: str
    context: Optional[str] = None

class Alert(BaseModel):
    id: str
    source: str = "SIEM"
    title: str
    description: str
    indicators: List[Indicator] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ValidityScore(BaseModel):
    label: Literal[
        "False Positive", "False Negative", "True Positive", "True Negative"
    ]
    likelihood: float = Field(ge=0, le=1, description="Belief alert is real (TP)")
    rationale: str

class SeverityScore(BaseModel):
    level: Literal[1, 2, 3]  # matches your slide levels
    impact: Literal["Low", "Medium", "High"]
    rationale: str

class ExploitabilityScore(BaseModel):
    level: Literal["Not Exploitable", "Low", "Medium", "Critical"]
    likelihood: float = Field(ge=0, le=1)
    rationale: str

class PlaybookChoice(BaseModel):
    names: List[str]
    rationale: str

class Decision(BaseModel):
    soc_attention: bool
    path: Literal["UPLOAD_XSOAR", "SOC_TRIAGE"]
    rationale: str

class ActionLog(BaseModel):
    at: datetime = Field(default_factory=datetime.utcnow)
    event: str
    details: Dict = Field(default_factory=dict)

# ---------- Global Graph State (typed) ----------
class SOCState(TypedDict, total=False):
    alert: Alert                       # written once (input)
    enrichment: Dict  # internal+external # written by enrich_node
    validity: ValidityScore            # written by validity_node
    severity: SeverityScore            # written by severity_node
    exploitability: ExploitabilityScore
    playbooks: PlaybookChoice
    decision: Decision
    status: str
    # IMPORTANT: allow concurrent appends from parallel nodes
    logs: Annotated[List[ActionLog], operator.add]   # <-- reducer to "add" lists