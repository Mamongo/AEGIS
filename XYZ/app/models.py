from enum import Enum
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    REDACT = "REDACT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


PRECEDENCE = {d: i for i, d in enumerate(Decision)}


class Finding(StrictModel):
    control: str
    decision: Decision = Decision.ALLOW
    severity: str = "info"
    score: float = Field(default=0, ge=0, le=1)
    reason: str
    rule_id: str


def finding(control, rule, reason, decision="BLOCK", severity="high", score=1):
    return Finding(control=control, rule_id=rule, reason=reason,
                   decision=decision, severity=severity, score=score)


def overall(findings):
    return max((f.decision for f in findings), key=PRECEDENCE.get, default=Decision.ALLOW)


class User(StrictModel):
    id: str = Field(default="anonymous", min_length=1, max_length=100)
    role: str = Field(default="employee", max_length=40)
    tenant: str = Field(default="unassigned", min_length=1, max_length=100)


class Agent(StrictModel):
    id: str = "support-agent"
    version: str = "1.0"


class Input(StrictModel):
    text: str = Field(default="", max_length=32000)


class ToolProposal(StrictModel):
    name: str = Field(max_length=100)
    arguments: dict = Field(default_factory=dict)


class Resource(StrictModel):
    tenant: str | None = None
    user_id: str | None = None
    operation: str = "read"


class Envelope(StrictModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str | None = None
    user: User = Field(default_factory=User)
    agent: Agent = Field(default_factory=Agent)
    model: str = "qwen3:4b"
    input: Input = Field(default_factory=Input)
    tool: ToolProposal | None = None
    resource: Resource | None = None
    destination: str | None = None


class SecurityResponse(StrictModel):
    decision: Decision
    request_id: str
    risk: str
    controls: list[Finding]
    executed: bool = False
    output: str | dict | list | None = None
    sanitized_input: str = ""
    policy_version: int
    signature_version: int
    latency_ms: float
    deterministic_latency_ms: float = 0
    semantic_latency_ms: float = 0
    tokens: int = 0
    budget_usage: dict = Field(default_factory=dict)
