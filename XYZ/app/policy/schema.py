from typing import Literal
from pydantic import Field, model_validator
from app.models import StrictModel

Action = Literal["allow", "block", "redact", "warn", "require_approval"]


class Defaults(StrictModel):
    action: Action = "block"


class Models(StrictModel):
    allow: list[str] = Field(min_length=1)


class PII(StrictModel):
    enabled: bool = True
    input_action: Action = "redact"
    output_action: Action = "redact"


class Secrets(StrictModel):
    enabled: bool = True
    action: Action = "block"
    output_action: Action = "redact"


class Injection(StrictModel):
    enabled: bool = True
    deterministic_threshold: float = Field(default=.75, gt=0, le=1)
    semantic_threshold: float = Field(default=.80, gt=0, le=1)
    action: Action = "block"


class Controls(StrictModel):
    pii: PII = Field(default_factory=PII)
    secrets: Secrets = Field(default_factory=Secrets)
    prompt_injection: Injection = Field(default_factory=Injection)


class ToolRule(StrictModel):
    action: Action = "allow"
    roles: list[str] = Field(default_factory=list)
    agents: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)


class Tools(StrictModel):
    default: Action = "block"
    allow: dict[str, ToolRule]


class Egress(StrictModel):
    default: Literal["block"] = "block"
    allow_domains: list[str] = Field(default_factory=list)
    allow_private_domains: list[str] = Field(default_factory=list)


class Memory(StrictModel):
    cross_user_access: Literal[False] = False
    cross_tenant_access: Literal[False] = False


class RequestBudget(StrictModel):
    max_tokens: int = Field(default=4000, gt=0)
    max_tool_calls: int = Field(default=5, gt=0)
    max_steps: int = Field(default=10, gt=0)
    max_duration_seconds: float = Field(default=60, gt=0)
    repeat_limit: int = Field(default=3, ge=2)


class UserBudget(StrictModel):
    max_requests_per_hour: int = Field(default=50, gt=0)
    max_tokens_per_hour: int = Field(default=100000, gt=0)


class GlobalBudget(StrictModel):
    max_requests_per_hour: int = Field(default=500, gt=0)


class Budgets(StrictModel):
    per_request: RequestBudget = Field(default_factory=RequestBudget)
    per_user: UserBudget = Field(default_factory=UserBudget)
    global_: GlobalBudget = Field(default_factory=GlobalBudget, alias="global")
    compute_units_per_model_call: int = Field(default=1, gt=0)


class Semantic(StrictModel):
    enabled: bool = True
    fail_mode: Literal["deterministic_only", "block"] = "deterministic_only"
    always: bool = False


class Audit(StrictModel):
    log_allowed: bool = True
    log_blocked: Literal[True] = True


class Policy(StrictModel):
    version: int = Field(ge=1)
    profile: str
    defaults: Defaults = Field(default_factory=Defaults)
    models: Models
    controls: Controls = Field(default_factory=Controls)
    tools: Tools
    egress: Egress = Field(default_factory=Egress)
    memory: Memory = Field(default_factory=Memory)
    budgets: Budgets = Field(default_factory=Budgets)
    semantic: Semantic = Field(default_factory=Semantic)
    audit: Audit = Field(default_factory=Audit)

    @model_validator(mode="after")
    def safe_domains(self):
        for domain in self.egress.allow_domains + self.egress.allow_private_domains:
            if any(c in domain for c in "/:@* ") or not domain:
                raise ValueError("Domains must be exact hostnames or IP literals")
        return self
