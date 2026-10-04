from typing import Literal
from pydantic import Field, field_validator, model_validator
from app.models import StrictModel


class TicketRead(StrictModel):
    ticket_id: str = Field(pattern=r"^\d{1,8}$")
    tenant: str | None = None


TicketStatus = Literal["open", "in_progress", "closed"]


class TicketCreate(StrictModel):
    summary: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=10000)
    tenant: str | None = None


class TicketUpdate(TicketRead):
    status: TicketStatus | None = None
    summary: str | None = Field(default=None, min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=10000)

    @model_validator(mode="after")
    def has_changes(self):
        if all(getattr(self, field) is None for field in ("status", "summary", "description")):
            raise ValueError("At least one ticket field must be supplied")
        return self


class TenantArgs(StrictModel):
    tenant: str | None = None


class TicketList(TenantArgs):
    status: TicketStatus | None = None
    limit: int = Field(default=50, ge=1, le=100)


class EmployeeCreate(TenantArgs):
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=320,
                       pattern=r"^(?:[^@\s]+@[^@\s]+\.[^@\s]+|\[REDACTED_EMAIL\])$")


class EmployeeList(TenantArgs):
    limit: int = Field(default=100, ge=1, le=100)


class HttpGet(StrictModel):
    url: str = Field(min_length=8, max_length=2048)


class HttpPost(HttpGet):
    data: dict | str = Field(default_factory=dict)


class WebSearch(StrictModel):
    query: str = Field(min_length=1, max_length=300)

    @field_validator("query", mode="before")
    @classmethod
    def strip_query(cls, value):
        return value.strip() if isinstance(value, str) else value


class Calculator(StrictModel):
    a: float = Field(allow_inf_nan=False, ge=-1e12, le=1e12)
    b: float = Field(allow_inf_nan=False, ge=-1e12, le=1e12)
    operation: Literal["add", "subtract", "multiply", "divide"] = "add"


SCHEMAS = {"internal.ticket.create": TicketCreate, "internal.ticket.read": TicketRead,
           "internal.ticket.update": TicketUpdate, "internal.ticket.list": TicketList,
           "internal.employee.create": EmployeeCreate, "internal.employee.list": EmployeeList,
           "http.get": HttpGet, "http.post": HttpPost, "web.search": WebSearch, "calculator": Calculator}


def schemas():
    return {name: model.model_json_schema() for name, model in SCHEMAS.items()}
