"""Authenticate configured API keys and derive identity exclusively on the server."""
import secrets
from typing import Literal

from fastapi import Header, HTTPException
from pydantic import Field, ValidationError

from app.models import StrictModel, User


class Principal(StrictModel):
    id: str = Field(min_length=1, max_length=100)
    role: Literal["employee", "admin"]
    tenant: str = Field(min_length=1, max_length=100)
    agents: list[str] = Field(default_factory=lambda: ["support-agent"], min_length=1)

    def user(self):
        return User(id=self.id, role=self.role, tenant=self.tenant)


class Authentication:
    def __init__(self, settings):
        try:
            self.keys = {
                key: Principal.model_validate(value)
                for key, value in settings.api_keys.items()
                if isinstance(key, str) and key
            }
            if len(self.keys) != len(settings.api_keys):
                raise ValueError
        except (ValidationError, ValueError, TypeError, AttributeError):
            # Never include configured credentials or claims in an error.
            raise ValueError("Invalid API key identity configuration") from None

    def authenticate(self, authorization: str | None = Header(default=None)):
        scheme, _, credential = (authorization or "").partition(" ")
        if scheme.lower() == "bearer" and credential:
            for key, principal in self.keys.items():
                if secrets.compare_digest(credential.encode(), key.encode()):
                    return principal
        raise HTTPException(401, "Valid Bearer API key required", headers={"WWW-Authenticate": "Bearer"})

    @staticmethod
    def bind(request, principal):
        if request.agent.id not in principal.agents:
            raise HTTPException(403, "API key does not grant this agent")
        return request.model_copy(update={"user": principal.user()})
