import re
from typing import Literal
from pydantic import Field, field_validator
from app.models import StrictModel, finding
from app.policy.loader import ValidatedLoader


class Signature(StrictModel):
    id: str
    category: str
    pattern: str = Field(max_length=300)
    severity: Literal["low", "medium", "high", "critical"]
    action: Literal["block", "warn"]

    @field_validator("pattern")
    @classmethod
    def valid_regex(cls, value):
        re.compile(value)
        return value


class Feed(StrictModel):
    version: int = Field(ge=1)
    signatures: list[Signature] = Field(max_length=100)

    @field_validator("signatures")
    @classmethod
    def unique_ids(cls, value):
        if len({s.id for s in value}) != len(value):
            raise ValueError("Duplicate signature IDs")
        return value


class SignatureLoader(ValidatedLoader):
    def __init__(self, path, callback=None):
        super().__init__(path, Feed, callback)


def inspect(text, feed):
    return [finding("attack_signature", signature.id, "Matched historical attack category: " + signature.category,
                    signature.action.upper(), signature.severity)
            for signature in feed.signatures if re.search(signature.pattern, text, re.I)]
