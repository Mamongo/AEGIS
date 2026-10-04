import json
import time
import uuid
from app.models import StrictModel, User, Agent, finding, overall
from pydantic import Field
from app.controls import secrets, injection, signatures
from app.audit.logger import sanitize


class MemoryWrite(StrictModel):
    user: User = Field(default_factory=User)
    agent: Agent = Field(default_factory=Agent)
    content: str = Field(min_length=1, max_length=16000)
    provenance: str = Field(min_length=1, max_length=200)
    sensitivity: str = "private"


class MemoryGuard:
    def __init__(self, db):
        self.db = db

    def write(self, request, policy, feed):
        checks, _ = secrets.inspect(request.content)
        checks += injection.inspect(request.content, policy.controls.prompt_injection)[0]
        checks += signatures.inspect(request.content, feed)
        if request.agent.id != "support-agent" or request.user.role not in {"employee", "admin"}:
            checks.append(finding("memory", "MEMORY_IDENTITY_DENIED", "Untrusted memory writer"))
        quarantined = overall(checks).value in {"BLOCK", "REQUIRE_APPROVAL", "WARN"}
        record_id = str(uuid.uuid4())
        # External writes can never mark themselves trusted, even if no pattern matched.
        with self.db.connect() as conn:
            conn.execute("INSERT INTO memory VALUES(?,?,?,?,?,?,?,?,?,?)", (
                record_id, request.user.tenant, request.user.id, request.agent.id,
                sanitize(request.content), sanitize(request.provenance), time.time(),
                request.sensitivity, 0, int(quarantined)))
        return {"id": record_id, "decision": "BLOCK" if quarantined else "ALLOW", "quarantined": quarantined,
                "trusted": False, "provenance": sanitize(request.provenance), "controls": [c.model_dump(mode="json") for c in checks]}

    def read(self, record_id, user, agent):
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM memory WHERE id=? AND tenant=? AND user_id=? AND agent_id=? AND quarantined=0",
                               (record_id, user.tenant, user.id, agent.id)).fetchone()
        return dict(row) if row else None
