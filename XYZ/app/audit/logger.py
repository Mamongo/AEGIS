import json
import time
from app.controls import secrets, pii


def sanitize(value):
    if isinstance(value, str):
        return pii.redact(secrets.redact(value))
    if isinstance(value, dict):
        return {str(k): "[REDACTED_SECRET]" if str(k).lower() in {
            "password", "passwd", "pwd", "token", "api_key", "secret", "authorization", "credentials"
        } else sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    return value


class AuditLogger:
    def __init__(self, db):
        self.db = db

    def record(self, ctx, result, policy_version, latency=0, tokens=0, usage=None, details=None):
        values = (time.time(), ctx.request_id if ctx else None, ctx.session_id if ctx else None,
                  ctx.user.id if ctx else None, ctx.user.tenant if ctx else None,
                  ctx.agent.id if ctx else None, ctx.model if ctx else None,
                  result.control, result.rule_id, result.decision.value, result.severity,
                  result.reason, ctx.tool.name if ctx and ctx.tool else None, policy_version,
                  latency, tokens, json.dumps(sanitize(usage or {})), json.dumps(sanitize(details or {})))
        values = tuple(sanitize(v) for v in values)
        with self.db.connect() as conn:
            conn.execute('''INSERT INTO events (timestamp,request_id,session_id,user_id,tenant,agent_id,model,
                control,rule_id,decision,severity,reason,tool,policy_version,latency_ms,tokens,budget_usage,details)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', values)

    def recent(self, limit=100, **filters):
        allowed = {"decision", "severity", "control", "user_id"}
        parts, params = [], []
        for key, value in filters.items():
            if key in allowed and value:
                parts.append(key + " = ?")
                params.append(value)
        query = "SELECT * FROM events" + (" WHERE " + " AND ".join(parts) if parts else "")
        with self.db.connect() as conn:
            rows = conn.execute(query + " ORDER BY id DESC LIMIT ?", params + [limit]).fetchall()
        return [dict(row) for row in rows]
