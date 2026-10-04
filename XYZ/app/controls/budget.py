import json
import time
import uuid
from app.models import finding
from app.controls.loop_guard import fingerprint


class BudgetEngine:
    """Transactions serialize quota reservation across workers; caller IDs are never trusted as run IDs."""
    def __init__(self, db):
        self.db = db

    def start(self, ctx, policy):
        run_id = str(uuid.uuid4())
        now = time.time()
        try:
            with self.db.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                user = conn.execute("SELECT COALESCE(SUM(requests),0), COALESCE(SUM(tokens),0) FROM usage WHERE tenant=? AND user_id=? AND started>?",
                                    (ctx.user.tenant, ctx.user.id, now - 3600)).fetchone()
                total = conn.execute("SELECT COALESCE(SUM(requests),0) FROM usage WHERE started>?", (now - 3600,)).fetchone()[0]
                if user[0] >= policy.budgets.per_user.max_requests_per_hour or total >= policy.budgets.global_.max_requests_per_hour or user[1] >= policy.budgets.per_user.max_tokens_per_hour:
                    return run_id, [finding("budget", "BUDGET_EXCEEDED", "Hourly user or global quota exhausted")]
                conn.execute("INSERT INTO usage(id,user_id,tenant,agent_id,started) VALUES(?,?,?,?,?)",
                             (run_id, ctx.user.id, ctx.user.tenant, ctx.agent.id, now))
            return run_id, []
        except Exception:
            return run_id, [finding("budget", "BUDGET_STORAGE_FAILURE", "Usage reservation failed; execution denied", severity="critical")]

    def reserve(self, run_id, ctx, policy, tokens=0, tool=None, step=1, model_call=False):
        try:
            with self.db.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM usage WHERE id=?", (run_id,)).fetchone()
                if row is None or (row["tenant"], row["user_id"], row["agent_id"]) != (ctx.user.tenant, ctx.user.id, ctx.agent.id):
                    return [finding("budget", "BUDGET_STORAGE_FAILURE", "Missing or mismatched trusted run")], {}
                usage = dict(row)
                limit = policy.budgets.per_request
                if time.time() - row["started"] > limit.max_duration_seconds:
                    return [finding("budget", "BUDGET_EXCEEDED", "Request duration limit exceeded")], usage
                actions = json.loads(row["actions"])
                if tool:
                    key = fingerprint(tool)
                    actions[key] = actions.get(key, 0) + 1
                    if actions[key] >= limit.repeat_limit:
                        return [finding("loop_guard", "LOOP_DETECTED", "Possible runaway agent loop detected.")], usage
                user_tokens = conn.execute("SELECT COALESCE(SUM(tokens),0) FROM usage WHERE tenant=? AND user_id=? AND started>?",
                                           (ctx.user.tenant, ctx.user.id, time.time() - 3600)).fetchone()[0]
                new_tokens, new_steps, new_calls = row["tokens"] + tokens, row["steps"] + step, row["tool_calls"] + bool(tool)
                if new_tokens > limit.max_tokens or new_steps > limit.max_steps or new_calls > limit.max_tool_calls or user_tokens + tokens > policy.budgets.per_user.max_tokens_per_hour:
                    return [finding("budget", "BUDGET_EXCEEDED", "Token, step, or tool-call quota exhausted")], usage
                units = row["compute_units"] + (policy.budgets.compute_units_per_model_call if model_call else 0)
                conn.execute("UPDATE usage SET tokens=?,steps=?,tool_calls=?,actions=?,compute_units=? WHERE id=?",
                             (new_tokens, new_steps, new_calls, json.dumps(actions), units, run_id))
                usage.update(tokens=new_tokens, steps=new_steps, tool_calls=new_calls, compute_units=units)
                usage.pop("actions", None)
                return [], usage
        except Exception:
            return [finding("budget", "BUDGET_STORAGE_FAILURE", "Budget storage unavailable; execution denied", severity="critical")], {}

    def snapshot(self):
        with self.db.connect() as conn:
            users = conn.execute("SELECT tenant,user_id,SUM(requests) requests,SUM(tokens) tokens,SUM(tool_calls) tool_calls,SUM(compute_units) compute_units FROM usage WHERE started>? GROUP BY tenant,user_id", (time.time() - 3600,)).fetchall()
        return {"window": "rolling_1_hour", "users": [dict(row) for row in users], "requests": sum(row["requests"] for row in users)}

    def reset(self):
        with self.db.connect() as conn:
            conn.execute("DELETE FROM usage")
