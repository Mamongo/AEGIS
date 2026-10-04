import time


class Metrics:
    def __init__(self, db):
        self.db = db
        self.ollama_calls = 0

    def record(self, ctx, response):
        with self.db.connect() as conn:
            conn.execute("INSERT INTO interactions(timestamp,request_id,decision,latency_ms,deterministic_ms,semantic_ms,tokens,tool,executed) VALUES(?,?,?,?,?,?,?,?,?)",
                         (time.time(), ctx.request_id, response.decision.value, response.latency_ms,
                          response.deterministic_latency_ms, response.semantic_latency_ms, response.tokens,
                          bool(ctx.tool), response.executed))

    def snapshot(self, policy_version, signature_version):
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM interactions").fetchall()
            counts = conn.execute("SELECT control,decision,COUNT(*) n FROM events GROUP BY control,decision").fetchall()
            tool_blocks = conn.execute("SELECT COUNT(*) FROM interactions WHERE tool=1 AND decision IN ('BLOCK','REQUIRE_APPROVAL')").fetchone()[0]
        latencies = sorted(r["latency_ms"] for r in rows)
        def count(control, decision="BLOCK"):
            return sum(r["n"] for r in counts if r["control"] == control and r["decision"] == decision)
        return {
            "total_requests": len(rows),
            "allowed_requests": sum(r["decision"] in {"ALLOW", "WARN"} for r in rows),
            "blocked_requests": sum(r["decision"] == "BLOCK" for r in rows),
            "redacted_requests": sum(r["decision"] == "REDACT" for r in rows),
            "blocked_by_control": {r["control"]: r["n"] for r in counts if r["decision"] == "BLOCK"},
            "prompt_injections_detected": count("prompt_injection"),
            "secret_detections": sum(r["n"] for r in counts if r["control"] in {"secret_detection", "output_secrets"}),
            "secret_blocks": count("secret_detection"), "pii_redactions": count("pii", "REDACT") + count("output_pii", "REDACT"),
            "tool_calls": sum(r["tool"] for r in rows), "tool_calls_blocked": tool_blocks,
            "budget_blocks": count("budget"), "runaway_loop_blocks": count("loop_guard"),
            "average_gateway_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0,
            "p95_gateway_latency_ms": round(latencies[min(len(latencies)-1, int(len(latencies)*.95))], 3) if latencies else 0,
            "ollama_calls": self.ollama_calls, "tokens": sum(r["tokens"] for r in rows),
            "policy_version": policy_version, "signature_version": signature_version,
        }
