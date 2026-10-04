"""Check a running authenticated gateway using real SQLite-backed operations."""
import json
import os
from pathlib import Path
import sys

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from run import load_environment


def main():
    load_environment()
    configured = json.loads(os.getenv("API_KEYS_JSON", "{}"))
    api_key = os.getenv("API_KEY") or next(iter(configured), "")
    if not api_key:
        raise SystemExit("Configure API_KEYS_JSON in .env or set API_KEY before running the smoke check.")
    with httpx.Client(base_url=os.getenv("GATEWAY_URL", "http://127.0.0.1:8000"),
                      headers={"Authorization": "Bearer " + api_key}, timeout=10, trust_env=False) as client:
        for path in ("/health", "/api/me", "/api/tools"):
            response = client.get(path)
            response.raise_for_status()
        def execute(name, arguments):
            response = client.post("/api/tool/execute", json={"tool": {"name": name, "arguments": arguments}})
            response.raise_for_status()
            result = response.json()
            if result["decision"] in {"BLOCK", "REQUIRE_APPROVAL"} or not result["executed"]:
                raise SystemExit(f"Smoke check blocked by gateway: {', '.join(c['rule_id'] for c in result['controls'])}")
            return result["output"]
        assert execute("calculator", {"a": 21, "b": 2, "operation": "multiply"})["result"] == 42
        created = execute("internal.ticket.create", {"summary": "Gateway smoke check", "description": "Created by the live smoke command."})
        retrieved = execute("internal.ticket.read", {"ticket_id": str(created["id"])})
        assert retrieved["summary"] == created["summary"]
        print(f"Live gateway checks passed. Persisted ticket {created['id']} was created and read.")


if __name__ == "__main__":
    main()
