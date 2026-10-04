import pytest

from app.auth import Authentication
from app.config import Settings


def test_gateway_rejects_missing_and_invalid_credentials(client):
    client.headers.pop("Authorization")
    for headers in ({}, {"Authorization": "Bearer invalid"}, {"Authorization": "Basic anything"}):
        for path in ("/api/evaluate", "/api/chat", "/api/tool/execute", "/api/memory"):
            assert client.post(path, json={}, headers=headers).status_code == 401
        for path in ("/api/me", "/api/tools", "/api/status"):
            assert client.get(path, headers=headers).status_code == 401
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200


def test_claimed_admin_identity_does_not_change_authenticated_role(client):
    result = client.post("/api/tool/execute", json={
        "user": {"id": "forged-admin", "role": "admin", "tenant": "other-company"},
        "tool": {"name": "internal.ticket.update", "arguments": {"ticket_id": "1827", "status": "closed"}},
    }).json()
    assert result["decision"] == "BLOCK" and not result["executed"]
    assert "SEC-AUTHZ-003" in {finding["rule_id"] for finding in result["controls"]}
    with client.app.state.gateway.audit.db.connect() as conn:
        ticket = conn.execute("SELECT status FROM tickets WHERE id=1827").fetchone()
        event = conn.execute("SELECT user_id,tenant FROM events WHERE request_id=?", (result["request_id"],)).fetchone()
    assert ticket["status"] == "open"
    assert tuple(event) == ("alice", "demo-company")


def test_claimed_tenant_cannot_access_another_tenants_records(client):
    result = client.post("/api/tool/execute", headers={"Authorization": "Bearer other-tenant-key"}, json={
        "user": {"id": "alice", "role": "admin", "tenant": "demo-company"},
        "tool": {"name": "internal.ticket.read", "arguments": {"ticket_id": "1827"}},
    }).json()
    assert result["decision"] == "BLOCK" and not result["executed"]
    assert result["output"] is None


def test_memory_identity_is_server_derived(client):
    written = client.post("/api/memory", json={
        "user": {"id": "bob", "role": "admin", "tenant": "other-company"},
        "content": "Actual customer preference", "provenance": "customer-message",
    }).json()
    with client.app.state.gateway.audit.db.connect() as conn:
        row = conn.execute("SELECT user_id,tenant FROM memory WHERE id=?", (written["id"],)).fetchone()
    assert tuple(row) == ("alice", "demo-company")


def test_key_agent_grant_cannot_be_spoofed(client):
    response = client.post("/api/evaluate", json={"agent": {"id": "other-agent"}})
    assert response.status_code == 403


def test_principal_and_live_status(client):
    assert client.get("/api/me").json() == {
        "user": {"id": "alice", "role": "employee", "tenant": "demo-company"}, "agents": ["support-agent"],
    }
    status = client.get("/api/status").json()
    assert status["simulated_tools"] is False and status["identity_mode"] == "api-key"


def test_missing_operator_token_never_opens_management(client):
    client.app.state.settings.admin_token = ""
    for path in ("/api/events", "/api/metrics", "/api/policy", "/api/budgets", "/api/signatures"):
        assert client.get(path).status_code == 401
    for path in ("/api/policy/reload", "/api/signatures/reload", "/api/budgets/reset"):
        assert client.post(path).status_code == 401


@pytest.mark.parametrize("claims", [{"id": "x", "role": "superuser", "tenant": "t"}, {}, {"id": "x", "role": "admin", "tenant": "t", "extra": "sensitive"}])
def test_invalid_key_configuration_does_not_echo_secrets(claims):
    with pytest.raises(ValueError) as error:
        Authentication(Settings(api_keys={"private-credential": claims}))
    assert "private-credential" not in str(error.value)
    assert "sensitive" not in str(error.value)


def test_invalid_environment_key_configuration_is_sanitized(monkeypatch):
    monkeypatch.setenv("API_KEYS_JSON", "private-invalid-json")
    with pytest.raises(ValueError) as error:
        Settings.from_env()
    assert "private-invalid-json" not in str(error.value)


def test_omitted_model_uses_server_configuration(client, monkeypatch):
    client.app.state.settings.ollama_model = "llama3.2:3b"
    requests = []
    async def chat(messages, model, *args):
        requests.append(model)
        return {"message": {"role": "assistant", "content": "The configured model answered."}}
    monkeypatch.setattr(client.app.state.gateway.provider, "chat", chat)
    result = client.post("/api/chat", json={"input": {"text": "Hello"}}).json()
    assert result["decision"] == "ALLOW"
    assert requests == ["llama3.2:3b"]
    with client.app.state.gateway.audit.db.connect() as conn:
        row = conn.execute("SELECT model FROM events WHERE request_id=?", (result["request_id"],)).fetchone()
    assert row["model"] == "llama3.2:3b"
    explicit = client.post("/api/chat", json={"model": "qwen3:4b", "input": {"text": "Hello"}}).json()
    assert explicit["decision"] == "ALLOW" and requests[-1] == "qwen3:4b"


def test_configured_default_model_still_requires_policy_grant(client, monkeypatch):
    client.app.state.settings.ollama_model = "ungranted-model"
    calls = []
    async def chat(*args):
        calls.append(1)
        raise AssertionError("Model must be denied before calling provider")
    monkeypatch.setattr(client.app.state.gateway.provider, "chat", chat)
    result = client.post("/api/chat", json={"input": {"text": "Hello"}}).json()
    assert result["decision"] == "BLOCK" and calls == []
    assert "MODEL_NOT_ALLOWED" in {finding["rule_id"] for finding in result["controls"]}
