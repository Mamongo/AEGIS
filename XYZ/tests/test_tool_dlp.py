import json
from urllib.parse import quote

import pytest
import yaml


def edit_input_policy(client, action, *, enabled=True):
    path = client.app.state.settings.policy_path
    policy = yaml.safe_load(path.read_text())
    policy["controls"]["pii"].update(input_action=action, enabled=enabled)
    path.write_text(yaml.safe_dump(policy))
    assert client.post("/api/policy/reload").json()["error"] is None


def execute(client, name, arguments, *, admin=False):
    headers = {"Authorization": "Bearer alice-admin-key"} if admin else {}
    return client.post("/api/tool/execute", headers=headers, json={
        "tool": {"name": name, "arguments": arguments},
    }).json()


def rules(result):
    return {finding["rule_id"] for finding in result["controls"]}


def test_ticket_creation_redacts_business_fields_before_persistence(client):
    result = execute(client, "internal.ticket.create", {
        "summary": "Contact jane@example.net", "description": "Call +48 123 456 789"})
    assert result["decision"] == "REDACT" and result["executed"]
    with client.app.state.gateway.audit.db.connect() as conn:
        saved = dict(conn.execute("SELECT summary,description FROM tickets WHERE id=?", (result["output"]["id"],)).fetchone())
    assert saved == {"summary": "Contact [REDACTED_EMAIL]", "description": "Call [REDACTED_PHONE]"}
    assert "jane@example.net" not in json.dumps(result)


def test_ticket_update_redacts_business_fields_before_persistence(client):
    result = execute(client, "internal.ticket.update", {
        "ticket_id": "1827", "summary": "Contact jane@example.net", "description": "Use 192.168.1.2"}, admin=True)
    assert result["decision"] == "REDACT" and result["executed"]
    with client.app.state.gateway.audit.db.connect() as conn:
        saved = dict(conn.execute("SELECT summary,description FROM tickets WHERE id=1827").fetchone())
    assert saved == {"summary": "Contact [REDACTED_EMAIL]", "description": "Use [REDACTED_IPV4]"}


def test_employee_creation_redacts_name_and_email_before_persistence(client):
    result = execute(client, "internal.employee.create", {
        "name": "Contact jane@example.net", "email": "jane@example.net"}, admin=True)
    assert result["decision"] == "REDACT" and result["executed"]
    with client.app.state.gateway.audit.db.connect() as conn:
        saved = dict(conn.execute("SELECT name,email FROM employees WHERE id=?", (result["output"]["id"],)).fetchone())
    assert saved == {"name": "Contact [REDACTED_EMAIL]", "email": "[REDACTED_EMAIL]"}


@pytest.mark.parametrize("tool_name, arguments, table", [
    ("internal.ticket.create", {"summary": "Contact jane@example.net"}, "tickets"),
    ("internal.employee.create", {"name": "Customer", "email": "jane@example.net"}, "employees"),
])
def test_business_pii_block_prevents_database_insertion(client, tool_name, arguments, table):
    edit_input_policy(client, "block")
    with client.app.state.gateway.audit.db.connect() as conn:
        before = conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
    result = execute(client, tool_name, arguments, admin=True)
    assert result["decision"] == "BLOCK" and not result["executed"] and "SEC-PII-001" in rules(result)
    with client.app.state.gateway.audit.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] == before


def test_business_pii_block_prevents_database_update(client):
    edit_input_policy(client, "block")
    result = execute(client, "internal.ticket.update", {
        "ticket_id": "1827", "description": "Contact jane@example.net"}, admin=True)
    assert result["decision"] == "BLOCK" and not result["executed"]
    with client.app.state.gateway.audit.db.connect() as conn:
        assert conn.execute("SELECT description FROM tickets WHERE id=1827").fetchone()[0] == "Customer needs help configuring notification settings."


def test_business_pii_allow_preserves_storage_but_scrubs_output(client):
    edit_input_policy(client, "allow")
    result = execute(client, "internal.employee.create", {"name": "Customer", "email": "jane@example.net"}, admin=True)
    assert result["executed"] and result["decision"] == "REDACT"
    with client.app.state.gateway.audit.db.connect() as conn:
        assert conn.execute("SELECT email FROM employees WHERE id=?", (result["output"]["id"],)).fetchone()[0] == "jane@example.net"
    assert result["output"]["email"] == "[REDACTED_EMAIL]"
    assert "jane@example.net" not in json.dumps(client.get("/api/events").json())


def test_redaction_expansion_is_schema_validated_before_write(client):
    # All inputs are initially <=500 chars, but replacing a short email exceeds that bound.
    summary = "x " * 246 + "a@b.co"
    assert len(summary) <= 500
    result = execute(client, "internal.ticket.create", {"summary": summary})
    assert result["decision"] == "BLOCK" and not result["executed"]
    assert "INVALID_TOOL_ARGUMENTS" in rules(result)
    with client.app.state.gateway.audit.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 1


@pytest.mark.parametrize("suffix, expected_rule", [
    ("/john%40example.com", "SEC-PII-001"),
    ("/john%2540example.com", "SEC-PII-001"),
    ("/help?contact=john%40example.com", "SEC-PII-001"),
    ("/help?contact=john%2540example.com", "SEC-PII-001"),
    ("/help?phone=%2B48%20123%20456%20789", "SEC-PII-001"),
    ("/help?password%3Dhunter2", "SEC-SECRET-001"),
    ("/help?api_key%3Dabcdefgh12345678", "SEC-SECRET-001"),
    ("/help?%74%6f%6b%65%6e=opaquevalue", "SEC-SECRET-002"),
])
def test_encoded_url_sensitive_data_is_denied_before_transport(client, monkeypatch, suffix, expected_rule):
    calls = []
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", lambda *args: calls.append(args))
    result = execute(client, "http.get", {"url": "https://docs.example.internal" + suffix})
    assert result["decision"] == "BLOCK" and not result["executed"] and expected_rule in rules(result)
    assert calls == []


def test_repeated_encoding_does_not_hide_url_personal_data(client, monkeypatch):
    encoded = "john@example.com"
    for _ in range(9):
        encoded = quote(encoded, safe="")
    calls = []
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", lambda *args: calls.append(args))
    result = execute(client, "http.get", {"url": "https://docs.example.internal/help?contact=" + encoded})
    assert result["decision"] == "BLOCK" and "SEC-PII-001" in rules(result) and calls == []


@pytest.mark.parametrize("action, expected_decision, executed", [
    ("redact", "BLOCK", False), ("block", "BLOCK", False),
    ("require_approval", "REQUIRE_APPROVAL", False), ("warn", "WARN", True), ("allow", "ALLOW", True),
])
def test_sensitive_url_honors_allow_warn_and_denies_redaction(client, monkeypatch, action, expected_decision, executed):
    edit_input_policy(client, action)
    calls = []
    def request(*args):
        calls.append(args)
        return {"status_code": 200, "body": "Public documentation"}
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", request)
    url = "https://docs.example.internal/help?contact=john%40example.com"
    result = execute(client, "http.get", {"url": url})
    assert result["decision"] == expected_decision and result["executed"] is executed
    assert len(calls) == int(executed)
    if executed:
        assert calls[0][1] == url


def test_encoded_url_secret_detection_remains_active_when_secret_control_disabled(client, monkeypatch):
    path = client.app.state.settings.policy_path
    policy = yaml.safe_load(path.read_text())
    policy["controls"]["secrets"]["enabled"] = False
    policy["controls"]["secrets"]["action"] = "allow"
    path.write_text(yaml.safe_dump(policy))
    assert client.post("/api/policy/reload").json()["error"] is None
    calls = []
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", lambda *args: calls.append(args))
    result = execute(client, "http.get", {"url": "https://docs.example.internal/help?password%3Dhunter2"})
    assert result["decision"] == "BLOCK" and not result["executed"]
    assert "SEC-SECRET-001" in rules(result) and calls == []


def test_structural_host_ip_is_not_redacted_or_blocked_as_url_payload(client, monkeypatch):
    path = client.app.state.settings.policy_path
    policy = yaml.safe_load(path.read_text())
    policy["controls"]["pii"]["input_action"] = "block"
    policy["egress"]["allow_domains"] = ["8.8.8.8"]
    policy["tools"]["allow"]["http.get"]["domains"] = ["8.8.8.8"]
    path.write_text(yaml.safe_dump(policy))
    assert client.post("/api/policy/reload").json()["error"] is None
    calls = []
    def request(*args):
        calls.append(args)
        return {"status_code": 200, "body": "Public content"}
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", request)
    result = execute(client, "http.get", {"url": "https://8.8.8.8/help?section=public"})
    assert result["decision"] == "ALLOW" and result["executed"]
    assert calls[0][1] == "https://8.8.8.8/help?section=public" and "SEC-PII-001" not in rules(result)


def test_http_body_redaction_still_preserves_structural_url(client, monkeypatch):
    path = client.app.state.settings.policy_path
    policy = yaml.safe_load(path.read_text())
    policy["tools"]["allow"]["http.post"]["action"] = "allow"
    path.write_text(yaml.safe_dump(policy))
    assert client.post("/api/policy/reload").json()["error"] is None
    calls = []
    def request(*args):
        calls.append(args)
        return {"status_code": 200, "body": "Stored"}
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", request)
    result = execute(client, "http.post", {"url": "https://docs.example.internal/help", "data": {"contact": "john@example.com"}})
    assert result["decision"] == "REDACT" and result["executed"]
    assert calls[0][1] == "https://docs.example.internal/help"
    assert calls[0][2] == {"contact": "[REDACTED_EMAIL]"}
