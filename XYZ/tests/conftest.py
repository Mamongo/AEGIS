import shutil
import pytest
import yaml
from fastapi.testclient import TestClient
from app.config import Settings, ROOT
from app.main import create_app


API_KEYS = {
    "alice-employee-key": {"id": "alice", "role": "employee", "tenant": "demo-company"},
    "alice-admin-key": {"id": "alice", "role": "admin", "tenant": "demo-company"},
    "bob-employee-key": {"id": "bob", "role": "employee", "tenant": "demo-company"},
    "bob-admin-key": {"id": "bob", "role": "admin", "tenant": "demo-company"},
    "other-tenant-key": {"id": "alice", "role": "admin", "tenant": "other-company"},
}


def identity_headers(user):
    for key, claims in API_KEYS.items():
        if all(claims[field] == user[field] for field in ("id", "role", "tenant")):
            return {"Authorization": "Bearer " + key}
    raise ValueError("No test API key configured for identity")


@pytest.fixture
def client(tmp_path):
    policy = tmp_path / "policy.yaml"
    feed = tmp_path / "attacks.yaml"
    shutil.copy(ROOT / "policies/policy.yaml", policy)
    shutil.copy(ROOT / "signatures/attacks.yaml", feed)
    contents = yaml.safe_load(policy.read_text())
    contents["egress"]["allow_domains"] = ["docs.example.internal", "en.wikipedia.org"]
    contents["tools"]["allow"]["http.get"]["action"] = "allow"
    contents["tools"]["allow"]["http.get"]["domains"] = ["docs.example.internal"]
    policy.write_text(yaml.safe_dump(contents))
    settings = Settings(policy_path=policy, signature_path=feed, database_path=tmp_path / "test.db",
                        semantic_enabled=False, ollama_base_url="http://127.0.0.1:1", ollama_timeout=.1,
                        api_keys=API_KEYS, admin_token="test-operator-token")
    app = create_app(settings)
    with app.state.gateway.audit.db.connect() as conn:
        conn.execute("INSERT INTO tickets(id,tenant,summary,description,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                     (1827, "demo-company", "Notification settings", "Customer needs help configuring notification settings.", "open", "alice", 1, 1))
        conn.execute("INSERT INTO employees(id,tenant,name,email) VALUES(?,?,?,?)",
                     ("employee-1", "demo-company", "Actual test employee", "john@example.com"))
    with TestClient(app, headers={"Authorization": "Bearer alice-employee-key", "X-Admin-Token": "test-operator-token"}) as test_client:
        yield test_client


def envelope(text="Hello", tool=None, role="employee", **updates):
    result = {"input": {"text": text}, "user": {"id": "alice", "role": role, "tenant": "demo-company"}}
    if tool:
        result["tool"] = tool
    result.update(updates)
    return result


def action(tool_name, **arguments):
    return {"name": tool_name, "arguments": arguments}
