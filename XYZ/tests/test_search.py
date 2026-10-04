import json
import socket
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, urlsplit

import pytest
import yaml
from pydantic import ValidationError

from app.audit.database import Database
from app.controls.egress import EgressDenied, validate_destination
from app.models import Envelope
from app.policy.schema import Policy
from app.search import SearchUnavailable, WikipediaSearch
from app.tools.real_tools import RealHttpTransport, RealTools
from app.tools.registry import SCHEMAS


def search_policy():
    return Policy(version=1, profile="search-test", models={"allow": ["qwen3:4b"]},
                  tools={"allow": {"web.search": {"roles": ["employee", "admin"],
                                                  "domains": ["en.wikipedia.org"]}}},
                  egress={"allow_domains": ["en.wikipedia.org"]})


def response(pages=None):
    return {"status_code": 200, "body": {"batchcomplete": True, "query": {"pages": pages if pages is not None else [
        {"pageid": 23862, "index": 1, "title": "Python (programming language)",
         "extract": "Python is a high-level programming language.",
         "fullurl": "https://en.wikipedia.org/wiki/Python_(programming_language)"}]}}}


class Provider:
    def __init__(self, result=None):
        self.result = response() if result is None else result
        self.calls = []

    def request(self, method, url, data, policy, domains):
        validate_destination(url, policy, domains)
        self.calls.append((method, url, data, policy, domains))
        if isinstance(self.result, Exception):
            raise self.result
        return deepcopy(self.result)


@pytest.fixture
def registered(tmp_path):
    provider = Provider()
    tools = RealTools(Database(tmp_path / "search.db"), SimpleNamespace(), http_transport=provider)
    return tools, provider, search_policy(), Envelope(user={"id": "alice", "tenant": "company-a", "role": "employee"})


def test_registered_search_uses_fixed_provider_and_correctly_encoded_query(registered):
    tools, provider, policy, ctx = registered
    result = tools.execute("web.search", {"query": "  C++ & Python  "}, ctx, policy)
    method, url, data, used_policy, domains = provider.calls[0]
    parts = urlsplit(url)
    assert (method, parts.scheme, parts.netloc, parts.path, data) == ("GET", "https", "en.wikipedia.org", "/w/api.php", None)
    assert parse_qs(parts.query) == {
        "action": ["query"], "generator": ["search"], "gsrsearch": ["C++ & Python"],
        "gsrlimit": ["4"], "gsrnamespace": ["0"], "prop": ["extracts|info"],
        "exintro": ["1"], "explaintext": ["1"], "exsentences": ["3"],
        "inprop": ["url"], "format": ["json"], "formatversion": ["2"],
    }
    assert used_policy is policy and domains == ["en.wikipedia.org"]
    assert result == {
        "provider": "Wikipedia", "query": "C++ & Python", "answer": "Python is a high-level programming language.",
        "title": "Python (programming language)", "sources": [{
            "title": "Python (programming language)", "url": "https://en.wikipedia.org/?curid=23862",
            "snippet": "Python is a high-level programming language."}],
        "google_url": "https://www.google.com/search?q=C%2B%2B+%26+Python", "cached": False,
    }


@pytest.mark.parametrize("arguments", [{"query": ""}, {"query": " \t\n"}, {"query": "x" * 301},
                                       {"query": None}, {"query": 1}, {"query": "Python", "url": "http://evil.invalid"}])
def test_search_invalid_or_unknown_arguments_never_reach_provider(registered, arguments):
    tools, provider, policy, ctx = registered
    with pytest.raises(ValidationError):
        tools.execute("web.search", arguments, ctx, policy)
    assert provider.calls == []
    assert SCHEMAS["web.search"].model_json_schema()["additionalProperties"] is False


def test_search_normalizes_untrusted_provider_data_and_preserves_search_rank(registered):
    tools, provider, policy, ctx = registered
    provider.result = response([
        {"pageid": 2, "index": 2, "title": "Second", "extract": "Second result", "fullurl": "javascript:alert(1)"},
        {"pageid": -1, "index": 1, "title": "Bad page", "extract": "Fake"},
        {"pageid": True, "index": 1, "title": "Boolean ID"},
        {"pageid": "1", "index": 1, "title": "String ID"},
        {"pageid": 1, "index": 1, "title": "<b>First &amp; best</b>\x00", "extract": "<script>alert(1)</script><p>Safe <b>excerpt</b>.</p>" + "a" * 1400,
         "fullurl": "https://evil.invalid/phishing", "canonicalurl": "javascript:alert(2)"},
        {"pageid": 1, "index": 3, "title": "Duplicate"},
        {"pageid": 3, "index": 3, "title": "t" * 300, "extract": "<style>bad</style>Third"},
        {"pageid": 4, "index": 4, "title": "Fourth", "extract": "Fourth"},
        {"pageid": 5, "index": 5, "title": "Fifth", "extract": "Fifth"},
        {"pageid": 6, "index": 1, "title": "Missing", "missing": True},
        None,
    ])
    result = tools.execute("web.search", {"query": "Python"}, ctx, policy)
    assert result["title"] == "First & best" and result["answer"].startswith("Safe excerpt.")
    assert len(result["answer"]) == 1200 and len(result["sources"]) == 4
    assert [source["url"] for source in result["sources"]] == ["https://en.wikipedia.org/?curid=" + str(i) for i in range(1, 5)]
    assert len(result["sources"][2]["title"]) == 200
    wire = json.dumps(result)
    assert "<" not in wire and "alert(" not in wire and "evil.invalid" not in wire and "Fifth" not in wire


@pytest.mark.parametrize("body", [{"batchcomplete": True}, {"batchcomplete": True, "query": {"pages": []}}])
def test_search_no_results_has_empty_answer_without_fabrication(body):
    provider = Provider({"status_code": 200, "body": body})
    result = WikipediaSearch(provider).search("unfindable query", search_policy())
    assert result["sources"] == [] and result["answer"] == "" and result["title"] == ""
    assert result["provider"] == "Wikipedia" and result["google_url"].endswith("q=unfindable+query")


@pytest.mark.parametrize("provider_result", [
    ConnectionError("Provider down"), TimeoutError("Private timeout detail"),
    ValueError("HTTP redirects are prohibited"), {"status_code": 403, "body": "provider denied access"},
    {"status_code": 429, "body": "rate limited"},
    {"status_code": 302, "body": {"location": "https://evil.invalid"}},
    {"status_code": 200, "body": "<html>upstream error</html>"},
    {"status_code": 200, "body": {"error": {"info": "Provider error"}}},
    {"status_code": 200, "body": {}}, {"status_code": 200, "body": {"query": {"pages": {}}}},
])
def test_search_provider_failures_are_not_cached_or_replaced_with_fake_answers(provider_result):
    provider = Provider(provider_result)
    search = WikipediaSearch(provider)
    with pytest.raises(SearchUnavailable, match="^Live search is unavailable$"):
        search.search("Python", search_policy())
    provider.result = response()
    assert search.search("Python", search_policy())["cached"] is False
    assert len(provider.calls) == 2


def test_search_uses_pinned_transport_and_never_connects_to_private_provider_dns():
    resolutions, connections = [], []

    def resolver(host, port, **_options):
        resolutions.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    transport = RealHttpTransport(SimpleNamespace(http_timeout=.5), resolver=resolver,
                                  connector=lambda *args: connections.append(args))
    with pytest.raises(EgressDenied):
        WikipediaSearch(transport).search("Python", search_policy())
    assert resolutions == [("en.wikipedia.org", 443)] and connections == []


def test_search_cache_is_bounded_expires_and_is_safe_from_caller_mutation():
    now = [0]
    provider = Provider()
    search = WikipediaSearch(provider, ttl_seconds=300, max_entries=2, clock=lambda: now[0])
    first = search.search("Python", search_policy())
    first["sources"][0]["title"] = "Modified"
    cached = search.search("Python", search_policy())
    assert cached["cached"] and cached["sources"][0]["title"] == "Python (programming language)"
    cached["sources"].clear()
    assert len(search.search("Python", search_policy())["sources"]) == 1 and len(provider.calls) == 1
    now[0] = 300
    assert search.search("Python", search_policy())["cached"] is False and len(provider.calls) == 2
    search.search("C++", search_policy())
    search.search("Java", search_policy())
    assert search.search("Python", search_policy())["cached"] is False and len(provider.calls) == 5


def test_provider_credential_like_output_is_never_retained_in_cache():
    provider = Provider(response([{"pageid": 1, "title": "Sensitive provider text", "extract": "password=hunter2"}]))
    search = WikipediaSearch(provider)
    # Preserve the original output for mandatory gateway detection and redaction.
    assert search.search("Python", search_policy())["answer"] == "password=hunter2"
    assert not search._cache
    assert search.search("Python", search_policy())["cached"] is False and len(provider.calls) == 2


def test_cached_search_still_requires_current_role_grant_and_egress_policy(registered):
    tools, provider, policy, ctx = registered
    tools.execute("web.search", {"query": "Python"}, ctx, policy)
    blocked_role = ctx.model_copy(deep=True)
    blocked_role.user.role = "guest"
    with pytest.raises(PermissionError):
        tools.execute("web.search", {"query": "Python"}, blocked_role, policy)
    for change in ("role", "action", "grant", "global_domain", "tool_domain"):
        changed = policy.model_copy(deep=True)
        if change == "role":
            changed.tools.allow["web.search"].roles = ["admin"]
        elif change == "action":
            changed.tools.allow["web.search"].action = "block"
        elif change == "grant":
            del changed.tools.allow["web.search"]
        elif change == "global_domain":
            changed.egress.allow_domains = ["other.example.org"]
        else:
            changed.tools.allow["web.search"].domains = ["other.example.org"]
        with pytest.raises((PermissionError, EgressDenied)):
            tools.execute("web.search", {"query": "Python"}, ctx, changed)
    assert len(provider.calls) == 1
    assert tools.execute("web.search", {"query": "Python"}, ctx, policy)["cached"] is True


@pytest.mark.parametrize("query", ["password=hunter2", "api_key=abcdefgh12345678",
                                    "Bearer abcdefgh12345678", "password%3Dhunter2", "password%253Dhunter2"])
def test_direct_search_rejects_credentials_before_transport_or_cache(query):
    provider = Provider()
    search = WikipediaSearch(provider)
    with pytest.raises(ValueError, match="credential"):
        search.search(query, search_policy())
    assert provider.calls == [] and not search._cache


def enable_search(client):
    path = client.app.state.settings.policy_path
    policy = yaml.safe_load(path.read_text())
    policy["egress"]["allow_domains"].append("en.wikipedia.org")
    policy["tools"]["allow"]["web.search"] = {"roles": ["employee", "admin"], "domains": ["en.wikipedia.org"]}
    path.write_text(yaml.safe_dump(policy))
    assert client.post("/api/policy/reload").json()["error"] is None


def test_registered_search_gateway_preserves_output_dlp_and_audit(client, monkeypatch):
    enable_search(client)
    provider = Provider(response([{"pageid": 1, "index": 1, "title": "Privacy test",
                                  "extract": "Email jane@example.org. password=hunter2"}]))
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)
    result = client.post("/api/tool/execute", json={"tool": {"name": "web.search", "arguments": {"query": "Python"}}}).json()
    assert result["executed"] and result["decision"] == "REDACT"
    assert "jane@example.org" not in json.dumps(result) and "hunter2" not in json.dumps(result)
    assert result["output"]["answer"] == "Email [REDACTED_EMAIL]. [REDACTED_PASSWORD]"
    events = client.get("/api/events").json()
    assert "hunter2" not in json.dumps(events) and "jane@example.org" not in json.dumps(events)
    assert any(event["rule_id"] == "TOOL_EXECUTED" and event["tool"] == "web.search" for event in events)


def test_registered_search_gateway_sanitizes_query_before_egress(client, monkeypatch):
    enable_search(client)
    provider = Provider()
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)
    result = client.post("/api/tool/execute", json={"tool": {"name": "web.search", "arguments": {"query": "Contact jane@example.org"}}}).json()
    assert result["executed"] and result["decision"] == "REDACT"
    sent_query = parse_qs(urlsplit(provider.calls[0][1]).query)["gsrsearch"][0]
    assert sent_query == "Contact [REDACTED_EMAIL]"
    assert "jane@example.org" not in json.dumps(result)


def test_registered_search_gateway_blocks_encoded_credentials_without_provider_call(client, monkeypatch):
    enable_search(client)
    provider = Provider()
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)
    query = "password=hunter2"
    for _ in range(5):
        query = quote(query, safe="")
    result = client.post("/api/tool/execute", json={"tool": {"name": "web.search", "arguments": {"query": query}}}).json()
    assert result["decision"] == "BLOCK" and not result["executed"] and result["output"] is None
    assert not provider.calls


def test_search_route_requires_authentication_before_any_provider_action(client, monkeypatch):
    provider = Provider()
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)
    for authorization in ("", "Bearer invalid-key"):
        result = client.post("/api/search", headers={"Authorization": authorization}, json={"query": "Python"})
        assert result.status_code == 401
    assert provider.calls == []


@pytest.mark.parametrize("payload", [{"query": " "}, {"query": "x" * 301}, {"query": "Python", "mode": "paid"},
                                    {"query": "Python", "api_key": "secret-value"},
                                    {"query": "Python", "user": {"role": "admin"}}])
def test_search_route_rejects_bad_schema_and_spoofed_identity_without_echoing_values(client, monkeypatch, payload):
    provider = Provider()
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)
    result = client.post("/api/search", json=payload)
    assert result.status_code == 422 and provider.calls == []
    assert "secret-value" not in result.text and "x" * 301 not in result.text


def test_search_route_returns_live_result_and_then_cache_without_model_calls(client, monkeypatch):
    provider = Provider()
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)

    async def no_model(*_args, **_kwargs):
        pytest.fail("Free quick search must not generate an AI answer")

    monkeypatch.setattr(client.app.state.gateway.provider, "chat", no_model)
    monkeypatch.setattr(client.app.state.gateway.provider, "generate", no_model)
    first = client.post("/api/search", json={"query": "  Python  "}).json()
    assert first["executed"] and first["decision"] == "ALLOW"
    assert first["output"]["provider"] == "Wikipedia" and first["output"]["cached"] is False
    second = client.post("/api/search", json={"query": "Python"}).json()
    assert second["output"]["cached"] is True and len(provider.calls) == 1


def test_google_mode_produces_encoded_link_without_provider_or_model_calls(client, monkeypatch):
    provider = Provider()
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)

    async def no_model(*_args, **_kwargs):
        pytest.fail("Opening Google must not invoke an AI model")

    monkeypatch.setattr(client.app.state.gateway.provider, "chat", no_model)
    monkeypatch.setattr(client.app.state.gateway.provider, "generate", no_model)
    result = client.post("/api/search", json={"query": "C++ & Python", "mode": "google"}).json()
    assert result["decision"] == "ALLOW" and not result["executed"]
    assert result["output"] == {"provider": "Google", "query": "C++ & Python", "google_url": "https://www.google.com/search?q=C%2B%2B+%26+Python"}
    assert provider.calls == []


@pytest.mark.parametrize("mode", ["quick", "google"])
def test_search_route_redacts_encoded_pii_before_response_links_and_provider(client, monkeypatch, mode):
    provider = Provider()
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)
    result = client.post("/api/search", json={"query": "Contact jane%2540example.org", "mode": mode}).json()
    assert result["decision"] == "REDACT"
    assert result["output"]["query"] == "Contact [REDACTED_EMAIL]"
    assert parse_qs(urlsplit(result["output"]["google_url"]).query)["q"] == ["Contact [REDACTED_EMAIL]"]
    if mode == "quick":
        assert parse_qs(urlsplit(provider.calls[0][1]).query)["gsrsearch"] == ["Contact [REDACTED_EMAIL]"]
    else:
        assert provider.calls == []


@pytest.mark.parametrize("mode", ["quick", "google"])
def test_search_route_blocks_encoded_secret_without_link_or_provider_and_scrubs_audit(client, monkeypatch, mode):
    provider = Provider()
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)
    result = client.post("/api/search", json={"query": "password%253Dhunter2", "mode": mode}).json()
    assert result["decision"] == "BLOCK" and result["output"] is None and not result["executed"]
    assert provider.calls == [] and "hunter2" not in json.dumps(result)
    assert "hunter2" not in json.dumps(client.get("/api/events").json())


def test_search_route_reports_upstream_denial_honestly_with_google_still_available(client, monkeypatch):
    provider = Provider({"status_code": 403, "body": "Private provider denial detail"})
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)
    failed = client.post("/api/search", json={"query": "Python"}).json()
    assert failed["decision"] == "BLOCK" and not failed["executed"] and failed["output"] is None
    assert "SEARCH_UNAVAILABLE" in {control["rule_id"] for control in failed["controls"]}
    assert "Private provider denial detail" not in json.dumps(failed)
    google = client.post("/api/search", json={"query": "Python", "mode": "google"}).json()
    assert google["decision"] == "ALLOW" and google["output"]["google_url"].endswith("q=Python")
    assert len(provider.calls) == 1


@pytest.mark.parametrize("mode", ["quick", "google"])
def test_search_route_requires_live_policy_authorization_even_when_cached(client, monkeypatch, mode):
    provider = Provider()
    monkeypatch.setattr(client.app.state.gateway.tools.http, "request", provider.request)
    assert client.post("/api/search", json={"query": "Python"}).json()["executed"]
    path = client.app.state.settings.policy_path
    policy = yaml.safe_load(path.read_text())
    policy["tools"]["allow"]["web.search"]["roles"] = ["admin"]
    path.write_text(yaml.safe_dump(policy))
    assert client.post("/api/policy/reload").json()["error"] is None
    rejected = client.post("/api/search", json={"query": "Python", "mode": mode}).json()
    assert rejected["decision"] == "BLOCK" and rejected["output"] is None and not rejected["executed"]
    assert len(provider.calls) == 1
