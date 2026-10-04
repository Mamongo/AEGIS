import json
import shutil
import socket
import ssl
import subprocess
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from app.audit.database import Database
from app.controls.egress import EgressDenied, validate_destination
from app.models import Envelope
from app.policy.schema import Policy
from app.tools.real_tools import RealHttpTransport, RealTools
from app.tools.registry import SCHEMAS


def settings(**updates):
    return SimpleNamespace(**({"http_timeout": 1, "http_max_response_bytes": 1024,
                              "http_max_request_bytes": 1024} | updates))


def context(tenant="company-a", role="admin"):
    return Envelope(user={"id": "alice", "tenant": tenant, "role": role})


def policy(host="api.example.org", private=False):
    grants = {name: {"roles": ["admin", "employee"]} for name in SCHEMAS}
    grants["http.get"]["domains"] = [host]
    grants["http.post"]["domains"] = [host]
    return Policy(version=1, profile="integration", models={"allow": ["qwen3:4b"]},
                  tools={"allow": grants}, egress={"allow_domains": [host],
                  "allow_private_domains": [host] if private else []})


def execute(tools, name, arguments, ctx, active=None):
    return tools.execute(name, arguments, ctx, active or policy())


def test_ticket_records_are_created_persisted_updated_and_tenant_scoped(tmp_path):
    db = Database(tmp_path / "records.db")
    tools = RealTools(db, settings())
    assert execute(tools, "internal.ticket.list", {}, context()) == []
    created = execute(tools, "internal.ticket.create", {"summary": "Real customer issue", "description": "Notification is disabled"}, context())
    assert created["summary"] == "Real customer issue" and created["created_by"] == "alice"
    # A new adapter and database connection read the committed business record.
    restarted = RealTools(Database(tmp_path / "records.db"), settings())
    assert execute(restarted, "internal.ticket.read", {"ticket_id": created["id"]}, context()) == created
    updated = execute(restarted, "internal.ticket.update", {"ticket_id": created["id"], "status": "closed", "description": "Resolved"}, context())
    assert updated["status"] == "closed" and updated["description"] == "Resolved"
    assert updated["updated_at"] >= updated["created_at"]
    assert execute(restarted, "internal.ticket.list", {"status": "open"}, context()) == []
    assert execute(restarted, "internal.ticket.list", {"status": "closed"}, context()) == [updated]
    assert execute(restarted, "internal.ticket.list", {}, context("company-b")) == []
    for name, arguments in [("internal.ticket.read", {}), ("internal.ticket.update", {"status": "open"})]:
        with pytest.raises(LookupError):
            execute(restarted, name, {"ticket_id": created["id"]} | arguments, context("company-b"))
    with pytest.raises(PermissionError):
        execute(restarted, "internal.ticket.read", {"ticket_id": created["id"], "tenant": "company-a"}, context("company-b"))
    assert execute(restarted, "internal.ticket.read", {"ticket_id": created["id"]}, context())["status"] == "closed"


def test_missing_ticket_never_fabricates_data_and_update_requires_changes(tmp_path):
    tools = RealTools(Database(tmp_path / "records.db"), settings())
    with pytest.raises(LookupError):
        execute(tools, "internal.ticket.read", {"ticket_id": "1827"}, context())
    with pytest.raises(LookupError):
        execute(tools, "internal.ticket.update", {"ticket_id": "1827", "status": "closed"}, context())
    with pytest.raises(ValidationError):
        execute(tools, "internal.ticket.update", {"ticket_id": "1827"}, context())
    assert execute(tools, "internal.ticket.list", {}, context()) == []
    assert "internal.secret.read" not in SCHEMAS


def test_employee_records_are_real_and_tenant_scoped(tmp_path):
    tools = RealTools(Database(tmp_path / "records.db"), settings())
    assert execute(tools, "internal.employee.list", {}, context()) == []
    created = execute(tools, "internal.employee.create", {"name": "Ada", "email": "ada@example.org"}, context())
    assert execute(tools, "internal.employee.list", {}, context()) == [created]
    assert execute(tools, "internal.employee.list", {}, context("company-b")) == []
    with pytest.raises(PermissionError):
        execute(tools, "internal.employee.create", {"name": "Eve", "email": "eve@example.org", "tenant": "company-b"}, context())


def test_employee_accepts_exact_email_redaction_marker(tmp_path):
    tools = RealTools(Database(tmp_path / "records.db"), settings())
    created = execute(tools, "internal.employee.create", {"name": "Ada", "email": "[REDACTED_EMAIL]"}, context())
    assert created["email"] == "[REDACTED_EMAIL]"
    assert execute(tools, "internal.employee.list", {}, context()) == [created]
    with pytest.raises(ValidationError):
        execute(tools, "internal.employee.create", {"name": "Ada", "email": "[REDACTED_OTHER]"}, context())


def test_adapter_enforces_captured_policy_and_calculator(tmp_path):
    tools = RealTools(Database(tmp_path / "records.db"), settings())
    active = policy()
    active.tools.allow["internal.ticket.create"].action = "block"
    with pytest.raises(PermissionError):
        execute(tools, "internal.ticket.create", {"summary": "Denied"}, context(), active)
    assert execute(tools, "calculator", {"a": 12, "b": 4, "operation": "divide"}, context())["result"] == 3
    with pytest.raises(ValueError):
        execute(tools, "calculator", {"a": 1, "b": 0, "operation": "divide"}, context())
    with pytest.raises(PermissionError):
        tools.execute("http.get", {"url": "https://api.example.org/"}, context(), None)
    with pytest.raises(PermissionError):
        tools.execute("internal.ticket.create", {"summary": "Requires policy"}, context(), None)
    active.tools.allow["internal.employee.list"].roles = ["admin"]
    with pytest.raises(PermissionError):
        execute(tools, "internal.employee.list", {}, context(role="employee"), active)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.requests.append({"method": "GET", "path": self.path, "host": self.headers["Host"]})
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/secret")
            self.end_headers()
            return
        if self.path in {"/oversized", "/unbounded"}:
            body = b"x" * 2048
            self.send_response(200)
            if self.path == "/oversized":
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/slow":
            self.send_response(200)
            self.send_header("Content-Length", "20")
            self.end_headers()
            try:
                for _ in range(20):
                    self.wfile.write(b"a")
                    self.wfile.flush()
                    time.sleep(.03)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return
        self._respond({"path": self.path, "host": self.headers["Host"]})

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        record = {"method": "POST", "path": self.path, "host": self.headers["Host"],
                  "content_type": self.headers["Content-Type"], "body": body.decode()}
        self.server.requests.append(record)
        self._respond(record)

    def _respond(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def backend(tls_context=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.requests = []
    if tls_context:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def transport(server, *, addresses=("93.184.216.34",), **updates):
    resolutions, connections = [], []

    def resolve(host, port, **_):
        resolutions.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port)) for address in addresses]

    def connect(address, port, timeout):
        connections.append((address.ip, port))
        # Inject test routing only: the complete HTTP exchange uses real sockets.
        return socket.create_connection(server.server_address, timeout)

    instance = RealHttpTransport(settings(**updates), resolver=resolve, connector=connect)
    return instance, resolutions, connections


def test_real_http_get_and_post_use_checked_address_and_original_host(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    with backend() as server:
        http, resolutions, connections = transport(server)
        response = http.request("GET", "http://api.example.org/help?q=ok#ignored", None, policy())
        assert response["status_code"] == 200
        assert response["body"] == {"path": "/help?q=ok", "host": "api.example.org"}
        posted = http.request("POST", "http://api.example.org/submit", {"message": "Actual payload"}, policy())
        assert json.loads(posted["body"]["body"]) == {"message": "Actual payload"}
        assert posted["body"]["content_type"] == "application/json"
        text = http.request("POST", "http://api.example.org/submit", "plain text", policy())
        assert text["body"]["body"] == "plain text"
        assert resolutions == [("api.example.org", 80)] * 3
        assert connections == [("93.184.216.34", 80)] * 3
        assert len(server.requests) == 3


@pytest.mark.parametrize("addresses", [("127.0.0.1",), ("169.254.169.254",), ("10.2.3.4",), ("93.184.216.34", "127.0.0.1")])
def test_http_rejects_all_prohibited_dns_answers_before_connecting(addresses):
    with backend() as server:
        http, _, connections = transport(server, addresses=addresses)
        with pytest.raises(EgressDenied):
            http.request("GET", "http://api.example.org/", None, policy())
        assert connections == [] and server.requests == []


def test_private_dns_address_needs_explicit_permission_and_loopback_always_denied():
    with backend() as server:
        http, _, connections = transport(server, addresses=("10.2.3.4",))
        assert http.request("GET", "http://api.example.org/", None, policy(private=True))["status_code"] == 200
        assert connections == [("10.2.3.4", 80)]
        denied, _, connects = transport(server, addresses=("127.0.0.1",))
        with pytest.raises(EgressDenied):
            denied.request("GET", "http://api.example.org/", None, policy(private=True))
        assert connects == []


def test_http_refuses_redirects_and_bounds_bodies_before_more_requests():
    with backend() as server:
        http, _, connections = transport(server)
        with pytest.raises(ValueError, match="redirects"):
            http.request("GET", "http://api.example.org/redirect", None, policy())
        assert len(server.requests) == 1
        for path in ("oversized", "unbounded"):
            with pytest.raises(ValueError, match="size limit"):
                http.request("GET", "http://api.example.org/" + path, None, policy())
        before = len(connections)
        with pytest.raises(ValueError, match="size limit"):
            http.request("POST", "http://api.example.org/", "x" * 2048, policy())
        assert len(connections) == before


def test_http_deadline_applies_to_entire_response_not_each_byte():
    with backend() as server:
        http, _, _ = transport(server, http_timeout=.12)
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            http.request("GET", "http://api.example.org/slow", None, policy())
        assert time.monotonic() - started < .5


def test_destination_urls_and_tool_domains_cannot_bypass_allowlist():
    active = policy()
    for url in ("http://api.example.org@evil.example.org/", "http://api.example.org:8000/", "http://api.example.org\n/", "http://%61pi.example.org/", "file:///tmp/example"):
        with pytest.raises(EgressDenied):
            validate_destination(url, active)
    with pytest.raises(EgressDenied):
        validate_destination("http://api.example.org/", active, ["another.example.org"])


@pytest.mark.parametrize("answers", [[], [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("::1", 80))],
                                    [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 80))],
                                    [(socket.AF_INET,)], [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("bad-ip", 80))]])
def test_malformed_or_mapped_local_dns_answers_are_denied(answers):
    with pytest.raises(EgressDenied):
        validate_destination("http://api.example.org/", policy(), resolve=True, resolver=lambda *_args, **_kwargs: answers)


def test_dns_lookup_respects_operation_deadline_without_connecting():
    connections = []

    def slow_resolver(*_args, **_kwargs):
        time.sleep(.15)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

    http = RealHttpTransport(settings(http_timeout=.03), resolver=slow_resolver,
                             connector=lambda *arguments: connections.append(arguments))
    started = time.monotonic()
    with pytest.raises(EgressDenied):
        http.request("GET", "http://api.example.org/", None, policy())
    assert time.monotonic() - started < .12
    assert connections == []


def test_https_validates_original_hostname_and_certificate(tmp_path):
    openssl = shutil.which("openssl")
    if not openssl:
        git_openssl = Path("C:/Program Files/Git/usr/bin/openssl.exe")
        openssl = str(git_openssl) if git_openssl.is_file() else None
    if not openssl:
        pytest.skip("OpenSSL executable required to create a local test certificate")
    certificate, key = tmp_path / "certificate.pem", tmp_path / "key.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-sha256",
                    "-subj", "/CN=api.example.org", "-addext", "subjectAltName=DNS:api.example.org",
                    "-keyout", str(key), "-out", str(certificate)], check=True, capture_output=True)
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(certificate, key)
    trusted = ssl.create_default_context(cafile=str(certificate))
    with backend(server_tls) as server:
        http, _, connections = transport(server)
        assert http.ssl_context.check_hostname and http.ssl_context.verify_mode == ssl.CERT_REQUIRED
        with pytest.raises(ssl.SSLCertVerificationError):
            http.request("GET", "https://api.example.org/", None, policy())
        http.ssl_context = trusted
        assert http.request("GET", "https://api.example.org/", None, policy())["status_code"] == 200
        with pytest.raises(ssl.SSLCertVerificationError):
            http.request("GET", "https://wrong.example.org/", None, policy("wrong.example.org"))
        assert connections == [("93.184.216.34", 443)] * 3
