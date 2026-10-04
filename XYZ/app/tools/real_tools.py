"""Persistent business tools and HTTP that connects only to policy-checked addresses."""
import http.client
import io
import json
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from uuid import uuid4
from app.controls.egress import validate_destination
from app.search import WikipediaSearch
from app.tools.registry import SCHEMAS


_DNS_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="egress-dns")


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("HTTP operation timed out")
    return remaining


class _DeadlineReader(io.RawIOBase):
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline
        # A socket file keeps the descriptor alive when HTTPConnection closes
        # its own reference after a Connection: close response header.
        self.file = sock.makefile("rb", buffering=0)
        super().__init__()

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(_remaining(self.deadline))
        return self.file.readinto(buffer)

    def close(self):
        self.file.close()
        super().close()


class _DeadlineSocket:
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def makefile(self, mode):
        if mode != "rb":
            raise ValueError("Only response reads are supported")
        return io.BufferedReader(_DeadlineReader(self.sock, self.deadline))

    def sendall(self, data):
        self.sock.settimeout(_remaining(self.deadline))
        self.sock.sendall(data)

    def close(self):
        self.sock.close()


def _connect(address, port, timeout):
    sock = socket.socket(address.family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        target = (address.ip, port, 0, 0) if address.family == socket.AF_INET6 else (address.ip, port)
        sock.connect(target)
        return sock
    except BaseException:
        sock.close()
        raise


class RealHttpTransport:
    def __init__(self, settings, *, resolver=None, connector=None, ssl_context=None):
        self.timeout = getattr(settings, "http_timeout", 10.0)
        self.max_response_bytes = getattr(settings, "http_max_response_bytes", 1048576)
        self.max_request_bytes = getattr(settings, "http_max_request_bytes", 1048576)
        if self.timeout <= 0 or self.max_response_bytes <= 0 or self.max_request_bytes <= 0:
            raise ValueError("HTTP limits must be positive")
        self.resolver = resolver or socket.getaddrinfo
        self.connector = connector or _connect
        self.ssl_context = ssl_context or ssl.create_default_context()

    def request(self, method, url, data, policy, domains=None):
        if method not in {"GET", "POST"}:
            raise ValueError("Unsupported HTTP method")
        deadline = time.monotonic() + self.timeout

        def resolve(host, port, **options):
            future = _DNS_POOL.submit(self.resolver, host, port, **options)
            try:
                return future.result(timeout=_remaining(deadline))
            except FutureTimeout:
                future.cancel()
                raise TimeoutError("Destination resolution timed out") from None

        destination = validate_destination(url, policy, domains, resolve=True, resolver=resolve)
        body = None
        headers = {"Accept": "application/json, text/plain, */*", "Connection": "close", "User-Agent": "AEGIS-Gateway/2.0"}
        if method == "POST":
            if isinstance(data, str):
                body = data.encode("utf-8")
                headers["Content-Type"] = "text/plain; charset=utf-8"
            else:
                body = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
                headers["Content-Type"] = "application/json"
            if len(body) > self.max_request_bytes:
                raise ValueError("HTTP request exceeds configured size limit")
        sock = None
        last_error = None
        for address in destination.addresses:
            try:
                sock = self.connector(address, destination.port, _remaining(deadline))
                break
            except OSError as error:
                last_error = error
        if sock is None:
            raise ConnectionError("Destination connection failed") from last_error
        connection = http.client.HTTPConnection(destination.host, destination.port, timeout=self.timeout)
        try:
            if destination.scheme == "https":
                sock.settimeout(_remaining(deadline))
                sock = self.ssl_context.wrap_socket(sock, server_hostname=destination.host, do_handshake_on_connect=False)
                sock.settimeout(_remaining(deadline))
                sock.do_handshake()
            connection.sock = _DeadlineSocket(sock, deadline)
            connection.request(method, destination.target, body=body, headers=headers)
            response = connection.getresponse()
            try:
                if 300 <= response.status < 400:
                    raise ValueError("HTTP redirects are prohibited")
                if response.length is not None and response.length > self.max_response_bytes:
                    raise ValueError("HTTP response exceeds configured size limit")
                content = response.read(self.max_response_bytes + 1)
                if len(content) > self.max_response_bytes:
                    raise ValueError("HTTP response exceeds configured size limit")
                _remaining(deadline)
                content_type = response.getheader("Content-Type", "")
                text = content.decode("utf-8", errors="replace")
                result = text
                if "application/json" in content_type.lower():
                    try:
                        def invalid_constant(_):
                            raise ValueError("Invalid JSON number")
                        result = json.loads(text, parse_constant=invalid_constant)
                    except ValueError:
                        pass
                return {"method": method, "url": url, "status_code": response.status,
                        "content_type": content_type, "body": result}
            finally:
                response.close()
        finally:
            connection.close()
            sock.close()


class RealTools:
    def __init__(self, db, settings, *, http_transport=None):
        self.db = db
        self.http = http_transport or RealHttpTransport(settings)
        self.search = WikipediaSearch(self.http)

    @staticmethod
    def _ticket(row):
        ticket = dict(row)
        ticket["id"] = str(ticket["id"])
        return ticket

    def execute(self, name, args, ctx, policy):
        if name not in SCHEMAS:
            raise ValueError("Unknown tool")
        args = SCHEMAS[name].model_validate(args).model_dump(exclude_none=True)
        tenant = ctx.user.tenant
        if args.get("tenant", tenant) != tenant:
            raise PermissionError("Cross-tenant resource access denied")
        if policy is None:
            raise PermissionError("Tool execution requires a policy")
        grant = policy.tools.allow.get(name)
        if grant is None or grant.action != "allow" or (grant.roles and ctx.user.role not in grant.roles) or (grant.agents and ctx.agent.id not in grant.agents):
            raise PermissionError("Tool is not authorized by policy")
        if name.startswith("internal.ticket."):
            return self._ticket_operation(name, args, ctx)
        if name == "internal.employee.create":
            record = {"id": str(uuid4()), "tenant": tenant, "name": args["name"], "email": args["email"]}
            with self.db.connect() as conn:
                conn.execute("INSERT INTO employees(id,tenant,name,email) VALUES(:id,:tenant,:name,:email)", record)
            return record
        if name == "internal.employee.list":
            with self.db.connect() as conn:
                return [dict(row) for row in conn.execute("SELECT id,tenant,name,email FROM employees WHERE tenant=? ORDER BY name,id LIMIT ?", (tenant, args["limit"]))]
        if name.startswith("http."):
            return self.http.request(name.split(".")[1].upper(), args["url"], args.get("data"), policy, grant.domains)
        if name == "web.search":
            return self.search.search(args["query"], policy, grant.domains)
        a, b = args["a"], args["b"]
        if args["operation"] == "divide" and b == 0:
            raise ValueError("Division by zero")
        return {"result": {"add": lambda: a+b, "subtract": lambda: a-b,
                           "multiply": lambda: a*b, "divide": lambda: a/b}[args["operation"]]()}

    def _ticket_operation(self, name, args, ctx):
        tenant = ctx.user.tenant
        with self.db.connect() as conn:
            if name == "internal.ticket.create":
                timestamp = time.time()
                cursor = conn.execute("INSERT INTO tickets(tenant,summary,description,status,created_by,created_at,updated_at) VALUES(?,?,?,'open',?,?,?)",
                                      (tenant, args["summary"], args["description"], ctx.user.id, timestamp, timestamp))
                row = conn.execute("SELECT * FROM tickets WHERE id=? AND tenant=?", (cursor.lastrowid, tenant)).fetchone()
                return self._ticket(row)
            if name == "internal.ticket.list":
                query, values = "SELECT * FROM tickets WHERE tenant=?", [tenant]
                if "status" in args:
                    query += " AND status=?"
                    values.append(args["status"])
                values.append(args["limit"])
                return [self._ticket(row) for row in conn.execute(query + " ORDER BY id DESC LIMIT ?", values)]
            if name == "internal.ticket.update":
                fields = [field for field in ("status", "summary", "description") if field in args]
                updates = ", ".join(field + "=?" for field in fields)
                values = [args[field] for field in fields] + [time.time(), args["ticket_id"], tenant]
                cursor = conn.execute("UPDATE tickets SET " + updates + ", updated_at=? WHERE id=? AND tenant=?", values)
                if not cursor.rowcount:
                    raise LookupError("Ticket not found")
            row = conn.execute("SELECT * FROM tickets WHERE id=? AND tenant=?", (args["ticket_id"], tenant)).fetchone()
            if row is None:
                raise LookupError("Ticket not found")
            return self._ticket(row)
