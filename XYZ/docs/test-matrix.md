# Security and real-runtime test matrix

The suite exercises the running gateway, trusted identity boundary, persistent tools, model proposal loop, and the outbound HTTP adapter. Categories describe tested behavior, not certification or exhaustive attack coverage. Every test uses isolated databases/configuration; no existing application records are changed by pytest.

| Area / tests | Boundary checked | Expected behavior |
|---|---|---|
| `test_auth.py`: missing/invalid keys; claimed role/tenant; agent grants | API identity | Missing credentials return 401; user fields cannot replace server-derived claims; ungranted agents deny |
| `test_auth.py`: memory identity; operator token; invalid key configuration | Memory and management identity | Ownership uses the authenticated principal; operator credentials are separate; invalid configuration errors omit secrets |
| `test_real_tools.py`: ticket creation, restart, update, tenant isolation | SQLite persistence | Creates actual rows; reopened adapter reads changes; foreign tenant access fails |
| `test_real_tools.py`: missing records, update validation, employees | Record integrity | No fabricated tickets/employees; updates require a change; employee creation/list is tenant-scoped; broker-redacted email markers can be persisted |
| `test_real_tools.py`: captured policy and calculator | Adapter enforcement | Policy must be supplied and granted; arithmetic executes; division by zero fails |
| `test_real_tools.py`: real HTTP GET/POST and original Host | Checked network execution | Actual local socket exchange uses the approved resolved address and original hostname |
| `test_real_tools.py`: prohibited DNS answers and private exceptions | SSRF and DNS rebinding | Every answer is checked before connecting; loopback denied; private addresses need explicit grants |
| `test_real_tools.py`: redirects, body caps, total deadline | HTTP resource and release boundary | Redirects are refused; oversized bodies and elapsed deadlines stop execution |
| `test_real_tools.py`: TLS hostname/certificate verification | HTTPS identity | Actual local HTTPS request verifies the original hostname and trusted certificate; mismatch fails |
| `test_live_agent.py`: unavailable provider and ticket keywords | Model execution | Unavailable model blocks with no fabricated response or ticket; text patterns do not invent proposals |
| `test_live_agent.py`: native Ollama HTTP contract and malformed responses | Provider trust | Valid native tool calls become proposals; invalid/non-finite/oversized responses deny |
| `test_live_agent.py`: model proposal persistence and threadpool execution | Model-to-broker boundary | Actual SQLite rows are created/read only after schema, policy, quotas, and pre-execution audit |
| `test_live_agent.py`: denied proposals and output injection | Untrusted model and tool output | Authorization, DLP, egress, signatures, and injection checks stop denied actions and unsafe follow-up content |
| `test_live_agent.py`: output DLP and blocked release | Tool-to-model boundary | Sensitive results are sanitized before the next model call; blocked output stops the loop |
| `test_live_agent.py`: repetition and multiple-call budgets | Agent resource use | Third identical proposal or exhausted quota stops; completed side effects retain `executed: true` after later failure |
| `test_live_agent.py`: policy snapshots and audit failures | In-flight authorization | Captured policy governs the run; missing pre-execution audit prevents a tool action |
| `test_gateway.py`: normal, evaluate-only, allowed broker calls | Gateway integration | Decisions and audit agree; evaluation never executes |
| `test_search.py`: fixed provider, normalization, cache, outages | Search results | Real adapter targets Wikipedia; citations use validated page IDs; cache is bounded and expires; errors never become invented answers |
| `test_search.py`: authentication, grants, decoded queries, Google mode | Search boundary | User key required; secret queries deny and PII redacts before egress; Google links use checked queries without contacting a provider |
| `test_gateway.py`: injection, signatures, secrets, PII | Content controls | Matched attacks block; configured PII redacts; detected secrets do not enter plaintext audit/response |
| `test_gateway.py`: RBAC, resource ownership, tenant checks | Authorization | Employee cannot use admin-only grants; cross-tenant access denies even for admin |
| `test_gateway.py`: URLs, private grants, DNS, model allowlist | Destination/model routing | Unsupported/ambiguous URLs and unapproved models deny |
| `test_gateway.py`: user/global/token/time quotas, concurrency, IDs, loops | Budget integrity | Atomic reservations and server-created runs prevent quota bypass; failures stop actions |
| `test_gateway.py`: valid/invalid policy and feed reloads | Live configuration | Valid versions activate; malformed YAML, unsupported fields, or invalid regex retain the last good state |
| `test_gateway.py`: nested payload secrets and output suppression | Data release | Secret payloads deny; blocked output is absent even after an authorized action executed |
| Business-field and encoded-URL input DLP tests | Storage / transmission boundary | Default PII policy scrubs record fields before writes; encoded secrets or restricted PII in URL paths/queries deny before HTTP execution |
| `test_gateway.py`: semantic JSON, fail modes, precedence | Supplemental classification | Invalid classifier output follows policy; semantic ALLOW cannot override deterministic BLOCK |
| `test_gateway.py`: memory poisoning/isolation; approvals | Stored content / human authorization | Suspicious memory quarantines and private reads deny; approval-required actions remain unexecuted |
| `test_gateway.py`: dashboard, static files, metrics, latency, removed demos | Runtime surface | Dashboard/API are available, telemetry reflects requests, runtime demo endpoints return 404 |

`python run.py test` runs pytest. The shell runner supports `PYTHON=python3 sh scripts/run_tests.sh`. Provider behavior is controlled in automated tests; real model generation requires a separately installed running Ollama model. HTTP adapter tests use actual local test servers with test-specific address setup, not a public service or the default blocked egress policy. Docker is not verified by this suite.

`python run.py smoke` checks an independently running server through its authenticated HTTP API, executes the real calculator, and creates/reads a saved ticket. That smoke command intentionally leaves its ticket in the application's database and does not exercise Ollama or outbound HTTP.

`node tests/frontend-search.cjs` covers source and Google link validation, safe text rendering, loading, failure/no-result states, and query or credential changes during pending requests. Browser checks use isolated response fixtures for successful provider rendering and separately exercise actual connection errors.
