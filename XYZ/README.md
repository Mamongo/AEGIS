# AEGIS

An authenticated FastAPI gateway for a local AI agent, with a browser dashboard, persistent SQLite ticket and employee records, a real HTTP adapter, YAML policies, and an audit trail. Ollama supplies actual model responses and structured tool proposals. Tools execute only after the gateway grants them.

The application starts with an empty record store. Reading a nonexistent ticket fails. Chat cannot produce a fallback reply when the model is unavailable. There are no runtime attack scenarios or simulated tool adapters.

## Run locally

Requires Python 3.11+. From the repository root on Windows:

```powershell
python run.py init
python run.py
```

On Linux or macOS:

```sh
python3 run.py init
python3 run.py
```

`init` creates a private `.env` containing randomly generated user and operator credentials. An existing `.env` is preserved. `run` initializes this file if absent, creates `.venv`, installs dependencies when the requirements change, loads `.env`, and starts http://127.0.0.1:8000. Internet access is needed for the first dependency installation. Stop with Ctrl+C. On Windows, `py` works instead of `python` if your Python launcher is registered correctly.

Open `.env` in your editor. The key of the `API_KEYS_JSON` object is your user API key; `ADMIN_TOKEN` is the separate operator credential. Enter these in the dashboard's **Connect** form. Credentials remain in browser memory and are cleared on disconnect or reload. The initial user is `local-user`, with the `admin` role in tenant `local`, authorized to use `support-agent`.

Create a ticket, refresh the list, read its details, and update its status. These operations use the same guarded broker as the agent and persist across application restarts. The registered-tool form accepts JSON arguments, displays their schema, and offers either execution or evaluation without execution. The operator view shows actual audit events, quota usage, policy grants, and reload controls.

The dashboard's catgirl guard reacts to actual gateway results: celebration for ALLOW, side-eye for WARN, privacy mode for REDACT, a bonk for BLOCK, and a hold for REQUIRE_APPROVAL. The notification shows rule IDs without copying your prompt or output. Blocked and approval-required notifications stay until dismissed; other notifications close after eight seconds and pause while hovered or focused. Use **Catgirl alerts: ON/OFF**, the close button, or Escape. If a tool ran before a later block, the alert states that its side effects may already have happened.

## Free search

Connect with your existing user API key, enter a query in the search panel, and press **Quick answer**. AEGIS fetches short Wikipedia excerpts with source links and caches successful queries for five minutes. This feature needs internet access but no search subscription, paid API key, or running Ollama model. It provides encyclopedia summaries; current events and other web results are available through Google.

Press **Search Google**, then **Open Google results** to open the checked query in a new tab. Google supplies those full results; the inline quick answer is labeled Wikipedia. Both actions pass through the gateway's authorization, secret detection, PII redaction, quotas, and audit. Queries are limited to 300 characters. Provider errors and empty results are shown explicitly, and the Google option remains available when Wikipedia fails.

The default policy grants the fixed Wikipedia integration only. General HTTP tools remain blocked until an operator explicitly enables them. Google links are generated locally without a server-side Google API call. Google's [Custom Search JSON API](https://developers.google.com/custom-search/v1/overview) is closed to new customers, so it is not a dependency.

## Enable the model

Install [Ollama](https://ollama.com/) separately and explicitly download the configured model:

```sh
ollama pull qwen3:4b
ollama serve
```

If the Ollama desktop application already runs its service, use that existing service. The gateway never installs Ollama or downloads a model. Relevant `.env` settings:

```dotenv
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen3:4b
OLLAMA_TIMEOUT=60
SEMANTIC_ENABLED=true
```

To change models, update both `OLLAMA_MODEL` and `models.allow` in `policies/policy.yaml`, then restart the application for the environment change. Use a model that supports native tool calls. The dashboard reports whether Ollama is connected and the configured model is available. Chat returns `BLOCK` with `MODEL_UNAVAILABLE` when a model call fails; deterministic evaluation, calculators, and record tools can run without Ollama.

Try “List my open tickets” after creating a record. The agent sends model-generated tool proposals through schema validation, authorization, DLP, egress checks, quotas, and pre-execution audit. Released tool results are sent back to the model for its next step. The loop stops on denial or its step, token, tool-call, repetition, or time limits. Each chat request is independent; include the context you want the agent to use.

## Authentication and configuration

User APIs require `Authorization: Bearer <API key>`. The server derives the user's ID, role, tenant, and allowed agents from `API_KEYS_JSON`; caller-supplied user claims cannot change that identity. Operator APIs require `X-Admin-Token`. A user with the `admin` role still needs the separate operator credential to access audit and policy management. Missing credentials fail closed.

`API_KEYS_JSON` is a single-line JSON object in `.env`. To add a user, add another randomly generated key with trusted claims:

```dotenv
API_KEYS_JSON={"<random-user-api-key>":{"id":"alice","role":"employee","tenant":"company-a","agents":["support-agent"]}}
ADMIN_TOKEN=<separate-random-operator-token>
```

Replace the placeholders with strong random values. Keep `.env` private; it is excluded from Git and Docker build context. Restart after credential or environment changes. The launcher preserves existing environment values over `.env` values. Direct uvicorn execution requires exporting those variables yourself; it does not load `.env` automatically.

Other settings are `DATABASE_PATH` (default `data/control.db`), `POLICY_PATH` (default `policies/policy.yaml`), `SIGNATURE_PATH` (default `signatures/attacks.yaml`), `HTTP_TIMEOUT` (10 seconds), `HTTP_MAX_REQUEST_BYTES`, and `HTTP_MAX_RESPONSE_BYTES` (both 1 MiB by default).

## Tools and real network access

| Tool | Arguments / behavior | Default roles |
|---|---|---|
| `internal.ticket.create` | `summary`, optional `description`; stores a new ticket | employee, admin |
| `internal.ticket.list` | Optional `status`, `limit` (1–100); lists this tenant's saved tickets | employee, admin |
| `internal.ticket.read` | `ticket_id` as a numeric string; reads an existing ticket | employee, admin |
| `internal.ticket.update` | `ticket_id` and at least one of `status`, `summary`, `description` | admin |
| `internal.employee.create` | `name`, `email`; stores a tenant-scoped employee | admin |
| `internal.employee.list` | Optional `limit` (1–100); lists saved employee records | admin |
| `calculator` | `a`, `b`, `operation`: add, subtract, multiply, divide | employee, admin |
| `web.search` | `query` (1–300 characters); real Wikipedia excerpts, citations, and a Google link | employee, admin |
| `http.get` | `url`; performs an explicitly authorized HTTP GET | blocked initially |
| `http.post` | `url`, optional `data` as an object or string; performs an authorized POST | blocked initially |

Record tools accept an optional `tenant`; a different tenant is denied even for an admin. Ticket status is `open`, `in_progress`, or `closed`. `GET /api/tools` supplies the complete registered JSON schemas. No employees, tickets, or credentials are fabricated by adapters. The default PII policy scrubs detected data in ticket/employee fields before storage and on released output. An email is stored as `[REDACTED_EMAIL]` under this policy. An operator can explicitly allow PII input storage; output controls are configured separately.

HTTP calls send real traffic after authorization. The default policy permits `en.wikipedia.org` for `web.search`; general HTTP tools are blocked. To allow a general HTTP destination, enable the relevant tool grant and update the global egress allowlist, for example:

```yaml
tools:
  default: block
  allow:
    # Retain the other existing tool grants here.
    http.get: {roles: [employee, admin], domains: [api.your-company.example]}
    http.post: {action: allow, roles: [admin], domains: [api.your-company.example]}
egress:
  default: block
  allow_domains: [en.wikipedia.org, api.your-company.example]
  allow_private_domains: []
```

Replace the example hostname with an actual destination you intend to authorize. Hostnames match exactly; HTTPS uses port 443 and HTTP uses port 80. Explicit private-domain exceptions require both egress lists; loopback and cloud metadata addresses remain denied. The adapter validates every DNS answer before connecting directly to a checked address. It preserves the original HTTP Host and TLS hostname, verifies certificates, ignores environment proxy settings, rejects redirects, and bounds request/response bytes and total network time. Detected secrets in decoded URL paths/queries deny; PII paths/queries also deny under the default redact policy, because a URL cannot safely be scrubbed and sent to the same resource. The adapter returns the method, URL, status code, content type, and JSON or text body. Output controls may suppress a response after the external action has already happened.

## API examples

On PowerShell, read the local credentials without printing them:

```powershell
$apiConfig = ((Get-Content .env | Where-Object { $_ -like 'API_KEYS_JSON=*' }) -replace '^API_KEYS_JSON=', '') | ConvertFrom-Json
$userHeaders = @{ Authorization = 'Bearer ' + $apiConfig.PSObject.Properties[0].Name }
Invoke-RestMethod http://127.0.0.1:8000/api/me -Headers $userHeaders

$body = @{ tool = @{ name = 'internal.ticket.create'; arguments = @{ summary = 'Notifications are delayed'; description = 'Investigate delivery timing.' } } } | ConvertTo-Json -Depth 6
Invoke-RestMethod http://127.0.0.1:8000/api/tool/execute -Method Post -Headers $userHeaders -ContentType application/json -Body $body
```

On Unix, set `API_KEY` to your configured user key, then:

```sh
curl -s http://127.0.0.1:8000/api/me -H "Authorization: Bearer $API_KEY"
curl -s http://127.0.0.1:8000/api/tool/execute \
  -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
  -d '{"tool":{"name":"internal.ticket.list","arguments":{"limit":50}}}'
curl -s http://127.0.0.1:8000/api/chat \
  -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
  -d '{"input":{"text":"List my open tickets."}}'
```

The normalized envelope can include `input`, `agent`, `model`, `tool`, `resource`, `destination`, `request_id`, and `session_id`. Omit `user`; authentication supplies trusted claims. An omitted `model` uses `OLLAMA_MODEL`; both configured and explicitly requested models still require a policy grant. Gateway responses report `decision`, findings in `controls`, `executed`, released `output`, versions, timing, and quota usage. A security denial is a valid HTTP 200 response with `BLOCK` or `REQUIRE_APPROVAL`, so clients must inspect the decision. `executed: true` can accompany a later output block or model failure.

| Endpoint | Access / purpose |
|---|---|
| `GET /`, `/static/*`, `/health`, `/docs` | Public dashboard assets, readiness, API documentation |
| `GET /api/me`, `/api/status`, `/api/tools` | User key; authenticated principal, model state, registered schemas |
| `POST /api/chat` | User key; real Ollama agent and guarded tool loop |
| `POST /api/search` | User key; `{query, mode: "quick"\|"google"}`; Wikipedia quick answer or a checked Google link |
| `POST /api/evaluate`, `/api/tool/evaluate` | User key; evaluate input or proposal without execution |
| `POST /api/tool/execute` | User key; evaluate and execute an authorized registered tool |
| `POST /api/memory`, `/api/memory/{id}/read` | User key; untrusted memory writes and ownership-scoped reads |
| `GET /api/events`, `/api/metrics`, `/api/budgets` | Operator token; audit, telemetry, rolling usage |
| `GET /api/policy`, `POST /api/policy/reload` | Operator token; validated policy and reload |
| `GET /api/signatures`, `POST /api/signatures/reload` | Operator token; signature feed and reload |
| `POST /api/budgets/reset` | Operator token; reset quota counters, retain records and audit |

Event filters are `decision`, `severity`, `control`, `user`, and `limit` (1–500).

## Policy and control behavior

`policies/policy.yaml` and `signatures/attacks.yaml` reload after validated edits. A background watcher checks every 0.5 seconds; requests also check for changes. Invalid edits retain the last known good configuration, while invalid initial configuration fails startup. Active versions and reload errors are visible to the operator. Each request retains its captured policy, including while waiting for the model.

Decision precedence is `BLOCK > REQUIRE_APPROVAL > REDACT > WARN > ALLOW`. An approval requirement holds the action; approval issuance is not implemented. Unknown tools/models and malformed arguments deny. A tool cannot run if the pre-execution authorization audit cannot be persisted. SQLite transactions make quota reservations atomic across workers. Client request/session IDs do not define trusted run counters.

Controls include PII and secret detection, normalized injection heuristics, role/tenant authorization, tool schemas and domain grants, network egress checks, output inspection, bounded semantic classification, attack signatures, memory ownership/provenance, budgets, and loop prevention. Semantic analysis supplements deterministic controls and cannot downgrade a denial. Its configured unavailable-provider behavior is distinct from chat: `deterministic_only` adds a warning; `block` denies. Tokens are approximate UTF-8 units, and reservations are not refunded after provider failures.

## Docker

Initialize `.env` first, then configure its `OLLAMA_BASE_URL` for access from the container. Docker Desktop normally uses `http://host.docker.internal:11434`; container `localhost` refers to the gateway container itself.

```sh
python3 run.py init
docker compose up --build
```

On Windows, use `python run.py init`. Compose requires `.env`, binds the published port to host loopback, runs as an unprivileged user, and persists SQLite in a named volume. Policy and signature directories are read-only inside the container and editable on the host. Ollama is a separate service. Linux includes a host-gateway mapping, but host Ollama must be reachable from the container network; configure a suitable private bind/firewall or use a separate Ollama service on that network.

## Verification

```powershell
python run.py test
```

```sh
python3 run.py test
# Or select an interpreter for the shell runner:
PYTHON=python3 sh scripts/run_tests.sh
```

With the server running, `python run.py smoke` (or `python3 run.py smoke`) verifies authentication, the calculator, and persistent ticket creation/read through live HTTP API calls. It leaves the created ticket in your database. `GATEWAY_URL` selects a different server; `API_KEY` can select a user credential. The smoke command does not verify model generation or perform outbound HTTP actions.

Frontend alert behavior can be checked separately with Node.js: `node tests/frontend-alerts.cjs`. The checks cover safe notification content, execution reporting, timers, mute/dismiss controls, error deduplication, and disconnect races.

Search frontend checks run with `node tests/frontend-search.cjs` and cover source links, provider failures, loading state, query sanitization, and stale requests. Search backend tests use controlled provider responses to verify parsing, caching, guards, and outages; live Wikipedia access depends on the network and provider.

The automated suite uses isolated SQLite databases and configuration files. Provider tests use controlled model responses and unavailable endpoints; adapter tests perform actual HTTP/HTTPS exchanges with local test servers and verify address checks, TLS hostname validation, redirects, size limits, and timeouts. These tests do not demonstrate a downloaded Ollama model, a public external service, or Docker deployment working on your machine. See [the test matrix](docs/test-matrix.md) for covered boundaries and [local validation](docs/validation.md) for measured results.

## Operational limits

This is a usable local service; shared deployments still require HTTPS, controlled credential distribution and rotation, network firewall rules, backups, and an appropriate process manager. SQLite is not encrypted or tamper-evident and has no automated retention. A browser disconnect clears its credentials and displayed data but does not cancel a request already accepted by the server.

DLP and injection detectors are heuristic and can miss encoded, novel, multilingual, or split attacks. Semantic classification is supplementary. Stored memory remains untrusted and is not automatically retrieved by the chat agent. There is no shell adapter, general MCP transport, approval-grant workflow, or cross-service transaction for tool effects and logging. A request denial cannot undo an earlier authorized tool action. Regex signatures and policy edits are privileged operator configuration.
