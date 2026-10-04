# Local validation

Validated on Windows with Python 3.12.1:

- Python verification covered **238 distinct tests**: a full run passed 222 tests, followed by all 47 final search tests, including 16 added cases. One upstream Starlette warning concerns the current httpx TestClient integration.
- `python run.py smoke`: the running authenticated gateway calculated 42 and created/read tickets 1 and 2 in SQLite. Ticket 1 was read successfully after restarting the server with the completed implementation.
- `Get-Content -Raw app/dashboard/static/app.js | node --check`: JavaScript syntax passed.
- Dashboard checks verified element references, authenticated tool submissions, ticket creation/list/update rendering, and rejection of a delayed credential response after disconnect.
- Catgirl frontend checks passed six Node behavior groups and browser checks for real alert hooks, dismiss/mute, timeouts, error deduplication, and connection cleanup. Chrome screenshots at desktop 1440 px and mobile 390 px verified loaded mascot images, notification bounds, and no horizontal overflow or uncaught JavaScript errors.
- Search frontend checks passed nine Node behavior groups plus desktop/mobile browser checks for citations, safe links, honest failures, loading, and pending-query/credential changes. Fifteen live browser checks verified missing/invalid keys and native form validation.
- Authenticated live `/api/search` verification produced a checked Google link in 13.665 ms, blocked a nested encoded secret without releasing a link, and redacted an encoded email before generating a Google query. These are local observations, not performance guarantees.
- Live Wikipedia access was unavailable: a separate public API reachability check returned HTTP 403 with a non-JSON body. The actual running search endpoint returned `BLOCK` / `SEARCH_UNAVAILABLE`, withheld the answer, and retained the independent guarded Google option. Successful article rendering and caching were verified using isolated test responses; a successful public Wikipedia response was not demonstrated here.
- Deterministic gateway telemetry: mean 9.66 ms and maximum 14.73 ms across 20 evaluations, including SQLite work. These are local observations, not performance guarantees.

HTTP adapter tests use actual local HTTP and HTTPS servers. An injected connector routes the policy-approved test address to a local ephemeral server while the real transport sends requests and verifies TLS certificates for the original hostname. Production uses the default connector and checked DNS addresses. Tests also cover rejected private or mixed DNS answers, redirects, deadlines, request and response size limits, and certificate or hostname failures.

Ollama inference was not exercised against an installed model in this environment. Provider tests validate the native HTTP contract and guarded tool-call loop with isolated provider responses; unavailable-model behavior is verified to block without producing a canned answer. Install and start Ollama with an allowed model to use live chat.

Docker configuration is supplied but was not executed here.
