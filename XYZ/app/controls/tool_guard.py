import json
from urllib.parse import parse_qsl, unquote, unquote_plus, urlsplit
from pydantic import ValidationError
from app.models import Decision, finding
from app.tools.registry import SCHEMAS
from app.controls import authz, egress, secrets, pii, injection


SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "api_key", "token", "credentials", "authorization"}
BUSINESS_TEXT_FIELDS = {"summary", "description", "name", "email", "query"}


def inspect_url_payload(url, policy):
    """Inspect the sent path/query without treating the structural host as personal data."""
    try:
        parts = urlsplit(url)
    except ValueError:
        # The egress control reports malformed destinations separately.
        return []
    path, query = parts.path, parts.query
    findings, seen = [], set()
    while True:
        payload = path + "\n" + query
        checks, _ = secrets.inspect(payload)
        if any(key.lower() in SENSITIVE_KEYS for key, _ in parse_qsl(query, keep_blank_values=True)):
            checks.append(finding("secret_detection", "SEC-SECRET-002", "Credential fields in destination query", severity="critical"))
        if policy.controls.pii.enabled:
            pii_checks, _ = pii.inspect(payload, policy.controls.pii.input_action)
            if policy.controls.pii.input_action == "redact":
                for check in pii_checks:
                    check.decision = Decision.BLOCK
                    check.reason = "Personal data in destination path/query cannot be safely redacted"
            checks += pii_checks
        for check in checks:
            key = (check.rule_id, check.decision, check.reason)
            if key not in seen:
                seen.add(key)
                findings.append(check)
        decoded_path, decoded_query = unquote(path), unquote_plus(query)
        if (decoded_path, decoded_query) == (path, query):
            return findings
        # Decoding only shortens or preserves these bounded URL components, so
        # even nested encodings reach a fixed point without an arbitrary depth gap.
        path, query = decoded_path, decoded_query


def inspect(ctx, policy):
    if ctx.tool.name not in SCHEMAS:
        return [finding("tool_schema", "UNKNOWN_TOOL", "Unknown tool; no executable adapter registered")], None
    try:
        parsed = SCHEMAS[ctx.tool.name].model_validate(ctx.tool.arguments)
        args = parsed.model_dump(exclude_none=True)
    except ValidationError:
        return [finding("tool_schema", "INVALID_TOOL_ARGUMENTS", "Tool arguments do not conform to the registered schema")], None
    results = authz.inspect(ctx, policy, args)
    if ctx.tool.name == "web.search":
        # Search engines interpret percent-encoded text. Inspect each decoded
        # layer and redact the query before it becomes a provider request or link.
        decoded, seen = args["query"], set()
        while decoded not in seen:
            seen.add(decoded)
            checks, _ = secrets.inspect(decoded)
            results.extend(checks)
            decoded = unquote(decoded)
        args["query"] = decoded
        checks, _ = injection.inspect(decoded, policy.controls.prompt_injection)
        results.extend(checks)
    # Broker DLP also covers structured payloads, regardless of user prompt wording.
    structured = json.dumps(args)
    def contains_secret_key(value):
        if isinstance(value, dict):
            return any(str(k).lower() in SENSITIVE_KEYS or contains_secret_key(v) for k, v in value.items())
        if isinstance(value, list):
            return any(contains_secret_key(v) for v in value)
        return False
    secret_findings, _ = secrets.inspect(structured)
    results.extend(secret_findings)
    if contains_secret_key(args.get("data")):
        results.append(finding("secret_detection", "SEC-SECRET-002", "Credential fields in outbound payload", severity="critical"))
    # Apply input policy before business text reaches persistent storage.
    if policy.controls.pii.enabled:
        for field in BUSINESS_TEXT_FIELDS & args.keys():
            checks, cleaned = pii.inspect(args[field], policy.controls.pii.input_action)
            results.extend(checks)
            if policy.controls.pii.input_action == "redact":
                args[field] = cleaned
    # Scan HTTP bodies separately so structural fields retain their schemas.
    if "data" in args and policy.controls.pii.enabled:
        raw_data = json.dumps(args["data"])
        checks, cleaned = pii.inspect(raw_data, policy.controls.pii.input_action)
        results.extend(checks)
        if policy.controls.pii.input_action == "redact":
            args["data"] = json.loads(cleaned)
    if ctx.tool.name.startswith("http."):
        results.extend(inspect_url_payload(args["url"], policy))
        rule = policy.tools.allow.get(ctx.tool.name)
        results.extend(egress.inspect(args["url"], policy, rule.domains if rule else None))
        if ctx.destination and ctx.destination != args["url"]:
            results.append(finding("egress", "SEC-EGRESS-002", "Envelope destination differs from actual tool destination"))
    try:
        # Redaction can expand text; validate the exact arguments the adapter receives.
        args = SCHEMAS[ctx.tool.name].model_validate(args).model_dump(exclude_none=True)
    except ValidationError:
        results.append(finding("tool_schema", "INVALID_TOOL_ARGUMENTS", "Sanitized tool arguments do not conform to the registered schema"))
        return results, None
    return results, args
