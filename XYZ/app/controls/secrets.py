import re
from app.models import finding

PATTERNS = {
    "AWS_KEY": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "GITHUB_TOKEN": r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
    "API_KEY": r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*[\"']?[^\s\"',;]{8,}",
    "BEARER": r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*",
    "JWT": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$)",
    "PASSWORD": r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"',;]+",
}
COMPILED = {key: re.compile(value) for key, value in PATTERNS.items()}


def redact(text):
    for name, pattern in COMPILED.items():
        text = pattern.sub(f"[REDACTED_{name}]", text)
    return text


def inspect(text, action="block"):
    matches = [name for name, pattern in COMPILED.items() if pattern.search(text)]
    return ([finding("secret_detection", "SEC-SECRET-001", "Credential-like material detected: " + ", ".join(matches),
                     action.upper(), "critical")] if matches else []), redact(text)
