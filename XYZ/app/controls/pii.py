import re
import ipaddress
from app.models import finding

PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "IPV4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "PESEL": re.compile(r"(?<!\d)\d{11}(?!\d)"),
    "CREDIT_CARD": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
    "PHONE": re.compile(r"(?<!\w)(?:\+\d{1,3}[ -]?)?(?:\(\d{3}\)[ -]?\d{3}[ -]?\d{4}|\d{3}[ -]\d{3}[ -]\d{3,4})(?!\d)"),
}


def valid(kind, value):
    if kind == "IPV4":
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False
    if kind == "CREDIT_CARD":
        digits = [int(c) for c in value if c.isdigit()]
        if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
            return False
        checksum = sum((d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2))
                       for i, d in enumerate(reversed(digits)))
        return checksum % 10 == 0
    return True


def inspect(text, action="redact"):
    detected = set()
    for kind, pattern in PATTERNS.items():
        def replace(match):
            if valid(kind, match.group()):
                detected.add(kind)
                return f"[REDACTED_{kind}]" if action == "redact" else match.group()
            return match.group()
        text = pattern.sub(replace, text)
    return ([finding("pii", "SEC-PII-001", "Personal data detected: " + ", ".join(sorted(detected)),
                     action.upper(), "medium")] if detected else []), text


def redact(text):
    return inspect(text)[1]
