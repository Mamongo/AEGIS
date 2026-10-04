import re
import unicodedata
from app.models import finding

RULES = {
    "instruction_override": r"ignore\s+(?:all\s+|previous\s+|prior\s+)?instructions|disregard.{0,30}(?:instructions|rules)",
    "system_disclosure": r"reveal.{0,30}system\s+prompt|(?:developer\s+message|act\s+as\s+system).{0,30}(?:override)?",
    "guardrail_bypass": r"(?:bypass|disable|turn\s+off).{0,30}(?:security|guardrails|controls|policy)",
    "hidden_instruction": r"hidden\s+instructions|execute\s+tool\s+regardless\s+of\s+policy",
    "exfiltration": r"exfiltrat\w*|(?:send|transmit|upload).{0,60}(?:secrets?|passwords?|credentials?).{0,100}(?:https?://|extern|outside)",
}


def normalize(text):
    return " ".join(unicodedata.normalize("NFKC", text).replace("\u200b", "").lower().split())


def score(text):
    text = normalize(text)
    matches = [name for name, pattern in RULES.items() if re.search(pattern, text)]
    value = .9 if matches else 0
    # Co-occurrence adds intent signals beyond exact phrases.
    authority = bool(re.search(r"system|developer|administrator|highest priority", text))
    imperative = bool(re.search(r"obey|override|forget|instead|must|replace", text))
    sensitive = bool(re.search(r"credentials?|passwords?|secrets?|tokens?", text))
    transfer = bool(re.search(r"send|copy|upload|transmit|deliver", text))
    external = bool(re.search(r"https?://|external|outside|remote", text))
    if authority and imperative:
        value = max(value, .55)
    if sensitive and transfer:
        value = max(value, .55 + (.35 if external else 0))
        matches.append("sensitive_transfer_intent")
    return min(1, value + .03 * max(0, len(matches) - 1)), matches


def inspect(text, config):
    value, matches = score(text)
    if not config.enabled or value == 0:
        return [], value
    action = config.action.upper() if value >= config.deterministic_threshold else "WARN"
    return [finding("prompt_injection", "SEC-INJECTION-001", "Instruction/intent signals: " + ", ".join(matches or ["authority manipulation"]),
                    action, "critical" if action == "BLOCK" else "medium", value)], value
