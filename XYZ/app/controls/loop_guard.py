import hashlib
import json


def fingerprint(tool):
    return hashlib.sha256(json.dumps(tool.model_dump(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
