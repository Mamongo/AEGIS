import os
from pathlib import Path
from dataclasses import dataclass, field
import json

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    policy_path: Path = ROOT / "policies/policy.yaml"
    signature_path: Path = ROOT / "signatures/attacks.yaml"
    database_path: Path = ROOT / "data/control.db"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3:4b"
    ollama_timeout: float = 60.0
    semantic_enabled: bool = True
    admin_token: str = ""
    api_keys: dict = field(default_factory=dict)
    http_timeout: float = 10.0
    http_max_response_bytes: int = 1048576
    http_max_request_bytes: int = 1048576

    @classmethod
    def from_env(cls):
        return cls(
            policy_path=Path(os.getenv("POLICY_PATH", str(ROOT / "policies/policy.yaml"))),
            signature_path=Path(os.getenv("SIGNATURE_PATH", str(ROOT / "signatures/attacks.yaml"))),
            database_path=Path(os.getenv("DATABASE_PATH", str(ROOT / "data/control.db"))),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            ollama_model=os.getenv("OLLAMA_MODEL", "qwen3:4b"),
            ollama_timeout=float(os.getenv("OLLAMA_TIMEOUT", "60")),
            semantic_enabled=os.getenv("SEMANTIC_ENABLED", "true").lower() == "true",
            admin_token=os.getenv("ADMIN_TOKEN", ""),
            api_keys=cls._api_keys(),
            http_timeout=float(os.getenv("HTTP_TIMEOUT", "10")),
            http_max_response_bytes=int(os.getenv("HTTP_MAX_RESPONSE_BYTES", "1048576")),
            http_max_request_bytes=int(os.getenv("HTTP_MAX_REQUEST_BYTES", "1048576")),
        )

    @staticmethod
    def _api_keys():
        try:
            value = json.loads(os.getenv("API_KEYS_JSON", "{}"))
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (ValueError, TypeError):
            raise ValueError("API_KEYS_JSON must be a JSON object of API keys and trusted identities") from None
