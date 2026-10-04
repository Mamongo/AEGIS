"""One-command local setup and launch: python run.py (Windows), python3 run.py (Unix)."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import venv
import secrets

ROOT = Path(__file__).resolve().parent
ENV = ROOT / ".venv"
PYTHON = ENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def load_environment():
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def initialize():
    """Create private local credentials without overwriting operator configuration."""
    env_file = ROOT / ".env"
    if env_file.exists():
        print("Existing .env preserved. Configure API_KEYS_JSON and ADMIN_TOKEN there.", flush=True)
        return
    principal = {"id": "local-user", "role": "admin", "tenant": "local", "agents": ["support-agent"]}
    configured_keys = os.getenv("API_KEYS_JSON") or json.dumps({secrets.token_urlsafe(32): principal}, separators=(",", ":"))
    configured_admin = os.getenv("ADMIN_TOKEN") or secrets.token_urlsafe(32)
    with env_file.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(
            "# Private credentials. Do not commit this file.\n"
            f"API_KEYS_JSON={configured_keys}\n"
            f"ADMIN_TOKEN={configured_admin}\n"
            "OLLAMA_BASE_URL=http://localhost:11434\n"
            "OLLAMA_MODEL=qwen3:4b\n"
            "OLLAMA_TIMEOUT=60\n"
            "SEMANTIC_ENABLED=true\n"
            "HTTP_TIMEOUT=10\n"
            "HTTP_MAX_RESPONSE_BYTES=1048576\n"
            "HTTP_MAX_REQUEST_BYTES=1048576\n"
        )
    print("Created .env with local API and operator credentials. Open .env to connect the dashboard.", flush=True)


def main():
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11 or newer is required")
    command = sys.argv[1] if len(sys.argv) > 1 else "run"
    if command not in {"run", "test", "init", "smoke"}:
        raise SystemExit("Usage: python run.py [run|test|init|smoke]")
    if command == "init":
        initialize()
        return
    if command == "run" and not (ROOT / ".env").exists():
        initialize()
    if not PYTHON.exists():
        print("Creating project virtual environment…", flush=True)
        venv.create(ENV, with_pip=True)
    digest = hashlib.sha256((ROOT / "requirements.txt").read_bytes()).hexdigest()
    marker = ENV / ".requirements-sha256"
    if not marker.exists() or marker.read_text() != digest:
        subprocess.run([str(PYTHON), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")], check=True, cwd=ROOT)
        marker.write_text(digest)
    # Existing environment values take precedence over the private local file.
    load_environment()
    if command == "test":
        args = ["-m", "pytest", "-q", "-s"]
    elif command == "smoke":
        args = [str(ROOT / "scripts/smoke_test.py")]
    elif command == "run":
        args = ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"]
    try:
        raise SystemExit(subprocess.call([str(PYTHON), *args], cwd=ROOT))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
