import hashlib
import threading
import yaml
from app.policy.schema import Policy


class ValidatedLoader:
    """Content-hash reload, atomic activation, last-known-good on any validation failure."""
    def __init__(self, path, schema, callback=None):
        self.path, self.schema, self.callback = path, schema, callback
        self.lock = threading.RLock()
        self.active = None
        self.version = 0
        self.digest = None
        self.error = None
        if not self.reload(force=True):
            raise ValueError(f"Initial configuration invalid: {self.error}")

    def reload(self, force=False):
        with self.lock:
            try:
                raw = self.path.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                if digest == self.digest and not force:
                    return False
                candidate = self.schema.model_validate(yaml.safe_load(raw))
            except Exception as exc:
                # Do not echo YAML values (configuration can contain sensitive data).
                self.error = f"Configuration rejected ({type(exc).__name__}); last-known-good retained"
                return False
            if digest == self.digest:
                self.error = None
                return False
            next_version = max(self.version + 1, candidate.version)
            if self.callback:
                self.callback(next_version)  # audit must succeed before activation
            self.active, self.digest, self.version = candidate, digest, next_version
            self.error = None
            return True

    def snapshot(self):
        with self.lock:
            self.reload()
            return self.active.model_copy(deep=True), self.version


class PolicyLoader(ValidatedLoader):
    def __init__(self, path, callback=None):
        super().__init__(path, Policy, callback)
