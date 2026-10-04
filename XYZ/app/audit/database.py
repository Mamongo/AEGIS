import sqlite3
from contextlib import contextmanager


class Database:
    def __init__(self, path):
        self.path = str(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, request_id TEXT,
                    session_id TEXT, user_id TEXT, tenant TEXT, agent_id TEXT, model TEXT,
                    control TEXT, rule_id TEXT, decision TEXT, severity TEXT, reason TEXT,
                    tool TEXT, policy_version INTEGER, latency_ms REAL, tokens INTEGER,
                    budget_usage TEXT, details TEXT
                );
                CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
                CREATE TABLE IF NOT EXISTS usage (
                    id TEXT PRIMARY KEY, user_id TEXT, tenant TEXT, agent_id TEXT,
                    started REAL, requests INTEGER DEFAULT 1, steps INTEGER DEFAULT 0,
                    tool_calls INTEGER DEFAULT 0, tokens INTEGER DEFAULT 0,
                    compute_units INTEGER DEFAULT 0, actions TEXT DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS usage_time ON usage(started);
                CREATE TABLE IF NOT EXISTS interactions (
                    id INTEGER PRIMARY KEY, timestamp REAL, request_id TEXT, decision TEXT,
                    latency_ms REAL, deterministic_ms REAL, semantic_ms REAL, tokens INTEGER,
                    tool INTEGER, executed INTEGER
                );
                CREATE TABLE IF NOT EXISTS memory (
                    id TEXT PRIMARY KEY, tenant TEXT, user_id TEXT, agent_id TEXT,
                    content TEXT, provenance TEXT, created_at REAL, sensitivity TEXT,
                    trusted INTEGER, quarantined INTEGER
                );
                CREATE TABLE IF NOT EXISTS tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT CHECK(id <= 99999999),
                    tenant TEXT NOT NULL, summary TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open', 'in_progress', 'closed')),
                    created_by TEXT NOT NULL, created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS tickets_tenant ON tickets(tenant, id);
                CREATE TABLE IF NOT EXISTS employees (
                    id TEXT NOT NULL, tenant TEXT NOT NULL, name TEXT NOT NULL,
                    email TEXT NOT NULL, PRIMARY KEY(tenant, id)
                );
                CREATE INDEX IF NOT EXISTS employees_tenant ON employees(tenant);
            ''')

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
