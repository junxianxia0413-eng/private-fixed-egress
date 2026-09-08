"""Append migrations; never rewrite an applied migration."""

MIGRATIONS = [
    [
        """CREATE TABLE administrator (
        id INTEGER PRIMARY KEY CHECK (id = 1), username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL, created_at INTEGER NOT NULL)""",
        """CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY, admin_id INTEGER REFERENCES administrator(id),
        csrf_token TEXT NOT NULL, expires_at INTEGER NOT NULL)""",
        "CREATE INDEX session_expiry ON sessions(expires_at)",
        """CREATE TABLE login_attempts (
        id INTEGER PRIMARY KEY, source TEXT NOT NULL, attempted_at INTEGER NOT NULL)""",
        "CREATE INDEX attempt_window ON login_attempts(attempted_at)",
        """CREATE TABLE audit_events (
        id INTEGER PRIMARY KEY, occurred_at INTEGER NOT NULL, actor TEXT NOT NULL,
        action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')""",
    ]
]
