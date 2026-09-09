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
    ],
    [
        """CREATE TABLE gateways (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, host TEXT NOT NULL,
            ssh_port INTEGER NOT NULL CHECK(ssh_port BETWEEN 1 AND 65535),
            location TEXT NOT NULL DEFAULT '', bootstrap_user TEXT NOT NULL,
            host_key TEXT NOT NULL, bootstrap_ref TEXT, managed_ref TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW', last_error TEXT NOT NULL DEFAULT '',
            health_json TEXT NOT NULL DEFAULT '{}', checked_at INTEGER,
            created_at INTEGER NOT NULL, UNIQUE(host, ssh_port)
        )""",
        """CREATE TABLE gateway_jobs (
            id INTEGER PRIMARY KEY, gateway_id INTEGER NOT NULL REFERENCES gateways(id),
            kind TEXT NOT NULL CHECK(kind IN ('deploy','check','restart')),
            state TEXT NOT NULL DEFAULT 'QUEUED', actor TEXT NOT NULL,
            stage TEXT NOT NULL DEFAULT 'QUEUED', error TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER
        )""",
        """CREATE UNIQUE INDEX one_gateway_job ON gateway_jobs(gateway_id)
            WHERE state IN ('QUEUED','RUNNING')""",
    ],
]
