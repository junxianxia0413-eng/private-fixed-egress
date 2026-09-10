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
    [
        """CREATE TABLE isp_exits (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, host TEXT NOT NULL,
            port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535), secret_ref TEXT NOT NULL,
            gateway_id INTEGER NOT NULL REFERENCES gateways(id), country TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '', provider TEXT NOT NULL DEFAULT '', expires_on TEXT,
            expected_exit_ip TEXT, current_exit_ip TEXT, latency_ms REAL,
            status TEXT NOT NULL DEFAULT 'NEW', last_error TEXT NOT NULL DEFAULT '',
            tested_at INTEGER, created_at INTEGER NOT NULL
        )""",
        """CREATE TRIGGER immutable_exit_identity BEFORE UPDATE OF expected_exit_ip ON isp_exits
            WHEN OLD.expected_exit_ip IS NOT NULL
            AND NEW.expected_exit_ip IS NOT OLD.expected_exit_ip
            BEGIN SELECT RAISE(ABORT, 'Exit identity is immutable'); END""",
        """CREATE TABLE isp_jobs (
            id INTEGER PRIMARY KEY, isp_id INTEGER NOT NULL REFERENCES isp_exits(id),
            actor TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'QUEUED',
            error TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, finished_at INTEGER
        )""",
        """CREATE UNIQUE INDEX one_isp_job ON isp_jobs(isp_id)
            WHERE state IN ('QUEUED','RUNNING')""",
        """CREATE TABLE isp_checks (
            id INTEGER PRIMARY KEY, isp_id INTEGER NOT NULL REFERENCES isp_exits(id),
            gateway_id INTEGER NOT NULL REFERENCES gateways(id), occurred_at INTEGER NOT NULL,
            status TEXT NOT NULL, expected_ip TEXT, observed_ip TEXT, latency_ms REAL,
            error TEXT NOT NULL DEFAULT ''
        )""",
    ],
    [
        """CREATE TABLE exit_groups (
            id INTEGER PRIMARY KEY CHECK(id BETWEEN 1 AND 1000), name TEXT NOT NULL UNIQUE,
            gateway_id INTEGER NOT NULL REFERENCES gateways(id),
            isp_id INTEGER NOT NULL REFERENCES isp_exits(id), secret_ref TEXT NOT NULL,
            applied INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'NEW',
            last_error TEXT NOT NULL DEFAULT '', current_exit_ip TEXT, latency_ms REAL,
            checked_at INTEGER, config_hash TEXT, created_at INTEGER NOT NULL
        )""",
        """CREATE TABLE exit_jobs (
            id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES exit_groups(id),
            gateway_id INTEGER NOT NULL REFERENCES gateways(id), actor TEXT NOT NULL,
            transaction_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL DEFAULT 'QUEUED',
            stage TEXT NOT NULL DEFAULT 'QUEUED', error TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL, finished_at INTEGER
        )""",
        """CREATE UNIQUE INDEX one_exit_transaction ON exit_jobs(gateway_id)
            WHERE state IN ('QUEUED','RUNNING')""",
    ],
    [
        """CREATE TABLE devices (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, type TEXT NOT NULL DEFAULT '',
            platform TEXT NOT NULL, purpose TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        )""",
    ],
    [
        """CREATE TABLE subscription_groups (
            id INTEGER PRIMARY KEY CHECK(id BETWEEN 1 AND 1000), name TEXT NOT NULL UNIQUE,
            exit_id INTEGER NOT NULL REFERENCES exit_groups(id),
            state TEXT NOT NULL DEFAULT 'PENDING',
            created_at INTEGER NOT NULL
        )""",
        """CREATE TABLE group_devices (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id),
            group_id INTEGER NOT NULL REFERENCES subscription_groups(id),
            slot INTEGER NOT NULL CHECK(slot IN (1,2)), UNIQUE(group_id,slot)
        )""",
        """CREATE TABLE group_confirmations (
            token_hash TEXT PRIMARY KEY,
            group_id INTEGER NOT NULL REFERENCES subscription_groups(id),
            old_exit_id INTEGER NOT NULL REFERENCES exit_groups(id),
            new_exit_id INTEGER NOT NULL REFERENCES exit_groups(id), actor TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )""",
    ],
    [
        "ALTER TABLE subscription_groups ADD COLUMN client_ref TEXT",
        "ALTER TABLE subscription_groups ADD COLUMN token_ref TEXT",
        "ALTER TABLE subscription_groups ADD COLUMN token_hash TEXT",
        "ALTER TABLE subscription_groups ADD COLUMN deployed_exit_id "
        "INTEGER REFERENCES exit_groups(id)",
        "CREATE UNIQUE INDEX unique_subscription_token ON subscription_groups(token_hash)",
    ],
    [
        """CREATE TABLE monitor_jobs (
            id INTEGER PRIMARY KEY, gateway_id INTEGER NOT NULL REFERENCES gateways(id),
            kind TEXT NOT NULL CHECK(kind IN ('health','quality')),
            state TEXT NOT NULL DEFAULT 'QUEUED', error TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL, finished_at INTEGER
        )""",
        """CREATE UNIQUE INDEX one_monitor_job ON monitor_jobs(gateway_id,kind)
            WHERE state IN ('QUEUED','RUNNING')""",
        """CREATE TABLE monitor_samples (
            id INTEGER PRIMARY KEY, gateway_id INTEGER NOT NULL REFERENCES gateways(id),
            kind TEXT NOT NULL, occurred_at INTEGER NOT NULL, healthy INTEGER NOT NULL,
            data_json TEXT NOT NULL
        )""",
        "CREATE INDEX monitor_sample_lookup ON monitor_samples(gateway_id,kind,occurred_at)",
    ],
]
