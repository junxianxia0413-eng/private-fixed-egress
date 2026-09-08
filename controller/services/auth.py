import hashlib
import secrets
import time
from threading import BoundedSemaphore

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from controller.services.database import audit, connect

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_HASH = HASHER.hash(secrets.token_urlsafe(32))
LOGIN_WINDOW = 900
SOURCE_LIMIT = 5
GLOBAL_LIMIT = 30
PASSWORD_SLOTS = BoundedSemaphore(2)


def digest(token: str):
    return hashlib.sha256(token.encode()).hexdigest()


def set_administrator(settings, username: str, password: str, *, reset=False):
    if not 1 <= len(username) <= 64 or any(ord(c) < 33 for c in username):
        raise ValueError("Username must be 1–64 characters without whitespace")
    if not 14 <= len(password) <= 256:
        raise ValueError("Password must contain 14–256 characters")
    password_hash = HASHER.hash(password)
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute("SELECT id FROM administrator").fetchone()
        if existing and not reset:
            raise ValueError("Administrator already exists; use --reset-admin explicitly")
        db.execute(
            """INSERT INTO administrator VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET username=excluded.username,
            password_hash=excluded.password_hash""",
            (username, password_hash, int(time.time())),
        )
        db.execute("DELETE FROM sessions")
        db.execute("DELETE FROM login_attempts")
        audit(db, username, "admin.reset" if existing else "admin.created")


def get_session(settings, token: str | None):
    if not token or len(token) > 128:
        return None
    with connect(settings.database_path) as db:
        row = db.execute(
            """SELECT s.*, a.username FROM sessions s
            LEFT JOIN administrator a ON a.id=s.admin_id
            WHERE token_hash=? AND expires_at>?""",
            (digest(token), int(time.time())),
        ).fetchone()
        return dict(row) if row else None


def insert_session(db, settings, admin_id=None, old_token=None):
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    ttl = settings.session_hours * 3600 if admin_id else 1800
    db.execute("DELETE FROM sessions WHERE expires_at<=?", (int(time.time()),))
    if old_token:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (digest(old_token),))
    db.execute(
        "INSERT INTO sessions VALUES (?, ?, ?, ?)",
        (digest(token), admin_id, csrf, int(time.time()) + ttl),
    )
    return token, csrf, ttl


def create_session(settings):
    with connect(settings.database_path) as db:
        return insert_session(db, settings)


def authenticate(settings, source: str, username: str, password: str, old_token: str):
    now = int(time.time())
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM login_attempts WHERE attempted_at<=?", (now - LOGIN_WINDOW,))
        total = db.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0]
        count = db.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE source=?", (source,)
        ).fetchone()[0]
        if total >= GLOBAL_LIMIT or count >= SOURCE_LIMIT:
            return "limited", None
        db.execute("INSERT INTO login_attempts(source, attempted_at) VALUES (?, ?)", (source, now))
        row = db.execute("SELECT * FROM administrator WHERE id=1").fetchone()
        snapshot = dict(row) if row else None
    matching = snapshot is not None and secrets.compare_digest(
        username.encode(), snapshot["username"].encode()
    )
    try:
        with PASSWORD_SLOTS:
            valid = HASHER.verify(snapshot["password_hash"] if matching else DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        valid = False
    if valid and matching:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT password_hash FROM administrator WHERE id=1").fetchone()
            if not current or current[0] != snapshot["password_hash"]:
                return "invalid", None
            db.execute("DELETE FROM login_attempts WHERE source=?", (source,))
            session = insert_session(db, settings, admin_id=1, old_token=old_token)
            audit(db, snapshot["username"], "auth.login")
        return "ok", session
    with connect(settings.database_path) as db:
        audit(db, "anonymous", "auth.failed")
    return "invalid", None


def revoke_session(settings, token: str, actor: str):
    with connect(settings.database_path) as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (digest(token),))
        audit(db, actor, "auth.logout")
