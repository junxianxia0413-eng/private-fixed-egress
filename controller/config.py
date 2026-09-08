import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    database_path: Path = ROOT / "database/controller.db"
    public_url: str = "http://127.0.0.1:8000"
    environment: str = "development"
    session_hours: int = 8

    def __post_init__(self):
        url = urlsplit(self.public_url)
        if self.environment not in {"development", "production", "test"}:
            raise ValueError("Invalid APP_ENV")
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
            or url.path
            or url.query
            or url.fragment
        ):
            raise ValueError("PUBLIC_URL must be an origin without path or credentials")
        if self.environment == "production" and url.scheme != "https":
            raise ValueError("Production requires HTTPS")
        if self.environment == "development" and url.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("Development requires a loopback PUBLIC_URL")
        if not 1 <= self.session_hours <= 24:
            raise ValueError("SESSION_HOURS must be between 1 and 24")

    @property
    def secure(self):
        return self.public_url.startswith("https://")

    @property
    def cookie_name(self):
        return "__Host-pfem_session" if self.secure else "pfem_session"

    @property
    def hostname(self):
        return urlsplit(self.public_url).hostname

    @classmethod
    def from_env(cls):
        values = {**dotenv_values(ROOT / ".env"), **os.environ}
        path = Path(values.get("DATABASE_PATH", "database/controller.db"))
        return cls(
            database_path=path if path.is_absolute() else ROOT / path,
            public_url=values.get("PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/"),
            environment=values.get("APP_ENV", "development"),
            session_hours=int(values.get("SESSION_HOURS", "8")),
        )
