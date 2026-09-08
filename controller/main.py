"""Phase 0 runnable baseline; authentication is added in Phase 1."""

import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

ROOT = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    (ROOT / "database").mkdir(exist_ok=True)
    with sqlite3.connect(ROOT / "database" / "controller.db") as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("SELECT 1")
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/", response_class=HTMLResponse)
def overview():
    return "<h1>Private Network</h1><p>System Online</p><p>Phase 0: local baseline only.</p>"


@app.get("/healthz")
def health():
    with sqlite3.connect(ROOT / "database" / "controller.db") as db:
        db.execute("SELECT 1")
    return {"status": "ok", "component": "controller"}

