import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from controller.config import ROOT
from controller.services.auth import (
    authenticate,
    create_session,
    get_session,
    revoke_session,
)
from controller.services.database import connect

router = APIRouter()
templates = Jinja2Templates(directory=ROOT / "controller/templates")


def session_for(request):
    settings = request.app.state.settings
    return get_session(settings, request.cookies.get(settings.cookie_name))


def cookie(response, settings, token, ttl):
    response.set_cookie(
        settings.cookie_name,
        token,
        max_age=ttl,
        httponly=True,
        secure=settings.secure,
        samesite="strict",
        path="/",
    )


def check_csrf(request, session, token):
    origin = request.headers.get("origin")
    if origin and origin != request.app.state.settings.public_url:
        raise HTTPException(403, "Invalid request origin")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Cross-site request blocked")
    if not session or not secrets.compare_digest(session["csrf_token"].encode(), token.encode()):
        raise HTTPException(403, "Invalid or expired form; reload the page")


@router.get("/login")
def login_page(request: Request):
    settings = request.app.state.settings
    session = session_for(request)
    if session and session["admin_id"]:
        return RedirectResponse("/", status_code=303)
    with connect(settings.database_path) as db:
        ready = db.execute("SELECT id FROM administrator").fetchone() is not None
    if not ready:
        return templates.TemplateResponse(
            request=request,
            name="setup.html",
            context={},
            status_code=503,
        )
    new_session = None
    if not session:
        new_session = create_session(settings)
        csrf = new_session[1]
    else:
        csrf = session["csrf_token"]
    response = templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"csrf": csrf, "error": None},
    )
    if new_session:
        cookie(response, settings, new_session[0], new_session[2])
    return response


@router.post("/login")
async def login(request: Request):
    settings = request.app.state.settings
    form = await request.form(max_fields=4, max_files=0)
    csrf, username, password = (form.get(k, "") for k in ("csrf", "username", "password"))
    if not all(isinstance(value, str) for value in (csrf, username, password)):
        raise HTTPException(400, "Invalid form")
    session = session_for(request)
    check_csrf(request, session, csrf)
    if len(username) > 64 or len(password) > 256:
        raise HTTPException(400, "Invalid credentials length")
    result, new_session = await run_in_threadpool(
        authenticate,
        settings,
        request.client.host if request.client else "unknown",
        username,
        password,
        request.cookies[settings.cookie_name],
    )
    if result != "ok":
        limited = result == "limited"
        response = templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "csrf": csrf,
                "error": (
                    "尝试次数过多，请在 15 分钟后重试。" if limited else "用户名或密码不正确。"
                ),
            },
            status_code=429 if limited else 401,
        )
        if limited:
            response.headers["Retry-After"] = "900"
        return response
    response = RedirectResponse("/", status_code=303)
    cookie(response, settings, new_session[0], new_session[2])
    return response


@router.post("/logout")
async def logout(request: Request):
    settings = request.app.state.settings
    session = session_for(request)
    form = await request.form(max_fields=2, max_files=0)
    token = form.get("csrf", "")
    if not isinstance(token, str):
        raise HTTPException(400, "Invalid form")
    check_csrf(request, session, token)
    revoke_session(
        settings, request.cookies[settings.cookie_name], session["username"] or "anonymous"
    )
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(settings.cookie_name, path="/", secure=settings.secure, httponly=True)
    return response


@router.get("/")
def overview(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        return RedirectResponse("/login", status_code=303)
    settings = request.app.state.settings
    with connect(settings.database_path) as db:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        gateway_count = db.execute("SELECT COUNT(*) FROM gateways").fetchone()[0]
        events = [
            dict(row)
            for row in db.execute(
                "SELECT occurred_at, actor, action FROM audit_events ORDER BY id DESC LIMIT 8"
            )
        ]
    for event in events:
        event["time"] = datetime.fromtimestamp(event["occurred_at"], UTC).strftime(
            "%m-%d %H:%M UTC"
        )
    return templates.TemplateResponse(
        request=request,
        name="overview.html",
        context={
            "csrf": session["csrf_token"],
            "username": session["username"],
            "version": version,
            "gateway_count": gateway_count,
            "events": events,
            "environment": settings.environment,
        },
    )
