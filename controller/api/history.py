import json
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from controller.api.dashboard import session_for, templates
from controller.services import alerts
from controller.services.database import connect

router = APIRouter()


@router.get("/history")
def history(request: Request, page: int = 1):
    session = session_for(request)
    if not session or not session["admin_id"]:
        return RedirectResponse("/login", status_code=303)
    page = max(1, min(page, 1000))
    with connect(request.app.state.settings.database_path) as db:
        rows = [
            dict(row)
            for row in db.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT 50 OFFSET ?", ((page - 1) * 50,)
            )
        ]
    for row in rows:
        row["time"] = datetime.fromtimestamp(row["occurred_at"], UTC).strftime("%Y-%m-%d %H:%M UTC")
        try:
            row["detail_view"] = json.dumps(json.loads(row["detail"]), ensure_ascii=False, indent=2)
        except (TypeError, ValueError):
            row["detail_view"] = row["detail"]
    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context={
            "username": session["username"],
            "csrf": session["csrf_token"],
            "active": "history",
            "events": rows,
            "page": page,
        },
    )


@router.get("/api/history")
def history_api(request: Request, page: int = 1):
    session = session_for(request)
    if not session or not session["admin_id"]:
        raise HTTPException(401, "请先登录。")
    page = max(1, min(page, 1000))
    with connect(request.app.state.settings.database_path) as db:
        rows = [
            dict(row)
            for row in db.execute(
                "SELECT occurred_at,actor,action,detail FROM audit_events "
                "ORDER BY id DESC LIMIT 50 OFFSET ?",
                ((page - 1) * 50,),
            )
        ]
    return {"events": rows, "page": page}


@router.get("/alerts")
def alert_page(request: Request, resolved: int = 0):
    session = session_for(request)
    if not session or not session["admin_id"]:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "username": session["username"],
            "csrf": session["csrf_token"],
            "active": "alerts",
            "alerts": alerts.snapshot(request.app.state.settings, bool(resolved)),
            "resolved": bool(resolved),
        },
    )


@router.get("/api/alerts")
def alert_api(request: Request, resolved: int = 0):
    session = session_for(request)
    if not session or not session["admin_id"]:
        raise HTTPException(401, "请先登录。")
    return {"alerts": alerts.snapshot(request.app.state.settings, bool(resolved))}
