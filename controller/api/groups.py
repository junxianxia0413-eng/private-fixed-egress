from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from controller.api.dashboard import session_for, templates
from controller.api.gateways import authenticated_form
from controller.services import groups
from controller.services.database import connect

router = APIRouter()


def page(request, session, error=None, status_code=200, confirmation=None):
    settings = request.app.state.settings
    with connect(settings.database_path) as db:
        devices = [dict(r) for r in db.execute("SELECT id,name FROM devices ORDER BY name")]
        exits = [dict(r) for r in db.execute("SELECT id,name FROM exit_groups WHERE applied=1")]
    return templates.TemplateResponse(
        request=request,
        name="groups.html",
        status_code=status_code,
        context={
            "username": session["username"],
            "csrf": session["csrf_token"],
            "active": "groups",
            "groups": groups.snapshot(settings),
            "devices": devices,
            "exits": exits,
            "error": error,
            "confirmation": confirmation,
        },
    )


@router.get("/groups")
def list_groups(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        return RedirectResponse("/login", status_code=303)
    return page(request, session)


@router.get("/api/groups")
def status(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        raise HTTPException(401, "请先登录。")
    return {"groups": groups.snapshot(request.app.state.settings)}


@router.post("/groups/add")
async def add(request: Request):
    session, form = await authenticated_form(request)
    try:
        groups.register(request.app.state.settings, form, session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/groups", status_code=303)


@router.post("/groups/{identifier}/change")
async def change(request: Request, identifier: int):
    session, form = await authenticated_form(request)
    try:
        confirmation = groups.prepare_change(
            request.app.state.settings, identifier, form.get("exit_id", ""), session["username"]
        )
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return page(request, session, confirmation=confirmation)


@router.post("/groups/{identifier}/edit")
async def edit(request: Request, identifier: int):
    session, form = await authenticated_form(request)
    try:
        groups.update(request.app.state.settings, identifier, form, session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/groups", status_code=303)


@router.post("/groups/{identifier}/confirm")
async def confirm(request: Request, identifier: int):
    session, form = await authenticated_form(request)
    try:
        groups.confirm_change(
            request.app.state.settings,
            identifier,
            form.get("confirmation", ""),
            session["username"],
        )
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/groups", status_code=303)
