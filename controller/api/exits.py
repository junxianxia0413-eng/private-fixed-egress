from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool

from controller.api.dashboard import session_for, templates
from controller.api.gateways import authenticated_form
from controller.services import exits
from controller.services.database import connect

router = APIRouter()


def page(request, session, error=None, status_code=200):
    settings = request.app.state.settings
    groups, jobs = exits.snapshot(settings)
    with connect(settings.database_path) as db:
        gateways = [
            dict(r)
            for r in db.execute(
                "SELECT id,name FROM gateways WHERE bootstrap_ref IS NULL ORDER BY id"
            )
        ]
        isps = [
            dict(r)
            for r in db.execute("SELECT id,name,expected_exit_ip FROM isp_exits ORDER BY id")
        ]
    return templates.TemplateResponse(
        request=request,
        name="exits.html",
        status_code=status_code,
        context={
            "username": session["username"],
            "csrf": session["csrf_token"],
            "groups": groups,
            "jobs": jobs,
            "gateways": gateways,
            "isps": isps,
            "error": error,
            "active": "exits",
            "refresh_seconds": 2 if any(value["busy"] for value in groups) else None,
        },
    )


@router.get("/exits")
def list_exits(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        return RedirectResponse("/login", status_code=303)
    return page(request, session)


@router.get("/api/exits")
def exit_status(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        raise HTTPException(401, "请先登录。")
    groups, jobs = exits.snapshot(request.app.state.settings)
    return {"groups": groups, "jobs": jobs}


@router.post("/exits/add")
async def add_exit(request: Request):
    session, form = await authenticated_form(request)
    settings = request.app.state.settings
    try:
        identifier = await run_in_threadpool(exits.register, settings, form, session["username"])
        exits.enqueue(settings, identifier, session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/exits", status_code=303)


@router.post("/exits/{group_id}/apply")
async def apply_exit(request: Request, group_id: int):
    session, _ = await authenticated_form(request)
    try:
        exits.enqueue(request.app.state.settings, group_id, session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/exits", status_code=303)
