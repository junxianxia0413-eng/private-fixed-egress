from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool

from controller.api.dashboard import session_for, templates
from controller.api.gateways import authenticated_form
from controller.services import isps
from controller.services.database import connect

router = APIRouter()


def page(request, session, error=None, status_code=200):
    settings = request.app.state.settings
    values, checks = isps.snapshot(settings)
    with connect(settings.database_path) as db:
        gateways = [dict(r) for r in db.execute("SELECT id,name FROM gateways ORDER BY id")]
    return templates.TemplateResponse(
        request=request,
        name="isps.html",
        status_code=status_code,
        context={
            "username": session["username"],
            "csrf": session["csrf_token"],
            "isps": values,
            "checks": checks,
            "gateways": gateways,
            "error": error,
            "active": "isps",
            "refresh_seconds": 1 if any(value["busy"] for value in values) else None,
        },
    )


@router.get("/isps")
def list_isps(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        return RedirectResponse("/login", status_code=303)
    return page(request, session)


@router.get("/api/isps")
def isp_status(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        raise HTTPException(401, "请先登录。")
    values, checks = isps.snapshot(request.app.state.settings)
    return {"isps": values, "checks": checks}


@router.post("/isps/add")
async def add_isp(request: Request):
    session, form = await authenticated_form(request)
    settings = request.app.state.settings
    try:
        identifier = await run_in_threadpool(isps.register, settings, form, session["username"])
        isps.enqueue(settings, identifier, session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/isps", status_code=303)


@router.post("/isps/{isp_id}/test")
async def test_isp(request: Request, isp_id: int):
    session, _ = await authenticated_form(request)
    try:
        isps.enqueue(request.app.state.settings, isp_id, session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/isps", status_code=303)


@router.post("/isps/{isp_id}/edit")
async def edit_isp(request: Request, isp_id: int):
    session, form = await authenticated_form(request)
    try:
        isps.rename(request.app.state.settings, isp_id, form.get("name", ""), session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/isps", status_code=303)
