from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from controller.api.dashboard import session_for, templates
from controller.api.gateways import authenticated_form
from controller.services import devices

router = APIRouter()


def page(request, session, error=None, status_code=200):
    return templates.TemplateResponse(
        request=request,
        name="devices.html",
        status_code=status_code,
        context={
            "username": session["username"],
            "csrf": session["csrf_token"],
            "active": "devices",
            "devices": devices.snapshot(request.app.state.settings),
            "error": error,
        },
    )


@router.get("/devices")
def list_devices(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        return RedirectResponse("/login", status_code=303)
    return page(request, session)


@router.get("/api/devices")
def status(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        raise HTTPException(401, "请先登录。")
    return {"devices": devices.snapshot(request.app.state.settings)}


@router.post("/devices/add")
async def add(request: Request):
    session, form = await authenticated_form(request)
    try:
        devices.save(request.app.state.settings, form, session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/devices", status_code=303)


@router.post("/devices/{identifier}/edit")
async def edit(request: Request, identifier: int):
    session, form = await authenticated_form(request)
    try:
        devices.save(request.app.state.settings, form, session["username"], identifier)
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/devices", status_code=303)
