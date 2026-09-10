from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from controller.api.dashboard import session_for, templates
from controller.api.gateways import authenticated_form
from controller.services import monitor

router = APIRouter()


@router.get("/network")
def page(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="network.html",
        context={
            "username": session["username"],
            "csrf": session["csrf_token"],
            "active": "network",
            "gateways": monitor.snapshot(request.app.state.settings),
        },
    )


@router.get("/api/network")
def status(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        raise HTTPException(401, "请先登录。")
    return {"gateways": monitor.snapshot(request.app.state.settings)}


@router.post("/network/check")
async def refresh(request: Request):
    session, _ = await authenticated_form(request)
    monitor.refresh(request.app.state.settings, session["username"])
    return RedirectResponse("/network", status_code=303)
