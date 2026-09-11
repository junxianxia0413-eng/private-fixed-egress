from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from controller.api.dashboard import check_csrf, session_for, templates
from controller.services.database import audit, connect
from controller.services.gateways import enqueue, register, snapshot
from controller.services.secrets import SecretStore

router = APIRouter()


def page(request, session, error=None, status_code=200):
    gateways, jobs = snapshot(request.app.state.settings)
    return templates.TemplateResponse(
        request=request,
        name="gateways.html",
        status_code=status_code,
        context={
            "username": session["username"],
            "csrf": session["csrf_token"],
            "gateways": gateways,
            "jobs": jobs,
            "error": error,
            "active": "gateways",
            "refresh_seconds": 2 if any(value["busy"] for value in gateways) else None,
        },
    )


async def authenticated_form(request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        raise HTTPException(401, "请先登录。")
    form = await request.form(max_fields=64, max_files=0)
    if not all(isinstance(v, str) for v in form.values()):
        raise HTTPException(400, "Invalid form")
    check_csrf(request, session, form.get("csrf", ""))
    return session, form


@router.get("/gateways")
def list_gateways(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        return RedirectResponse("/login", status_code=303)
    return page(request, session)


@router.get("/api/gateways")
def gateway_status(request: Request):
    session = session_for(request)
    if not session or not session["admin_id"]:
        raise HTTPException(401, "请先登录。")
    gateways, jobs = snapshot(request.app.state.settings)
    return {"gateways": gateways, "jobs": jobs}


@router.post("/gateways/add")
async def add_gateway(request: Request):
    session, form = await authenticated_form(request)
    try:
        await run_in_threadpool(register, request.app.state.settings, form, session["username"])
    except ValueError as exc:
        # Credentials are deliberately never repopulated into the returned form.
        return page(request, session, str(exc), 400)
    return RedirectResponse("/gateways", status_code=303)


@router.post("/gateways/{gateway_id}/recovery-key")
async def recovery_key(request: Request, gateway_id: int):
    session, _ = await authenticated_form(request)
    settings = request.app.state.settings
    with connect(settings.database_path) as db:
        row = db.execute("SELECT managed_ref FROM gateways WHERE id=?", (gateway_id,)).fetchone()
        if not row:
            raise HTTPException(404, "未找到服务器。")
        private = SecretStore(settings.secret_directory).get(row[0])["recovery_private_key"]
        audit(
            db, session["username"], "gateway.recovery-key.downloaded", f"gateway_id={gateway_id}"
        )
    return Response(
        private,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="gateway-{gateway_id}-recovery.key"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/gateways/{gateway_id}/{action}")
async def gateway_action(request: Request, gateway_id: int, action: str):
    session, _ = await authenticated_form(request)
    try:
        enqueue(request.app.state.settings, gateway_id, action, session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/gateways", status_code=303)
