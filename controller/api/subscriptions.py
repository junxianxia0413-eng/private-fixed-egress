from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from controller.api.dashboard import templates
from controller.api.gateways import authenticated_form
from controller.api.groups import page
from controller.services import groups, subscriptions

router = APIRouter()


@router.get("/sub/{token}")
def subscription(request: Request, token: str):
    requested = request.query_params.get("format", "").lower()
    if requested and requested not in {"shadowrocket", "clash"}:
        return PlainTextResponse("Unsupported subscription format", status_code=400)
    user_agent = request.headers.get("user-agent", "").lower()
    accept = request.headers.get("accept", "").lower()
    if requested:
        format_name = requested
    elif any(value in user_agent for value in ("clash", "mihomo", "flclash")):
        format_name = "clash"
    elif "shadowrocket" in user_agent:
        format_name = "shadowrocket"
    elif "text/html" in accept and any(
        value in user_agent for value in ("mozilla/", "chrome/", "safari/")
    ):
        format_name = "html"
    else:
        format_name = "shadowrocket"
    try:
        content = subscriptions.payload(
            request.app.state.settings,
            token,
            "shadowrocket" if format_name == "html" else format_name,
        )
    except ValueError:
        return PlainTextResponse(
            "Subscription temporarily unavailable",
            status_code=503,
            headers={
                "Retry-After": "60",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "private, no-store",
                "Vary": "User-Agent, Accept",
            },
        )
    headers = {
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "private, no-store",
        "Vary": "User-Agent, Accept",
        "profile-update-interval": "1",
    }
    if content and format_name == "html":
        return templates.TemplateResponse(
            request=request,
            name="subscription_public.html",
            headers={**headers, "Content-Type": "text/html; charset=utf-8"},
            context={"link": str(request.url).split("?", 1)[0]},
        )
    return PlainTextResponse(
        content or "Not found",
        status_code=200 if content else 404,
        headers=headers,
        media_type="text/yaml" if format_name == "clash" else "text/plain",
    )


@router.post("/groups/{identifier}/activate")
async def activate(request: Request, identifier: int):
    session, _ = await authenticated_form(request)
    try:
        subscriptions.activate(request.app.state.settings, identifier, session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/groups", status_code=303)


@router.post("/groups/{identifier}/link")
async def show_link(request: Request, identifier: int):
    session, _ = await authenticated_form(request)
    try:
        link = subscriptions.link(request.app.state.settings, identifier)
        group = next(
            row for row in groups.snapshot(request.app.state.settings) if row["id"] == identifier
        )
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return templates.TemplateResponse(
        request=request,
        name="subscription_link.html",
        headers={"Referrer-Policy": "no-referrer"},
        context={
            "link": link,
            "group": group,
            "qr": subscriptions.qr_data(link),
            "csrf": session["csrf_token"],
            "username": session["username"],
            "active": "groups",
        },
    )


@router.post("/groups/{identifier}/rotate")
async def rotate(request: Request, identifier: int):
    session, _ = await authenticated_form(request)
    try:
        subscriptions.rotate(request.app.state.settings, identifier, session["username"])
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return RedirectResponse("/groups", status_code=303)
