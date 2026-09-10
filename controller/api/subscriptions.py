from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from controller.api.dashboard import templates
from controller.api.gateways import authenticated_form
from controller.api.groups import page
from controller.services import subscriptions

router = APIRouter()


@router.get("/sub/{token}")
def subscription(request: Request, token: str):
    try:
        content = subscriptions.payload(request.app.state.settings, token)
    except ValueError:
        return PlainTextResponse(
            "Subscription temporarily unavailable",
            status_code=503,
            headers={"Retry-After": "60", "Referrer-Policy": "no-referrer"},
        )
    return PlainTextResponse(
        content or "Not found",
        status_code=200 if content else 404,
        headers={"Referrer-Policy": "no-referrer", "profile-update-interval": "1"},
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
    except ValueError as exc:
        return page(request, session, str(exc), 400)
    return templates.TemplateResponse(
        request=request,
        name="subscription_link.html",
        headers={"Referrer-Policy": "no-referrer"},
        context={
            "link": link,
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
