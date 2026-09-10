import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from controller.api.dashboard import router
from controller.api.devices import router as devices_router
from controller.api.exits import router as exits_router
from controller.api.gateways import router as gateways_router
from controller.api.groups import router as groups_router
from controller.api.isps import router as isps_router
from controller.api.network import router as network_router
from controller.api.subscriptions import router as subscriptions_router
from controller.config import ROOT, Settings
from controller.services.database import connect, migrate
from controller.services.gateways import GatewayWorker


class BodyLimitMiddleware:
    """Bound request bodies, including chunked requests."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 16384:
                response = JSONResponse({"detail": "Request too large"}, status_code=413)
                return await response(scope, receive, send)
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def create_app(settings: Settings | None = None):
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app):
        migrate(settings.database_path)
        worker = GatewayWorker(settings)
        if settings.environment != "test":
            worker.start()
        try:
            yield
        finally:
            if settings.environment != "test":
                worker.close()

    app = FastAPI(
        title="Private Network",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.add_middleware(BodyLimitMiddleware)
    if settings.secure:
        app.add_middleware(HTTPSRedirectMiddleware)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[settings.hostname])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": response.headers.get("Referrer-Policy", "same-origin"),
                "Content-Security-Policy": (
                    "default-src 'self'; style-src 'self'; script-src 'none'; "
                    "img-src 'self' data:; form-action 'self'; "
                    "frame-ancestors 'none'; base-uri 'none'"
                ),
            }
        )
        if settings.secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(sqlite3.Error)
    async def database_unavailable(request, exc):
        return JSONResponse({"detail": "Controller database unavailable"}, status_code=503)

    @app.get("/healthz")
    def health():
        with connect(settings.database_path) as db:
            db.execute("SELECT COUNT(*) FROM administrator").fetchone()
        return {"status": "ok", "component": "controller"}

    app.mount("/static", StaticFiles(directory=ROOT / "controller/static"), name="static")
    app.include_router(router)
    app.include_router(gateways_router)
    app.include_router(isps_router)
    app.include_router(exits_router)
    app.include_router(devices_router)
    app.include_router(groups_router)
    app.include_router(subscriptions_router)
    app.include_router(network_router)
    return app


app = create_app()
