"""QRShield local web application (FastAPI + Jinja2 + HTMX). Presentation layer only: all analysis lives in qrshield_core."""
from __future__ import annotations

import base64
import hmac
import ipaddress
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware
from urllib.parse import urlsplit

from qrshield_core import __version__
from qrshield_core.config import Settings
from qrshield_core.models import LEVEL_LABELS, AssessmentLevel

from .state import AppState

BASE = Path(__file__).resolve().parent
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
LEVEL_ORDER = [l.value for l in (AssessmentLevel.NO_MATERIAL_CONCERN, AssessmentLevel.NEEDS_VERIFICATION,
                                 AssessmentLevel.HIGH_CONCERN, AssessmentLevel.HARMFUL_CORROBORATED)]
LEVEL_NAMES = {l.value: LEVEL_LABELS[l] for l in AssessmentLevel}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _host_only(value: str) -> str:
    value = value.strip().lower()
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def _remote_access_enabled(allowed_hosts: list[str]) -> bool:
    """Treat wildcard or any non-loopback allowed host as a remote deployment."""
    for configured in allowed_hosts:
        value = configured.strip().lower()
        host = _host_only(value)
        if value == "*" or value.startswith("*.") or host not in LOCAL_HOSTS:
            return True
    return False


def _valid_access_header(header: str | None, expected: str) -> bool:
    """Accept a Bearer token for API clients or HTTP Basic password for browsers."""
    if not header or not expected:
        return False
    scheme, _, credentials = header.partition(" ")
    if scheme.lower() == "bearer":
        supplied = credentials.strip()
    elif scheme.lower() == "basic":
        try:
            decoded = base64.b64decode(credentials.strip(), validate=True).decode("utf-8")
            _, separator, supplied = decoded.partition(":")
            if not separator:
                return False
        except (ValueError, UnicodeDecodeError):
            return False
    else:
        return False
    return bool(supplied) and hmac.compare_digest(supplied, expected)


def create_app(state: AppState | None = None) -> FastAPI:
    cfg = state.settings if state is not None else Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.qs = state or AppState(cfg)
        yield

    app = FastAPI(title="QRShield", version=__version__, lifespan=lifespan, docs_url="/api/docs", redoc_url=None)
    if state is not None:                         # tests inject state directly (lifespan may not run)
        app.state.qs = state
    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
    templates = Jinja2Templates(directory=str(BASE / "templates"))      # autoescape is on for .html
    templates.env.globals.update(version=__version__, level_order=LEVEL_ORDER, level_names=LEVEL_NAMES)
    app.state.templates = templates

    # DNS-rebinding protection: only accept requests addressed to an allowed Host (set ALLOWED_HOSTS to widen; "*" disables).
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=cfg.allowed_hosts or ["127.0.0.1"])

    @app.middleware("http")
    async def same_origin_for_state_changes(request: Request, call_next):
        """CSRF mitigation for a local tool: browsers always send Origin on cross-site POSTs; reject any that is not this host.
        Non-browser clients (curl, tests, API consumers) send no Origin and are unaffected."""
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if origin is not None and urlsplit(origin).netloc != request.headers.get("host", ""):
                return JSONResponse({"error": "cross_origin_request_rejected"}, status_code=403)
        return await call_next(request)

    test_environment = cfg.env.strip().lower() in {"test", "testing"}
    remote_access = _remote_access_enabled(cfg.allowed_hosts)

    @app.middleware("http")
    async def remote_access_guard(request: Request, call_next):
        """Keep local-only configurations loopback-only and token-protect remote deployments."""
        if test_environment or request.url.path == "/health" or request.url.path.startswith("/static/"):
            return await call_next(request)

        peer_host = request.client.host if request.client else ""
        try:
            peer_ip = ipaddress.ip_address(peer_host.strip("[]"))
            peer_is_loopback = peer_ip.is_loopback
        except ValueError:
            # ASGI test clients and local socket abstractions may use non-IP labels.
            peer_is_loopback = peer_host.lower() in {"testclient", "testserver", "localhost"}

        if not remote_access:
            if not peer_is_loopback:
                return JSONResponse(
                    {"error": "remote_access_disabled", "detail": "QRShield is configured for loopback access only. Add an allowed remote host and a strong QRSHIELD_ACCESS_TOKEN to enable remote access."},
                    status_code=403,
                )
            return await call_next(request)

        token = cfg.access_token
        if len(token) < 32:
            return JSONResponse(
                {"error": "remote_access_not_configured", "detail": "Set QRSHIELD_ACCESS_TOKEN to a random secret of at least 32 characters before allowing remote hosts."},
                status_code=503,
            )
        if not _valid_access_header(request.headers.get("authorization"), token):
            return JSONResponse(
                {"error": "authentication_required"}, status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="QRShield", charset="UTF-8"'},
            )
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not request.url.path.startswith("/static"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):      # error isolation: never leak internals or turn errors into verdicts
        return JSONResponse({"error": "internal_error", "detail": "The request could not be processed."}, status_code=500)

    from .api import routes as api_routes
    from .routes import analyze, research, settings as settings_routes
    for r in (analyze.router, research.router, settings_routes.router, api_routes.router):
        app.include_router(r)
    return app


# Module-level instance for: uvicorn app.main:app
# Tests that need custom state use create_app(state=...) directly.
app = create_app()
