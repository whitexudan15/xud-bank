# ============================================================
# XUD-BANK — app/main.py
# Point d'entrée FastAPI — montage routers + lifespan
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================

import logging
from contextlib import asynccontextmanager
from jinja2 import FileSystemLoader, Environment
from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from app.config import get_settings
from app.database import check_db_connection, close_db
from secureDataMonitor.events.handlers import register_all_handlers
from secureDataMonitor.services.logger import setup_file_logger, stop_file_logger

settings = get_settings()
log = logging.getLogger("xud_bank")

# ── Loader Jinja2 combiné (app + secureDataMonitor) ───────────
jinja_env = Environment(
    loader=FileSystemLoader([
        "app/templates",
        "secureDataMonitor/templates",
    ]),
    autoescape=True,
)
templates_app     = Jinja2Templates(env=jinja_env)
templates_monitor = Jinja2Templates(env=jinja_env)


# ════════════════════════════════════════════════════════════
# LIFESPAN — Démarrage & Arrêt
# ════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_file_logger()
    log.info("=" * 60)
    log.info(f"  {settings.APP_NAME} v{settings.APP_VERSION}")
    log.info("=" * 60)

    try:
        await check_db_connection()
        log.info("✓ Connexion PostgreSQL (Railway) établie")
    except Exception as e:
        log.critical(f"✗ Connexion BDD impossible : {e}")
        raise

    register_all_handlers()
    log.info("✓ Handlers SecureDataMonitor enregistrés")
    log.info("✓ Application démarrée — en écoute...")

    yield

    await close_db()
    stop_file_logger()
    log.info("✓ Pool de connexions BDD fermé proprement")
    log.info("✓ Logger fichier arrêté proprement")


# ════════════════════════════════════════════════════════════
# APPLICATION FASTAPI
# ════════════════════════════════════════════════════════════

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url=None,
)


# ════════════════════════════════════════════════════════════
# FICHIERS STATIQUES
# ════════════════════════════════════════════════════════════

app.mount("/static/app",     StaticFiles(directory="app/static"),              name="static_app")
app.mount("/static/monitor", StaticFiles(directory="secureDataMonitor/static"), name="static_monitor")


# ════════════════════════════════════════════════════════════
# ROUTERS
# ════════════════════════════════════════════════════════════

from app.routers.auth import router as auth_router
from app.routers.data import router as data_router
from secureDataMonitor.routers.admin import router as admin_router
from secureDataMonitor.routers.api_alerts import router as alerts_router

app.include_router(auth_router)
app.include_router(data_router)
app.include_router(admin_router)
app.include_router(alerts_router)


# ════════════════════════════════════════════════════════════
# ROUTES DE BASE
# ════════════════════════════════════════════════════════════

@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/auth/login", status_code=302)


@app.get("/health", include_in_schema=False)
async def health():
    try:
        await check_db_connection()
        return {"status": "ok", "db": "connected"}
    except Exception:
        return {"status": "error", "db": "unreachable"}


# ════════════════════════════════════════════════════════════
# GESTIONNAIRES D'ERREURS GLOBAUX
# ════════════════════════════════════════════════════════════

@app.exception_handler(403)
async def forbidden_handler(request: Request, exc):
    from secureDataMonitor.events.dispatcher import dispatcher
    try:
        token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        from app.services.auth_service import decode_session_token
        user_data = decode_session_token(token) if token else {}
        username = user_data.get("username") if user_data else None
        role = user_data.get("role") if user_data else "anonymous"
    except Exception:
        username, role = None, "anonymous"

    if request.url.path.startswith("/admin"):
        await dispatcher.emit("unauthorized", {
            "ip": request.client.host,
            "username": username,
            "role": role,
            "path": request.url.path,
        })

    return templates_monitor.TemplateResponse(
        "errors/403.html",
        {"request": request, "path": request.url.path},
        status_code=403,
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    from secureDataMonitor.services.detection import check_suspicious_url
    from secureDataMonitor.events.dispatcher import dispatcher

    path = request.url.path
    if check_suspicious_url(path):
        await dispatcher.emit("suspicious_url", {
            "ip": request.client.host,
            "url": path,
            "username": None,
        })

    return templates_monitor.TemplateResponse(
        "errors/404.html",
        {"request": request, "path": path},
        status_code=404,
    )


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    log.error(f"Erreur 500 sur {request.url.path} : {exc}")
    return templates_monitor.TemplateResponse(
        "errors/404.html",
        {"request": request, "path": request.url.path},
        status_code=500,
    )


# ════════════════════════════════════════════════════════════
# MIDDLEWARE — Sécurité globale
# ════════════════════════════════════════════════════════════

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        from secureDataMonitor.services.detection import check_suspicious_url
        from secureDataMonitor.events.dispatcher import dispatcher

        path = request.url.path

        # ignorer la vérification d'url pour les fichiers static
        if path.startswith("/static/"):
            response = await call_next(request)
            response.headers["Cache-Control"] = "public, max-age=3600"
            return response

        if check_suspicious_url(path):
            await dispatcher.emit("suspicious_url", {
                "ip": request.client.host,
                "url": path,
                "username": None,
            })
            return templates_monitor.TemplateResponse(
                "errors/403.html",
                {"request": request, "path": path},
                status_code=403,
            )

        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response


app.add_middleware(SecurityMiddleware)