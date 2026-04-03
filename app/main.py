# ============================================================
# XUD-BANK — app/main.py
# Point d'entrée FastAPI — montage routers + lifespan
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings, templates
from app.database import check_db_connection, close_db
from secureDataMonitor.events.handlers import register_all_handlers
from secureDataMonitor.services.logger import setup_file_logger, stop_file_logger

settings = get_settings()
log = logging.getLogger("xud_bank")

# Templates (importés depuis config.py)
templates_app = templates
templates_monitor = templates


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
from app.routers.soc import router as soc_router
from app.routers.direction import router as direction_router
from app.routers.comptabilite import router as comptabilite_router
from app.routers.client import router as client_router
from secureDataMonitor.routers.api_alerts import router as alerts_router

app.include_router(auth_router)
app.include_router(soc_router)
app.include_router(direction_router)
app.include_router(comptabilite_router)
app.include_router(client_router)
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
    from secureDataMonitor.services.detection import check_unauthorized_report_access
    try:
        token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        from app.services.auth_service import decode_session_token
        user_data = decode_session_token(token) if token else {}
        username = user_data.get("username") if user_data else None
        role = user_data.get("role") if user_data else "anonymous"
    except Exception:
        username, role = None, "anonymous"

    # Monitoring des accès non autorisés aux zones sensibles
    if request.url.path.startswith(("/soc", "/direction", "/comptabilite")):
        await dispatcher.emit("unauthorized", {
            "ip": request.client.host,
            "username": username,
            "role": role,
            "path": request.url.path,
        })
    
    # Règle 7 : Tentative de vol de dossiers bancaires
    if check_unauthorized_report_access(request.url.path, role):
        await dispatcher.emit("bank_fraud_attempt", {
            "ip": request.client.host,
            "username": username,
            "role": role,
            "path": request.url.path,
            "severity": "CRITICAL",
        })

    return templates_monitor.TemplateResponse(
        "errors/403.html",
        {"request": request, "path": request.url.path},
        status_code=403,
    )


@app.exception_handler(401)
async def unauthorized_handler(request: Request, exc):
    """Gère les erreurs 401 (Non authentifié) en redirigeant vers /auth/login."""
    # Redirige vers la page de login pour toute erreur 401
    log.error(f"Erreur 401 sur {request.url.path} : {exc}")

    return templates_monitor.TemplateResponse(
        "errors/401.html",
        {"request": request, "path": request.url.path},
        status_code=401,
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    from secureDataMonitor.services.detection import check_suspicious_url
    from secureDataMonitor.events.dispatcher import dispatcher

    log.error(f"Erreur 404 sur {request.url.path} : {exc}")

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
    error_type = type(exc).__name__
    log.error(f"Erreur 500 sur {request.url.path} : {exc}")
    
    return templates_monitor.TemplateResponse(
        "errors/500.html",
        {"request": request, "path": request.url.path, "error_type": error_type, "error_message": str(exc)},
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