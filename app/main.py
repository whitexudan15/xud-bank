# ============================================================
# XUD-BANK — app/main.py
# Point d'entrée FastAPI — montage routers + lifespan
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.database import check_db_connection, close_db
from secureDataMonitor.events.handlers import register_all_handlers
from secureDataMonitor.services.logger import setup_file_logger

settings = get_settings()
log = logging.getLogger("xud_bank")


# ════════════════════════════════════════════════════════════
# LIFESPAN — Démarrage & Arrêt
# ════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Exécuté au démarrage et à l'arrêt de l'application.
    Ordre de démarrage :
      1. Logger fichier
      2. Vérification connexion BDD
      3. Enregistrement des handlers événementiels
    """
    # ── Démarrage ─────────────────────────────────────────────
    setup_file_logger()
    log.info("=" * 60)
    log.info(f"  {settings.APP_NAME} v{settings.APP_VERSION}")
    log.info("=" * 60)

    # Vérification BDD
    try:
        await check_db_connection()
        log.info("✓ Connexion PostgreSQL (Supabase) établie")
    except Exception as e:
        log.critical(f"✗ Connexion BDD impossible : {e}")
        raise

    # Enregistrement des handlers événementiels
    register_all_handlers()
    log.info("✓ Handlers SecureDataMonitor enregistrés")
    log.info("✓ Application démarrée — en écoute...")

    yield

    # ── Arrêt ─────────────────────────────────────────────────
    await close_db()
    log.info("✓ Pool de connexions BDD fermé proprement")


# ════════════════════════════════════════════════════════════
# APPLICATION FASTAPI
# ════════════════════════════════════════════════════════════

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/api/docs" if settings.DEBUG else None,   # Swagger désactivé en prod
    redoc_url=None,
)


# ════════════════════════════════════════════════════════════
# FICHIERS STATIQUES
# ════════════════════════════════════════════════════════════

app.mount("/static/app", StaticFiles(directory="app/static"), name="static_app")
app.mount("/static/monitor", StaticFiles(directory="secureDataMonitor/static"), name="static_monitor")


# ════════════════════════════════════════════════════════════
# TEMPLATES
# ════════════════════════════════════════════════════════════

templates_app     = Jinja2Templates(directory="app/templates")
templates_monitor = Jinja2Templates(directory="secureDataMonitor/templates")


# ════════════════════════════════════════════════════════════
# ROUTERS
# ════════════════════════════════════════════════════════════

# App bancaire
from app.routers.auth import router as auth_router
from app.routers.data import router as data_router

# SecureDataMonitor
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
    """Redirige vers login."""
    return RedirectResponse(url="/auth/login", status_code=302)


@app.get("/health", include_in_schema=False)
async def health():
    """Endpoint de santé pour Render.com."""
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
    """Page 403 personnalisée + émission événement."""
    from app.config import get_settings
    from secureDataMonitor.events.dispatcher import dispatcher

    try:
        token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        from app.services.auth_service import decode_session_token
        user_data = decode_session_token(token) if token else {}
        username = user_data.get("username") if user_data else None
        role = user_data.get("role") if user_data else "anonymous"
    except Exception:
        username, role = None, "anonymous"

    # Émet unauthorized si l'URL cible /admin
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
    """Page 404 personnalisée + détection URL suspecte."""
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
# MIDDLEWARE — Détection URL suspecte sur toutes les requêtes
# ════════════════════════════════════════════════════════════

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Middleware global :
    - Détecte les URL suspectes sur toutes les routes
    - Ajoute les headers de sécurité sur toutes les réponses
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        from secureDataMonitor.services.detection import check_suspicious_url
        from secureDataMonitor.events.dispatcher import dispatcher

        path = request.url.path

        # Vérifie l'URL
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

        # Headers de sécurité
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response


app.add_middleware(SecurityMiddleware)