# ============================================================
# XUD-BANK — app/routers/auth.py
# Routes d'authentification : login, logout, register
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================

import logging
from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config import get_settings
from app.services.auth_service import (
    authenticate, create_user, create_session_token,
    get_current_user_data, AuthResult,
)
from secureDataMonitor.events.dispatcher import dispatcher
from secureDataMonitor.services.detection import (
    check_sql_injection, check_off_hours, check_special_characters,
)

settings = get_settings()
log = logging.getLogger("xud_bank.router.auth")

router = APIRouter(prefix="/auth", tags=["auth"])
templates = Jinja2Templates(directory="app/templates")


# ════════════════════════════════════════════════════════════
# GET /auth/login
# ════════════════════════════════════════════════════════════

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Affiche la page de connexion."""
    # Redirige si déjà connecté
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if token:
        return RedirectResponse(url="/data/accounts", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})


# ════════════════════════════════════════════════════════════
# POST /auth/login
# ════════════════════════════════════════════════════════════

@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Traite la soumission du formulaire de connexion.
    Émet les événements appropriés via le dispatcher.
    """
    ip = request.client.host

    # ── Détection SQL injection dans les champs ───────────────
    for field, value in [("username", username), ("password", password)]:
        if check_sql_injection(value):
            await dispatcher.emit("sql_injection", {
                "ip": ip,
                "username": username,
                "field": field,
                "payload": value,
            })
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Identifiants invalides."},
                status_code=400,
            )

    # ── Détection caractères spéciaux ────────────────────────
    if check_special_characters(username, "username"):
        await dispatcher.emit("suspicious_url", {
            "ip": ip,
            "url": f"/auth/login?username={username[:30]}",
            "username": None,
        })
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Identifiants invalides."},
            status_code=400,
        )

    # ── Authentification ──────────────────────────────────────
    result: AuthResult = await authenticate(db, username, password)

    if result.success:
        user = result.user

        # Détection accès hors horaires
        if check_off_hours():
            from datetime import datetime
            await dispatcher.emit("off_hours_access", {
                "ip": ip,
                "username": user.username,
                "hour": datetime.utcnow().hour,
            })

        # Émet login_success
        await dispatcher.emit("login_success", {
            "ip": ip,
            "username": user.username,
            "role": user.role.value,
        })

        # Crée le cookie de session
        token = create_session_token(user)
        response = RedirectResponse(url="/data/accounts", status_code=302)
        response.set_cookie(
            key=settings.SESSION_COOKIE_NAME,
            value=token,
            max_age=settings.SESSION_MAX_AGE,
            httponly=settings.COOKIE_HTTPONLY,
            samesite=settings.COOKIE_SAMESITE,
        )
        log.info(f"Login réussi : {user.username} depuis {ip}")
        return response

    # ── Échec d'authentification ──────────────────────────────
    if result.reason == "unknown_user":
        await dispatcher.emit("unknown_user", {
            "ip": ip,
            "username": username,
        })

    elif result.reason == "account_locked":
        await dispatcher.emit("account_locked", {
            "ip": ip,
            "username": username,
        })

    elif result.reason == "invalid_password":
        attempt_count = result.user.failed_attempts if result.user else 1
        await dispatcher.emit("login_failed", {
            "ip": ip,
            "username": username,
            "attempt": attempt_count,
        })

    # Message générique (anti-énumération)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Identifiants invalides ou compte verrouillé."},
        status_code=401,
    )


# ════════════════════════════════════════════════════════════
# GET /auth/logout
# ════════════════════════════════════════════════════════════

@router.get("/logout")
async def logout(request: Request):
    """Supprime le cookie de session et redirige vers login."""
    response = RedirectResponse(url="/auth/login", status_code=302)
    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    return response


# ════════════════════════════════════════════════════════════
# GET /auth/register
# ════════════════════════════════════════════════════════════

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Affiche la page d'inscription."""
    return templates.TemplateResponse("register.html", {"request": request})


# ════════════════════════════════════════════════════════════
# POST /auth/register
# ════════════════════════════════════════════════════════════

@router.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Crée un nouveau compte utilisateur (rôle=utilisateur par défaut).
    Vérifie les injections avant tout.
    """
    ip = request.client.host

    # Vérifications sécurité
    for field, value in [("username", username), ("email", email), ("password", password)]:
        if check_sql_injection(value):
            await dispatcher.emit("sql_injection", {
                "ip": ip,
                "username": username,
                "field": field,
                "payload": value,
            })
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "error": "Données invalides."},
                status_code=400,
            )

    try:
        user = await create_user(db, username=username, email=email, password=password)
        await db.commit()
        log.info(f"Nouveau compte créé : {username} depuis {ip}")
        return RedirectResponse(url="/auth/login?registered=1", status_code=302)

    except Exception as e:
        await db.rollback()
        log.error(f"Erreur création compte {username} : {e}")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Ce nom d'utilisateur ou email est déjà pris."},
            status_code=400,
        )