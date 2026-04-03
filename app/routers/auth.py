# ============================================================
# XUD-BANK — app/routers/auth.py
# Routes d'authentification : login, logout, register
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================

import logging
import asyncio
from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import templates
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


# ════════════════════════════════════════════════════════════
# HELPER — Validation centralisée des entrées
# ════════════════════════════════════════════════════════════

def validate_inputs(fields: dict) -> tuple[bool, str, str]:
    """
    Valide plusieurs champs en une seule passe.
    Retourne: (is_violation: bool, field_name: str, value: str)
    """
    for field_name, value in fields.items():
        if check_sql_injection(value):
            return True, field_name, value
    return False, "", ""


# ════════════════════════════════════════════════════════════
# GET /auth/login
# ════════════════════════════════════════════════════════════

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if token:
        # Utilisateur déjà connecté, rediriger selon le rôle
        from app.services.auth_service import decode_session_token
        data = decode_session_token(token)
        if data:
            # Session valide, rediriger selon le rôle
            role_redirects = {
                "soc": "/soc/dashboard",
                "directeur": "/direction/dashboard",
                "comptable": "/comptabilite/dashboard",
                "utilisateur": "/client/dashboard"
            }
            return RedirectResponse(url=role_redirects.get(data["role"], "/auth/login"), status_code=302)
        # Session invalide ou expirée, afficher la page de login
    return templates.TemplateResponse("login.html", {"request": request})


# ════════════════════════════════════════════════════════════
# POST /auth/login
# ════════════════════════════════════════════════════════════

@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    ip = request.client.host

    # ── Détection SQL injection (validation centralisée) ──────
    is_violation, field, value = validate_inputs({"email": email, "password": password})
    if is_violation:
        asyncio.create_task(dispatcher.emit("sql_injection", {
            "ip": ip, "username": email, "field": field, "payload": value,
        }))
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Identifiants invalides."},
            status_code=400,
        )

    # ── Détection caractères spéciaux ─────────────────────────
    if check_special_characters(email, "email"):
        asyncio.create_task(dispatcher.emit("suspicious_url", {
            "ip": ip, "url": f"/auth/login?email={email[:30]}", "username": None,
        }))
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Identifiants invalides."},
            status_code=400,
        )

    # ── Authentification ──────────────────────────────────────
    result: AuthResult = await authenticate(db, email, password)

    if result.success:
        user = result.user

        if check_off_hours():
            from datetime import datetime
            asyncio.create_task(dispatcher.emit("off_hours_access", {
                "ip": ip, "username": user.username, "hour": datetime.utcnow().hour,
            }))

        asyncio.create_task(dispatcher.emit("login_success", {
            "ip": ip, "username": user.username, "role": user.role.value,
        }))

        token = create_session_token(user)
        role_redirects = {
            "soc": "/soc/dashboard",
            "directeur": "/direction/dashboard",
            "comptable": "/comptabilite/dashboard",
            "utilisateur": "/client/dashboard"
        }
        redirect_url = role_redirects.get(user.role.value, "/auth/login")
        response = RedirectResponse(url=redirect_url, status_code=302)
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
        asyncio.create_task(dispatcher.emit("unknown_user", {
            "ip": ip, "username": email,
        }))
    elif result.reason == "account_locked":
        asyncio.create_task(dispatcher.emit("account_locked", {
            "ip": ip, "username": email,
        }))
    elif result.reason == "invalid_password":
        attempt_count = result.user.failed_attempts if result.user else 1
        asyncio.create_task(dispatcher.emit("login_failed", {
            "ip": ip, "username": email, "attempt": attempt_count,
        }))

    if result.reason == "account_locked":
        error_msg = "Votre compte est verrouillé ! Contactez un Administrateur."
    else:
        error_msg = "Email ou mot de passe incorrect."

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": error_msg},
        status_code=401,
    )


# ════════════════════════════════════════════════════════════
# GET /auth/logout
# ════════════════════════════════════════════════════════════

@router.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/auth/login", status_code=302)
    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    return response


# Inscription publique désactivée (Action réservée à la Direction)
# @router.get("/register", response_class=HTMLResponse)
# ... etc