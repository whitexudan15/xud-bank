# ============================================================
# XUD-BANK — app/routers/data.py
# Routes de consultation des données bancaires sensibles
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================

import json
import logging
from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.config import get_settings
from app.models.bank_account import BankAccount, AccountClassification
from app.models.user import UserRole
from app.services.auth_service import get_current_user_data, require_role
from secureDataMonitor.events.dispatcher import dispatcher
from secureDataMonitor.services.detection import (
    record_data_access,
    check_sql_injection,
    check_suspicious_url,
)

settings = get_settings()
log = logging.getLogger("xud_bank.router.data")

router = APIRouter(prefix="/data", tags=["data"])
templates = Jinja2Templates(directory="app/templates")


# ════════════════════════════════════════════════════════════
# MIDDLEWARE INTERNE — Vérification URL suspecte
# ════════════════════════════════════════════════════════════

async def _check_request_security(request: Request, user_data: dict) -> None:
    """
    Vérifie chaque requête entrante :
    - URL suspecte (path traversal, fichiers sensibles)
    - Paramètres suspects
    Émet les événements appropriés si détection.
    """
    ip = request.client.host
    full_path = str(request.url)

    if check_suspicious_url(full_path):
        await dispatcher.emit("suspicious_url", {
            "ip": ip,
            "url": full_path,
            "username": user_data.get("username"),
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requête bloquée.",
        )

    # Vérifie les query params
    for key, value in request.query_params.items():
        if check_sql_injection(value):
            await dispatcher.emit("sql_injection", {
                "ip": ip,
                "username": user_data.get("username"),
                "field": f"query:{key}",
                "payload": value,
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Paramètre invalide.",
            )


# ════════════════════════════════════════════════════════════
# GET /data/accounts — Liste des comptes bancaires
# ════════════════════════════════════════════════════════════

@router.get("/accounts", response_class=HTMLResponse)
async def list_accounts(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(get_current_user_data),
):
    """
    Affiche la liste des comptes bancaires selon le rôle :
      - utilisateur : ses propres comptes uniquement
      - analyste    : tous les comptes (classification <= confidentiel)
      - admin       : tous les comptes sans restriction

    Règle 4 : comptage des accès → alerte CRITICAL si >20 en 1 min
    """
    ip = request.client.host
    username = user_data["username"]
    role = user_data["role"]

    # Vérification sécurité URL
    await _check_request_security(request, user_data)

    # ── Règle 4 : détection exfiltration massive ──────────────
    triggered, count = record_data_access(username)
    if triggered:
        await dispatcher.emit("mass_data_access", {
            "ip": ip,
            "username": username,
            "count": count,
            "window": settings.MASS_ACCESS_WINDOW,
        })

    # ── Filtrage par rôle ─────────────────────────────────────
    query = select(BankAccount)

    if role == UserRole.utilisateur.value:
        # Ses comptes uniquement
        query = query.where(BankAccount.owner_id == user_data["user_id"])

    elif role == UserRole.analyste.value:
        # Tous sauf "secret"
        query = query.where(
            BankAccount.classification.in_([
                AccountClassification.public,
                AccountClassification.confidentiel,
            ])
        )
    # admin : tous les comptes, pas de filtre

    query = query.order_by(BankAccount.created_at.desc())
    result = await db.execute(query)
    accounts = result.scalars().all()

    # Désérialise l'historique JSON pour l'affichage
    accounts_data = []
    for acc in accounts:
        acc_dict = {
            "id": str(acc.id),
            "id_compte": acc.id_compte,
            "titulaire": acc.titulaire,
            "solde": float(acc.solde),
            "classification": acc.classification.value,
            "created_at": acc.created_at,
            "historique": [],
        }
        if acc.historique:
            try:
                acc_dict["historique"] = json.loads(acc.historique)
            except (json.JSONDecodeError, TypeError):
                acc_dict["historique"] = []
        accounts_data.append(acc_dict)

    log.info(f"[DATA] {username} ({role}) a consulté {len(accounts_data)} compte(s) depuis {ip}")

    return templates.TemplateResponse("data.html", {
        "request": request,
        "user": user_data,
        "accounts": accounts_data,
        "total": len(accounts_data),
    })


# ════════════════════════════════════════════════════════════
# GET /data/accounts/{account_id} — Détail d'un compte
# ════════════════════════════════════════════════════════════

@router.get("/accounts/{account_id}", response_class=HTMLResponse)
async def account_detail(
    account_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(get_current_user_data),
):
    """
    Détail d'un compte bancaire spécifique.
    Vérifie que l'utilisateur a accès à ce compte (périmètre).
    """
    ip = request.client.host
    username = user_data["username"]
    role = user_data["role"]

    # Vérification sécurité
    await _check_request_security(request, user_data)

    # Règle 4
    triggered, count = record_data_access(username)
    if triggered:
        await dispatcher.emit("mass_data_access", {
            "ip": ip,
            "username": username,
            "count": count,
            "window": settings.MASS_ACCESS_WINDOW,
        })

    # Récupère le compte
    result = await db.execute(
        select(BankAccount).where(BankAccount.id == account_id)
    )
    account = result.scalar_one_or_none()

    if not account:
        raise HTTPException(status_code=404, detail="Compte introuvable.")

    # Vérification périmètre
    if role == UserRole.utilisateur.value:
        if str(account.owner_id) != user_data["user_id"]:
            # Tentative d'accès hors périmètre
            await dispatcher.emit("privilege_escalation", {
                "ip": ip,
                "username": username,
                "detail": f"Accès au compte {account_id} non autorisé (owner={account.owner_id})",
            })
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Accès refusé.",
            )

    elif role == UserRole.analyste.value:
        if account.classification == AccountClassification.secret:
            await dispatcher.emit("unauthorized", {
                "ip": ip,
                "username": username,
                "role": role,
                "path": f"/data/accounts/{account_id}",
            })
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Accès refusé : données classifiées SECRET.",
            )

    # Désérialise historique
    historique = []
    if account.historique:
        try:
            historique = json.loads(account.historique)
        except (json.JSONDecodeError, TypeError):
            historique = []

    return templates.TemplateResponse("data.html", {
        "request": request,
        "user": user_data,
        "account_detail": {
            "id": str(account.id),
            "id_compte": account.id_compte,
            "titulaire": account.titulaire,
            "solde": float(account.solde),
            "classification": account.classification.value,
            "created_at": account.created_at,
            "historique": historique,
        },
    })