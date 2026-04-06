# ============================================================
# XUD-BANK — app/routers/client.py
# Espace personnel du client
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================
import json
from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from app.config import templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.bank_account import BankAccount
from app.services.auth_service import require_role

router = APIRouter(prefix="/client", tags=["client"])

@router.get("/dashboard", response_class=HTMLResponse)
async def client_dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("utilisateur")),
):
    """
    Espace personnel : ses propres comptes.
    Règle 4 : détection exfiltration massive.
    """
    from secureDataMonitor.services.detection import record_data_access
    from secureDataMonitor.events.dispatcher import dispatcher
    from app.config import get_settings
    
    settings = get_settings()
    from app.utils import get_client_ip
    ip = get_client_ip(request)
    username = user_data["username"]

    # Règle 4 : détection exfiltration massive
    triggered, count = record_data_access(username)
    if triggered:
        await dispatcher.emit("mass_data_access", {
            "ip": ip,
            "username": username,
            "count": count,
            "window": settings.MASS_ACCESS_WINDOW,
        })
    query = select(BankAccount).where(BankAccount.owner_id == user_data["user_id"])
    query = query.order_by(BankAccount.created_at.desc())
    result = await db.execute(query)
    accounts = result.scalars().all()

    accounts_data = []
    for acc in accounts:
        historique = []
        if acc.historique:
            try:
                historique = json.loads(acc.historique)
            except:
                pass
        accounts_data.append({
            "id": str(acc.id),
            "id_compte": acc.id_compte,
            "titulaire": acc.titulaire,
            "solde": float(acc.solde),
            "classification": acc.classification.value,
            "created_at": acc.created_at,
            "historique": historique,
        })

    return templates.TemplateResponse("client/dashboard.html", {
        "request": request,
        "user": user_data,
        "accounts": accounts_data,
        "total": len(accounts_data),
    })
