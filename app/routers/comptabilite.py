# ============================================================
# XUD-BANK — app/routers/comptabilite.py
# Espace comptabilité bancaire
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================
import json
from decimal import Decimal
from fastapi import APIRouter, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from app.config import templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.user import User, UserRole
from app.models.bank_account import BankAccount, AccountClassification
from app.services.auth_service import require_role
from app.services.report_service import ReportService

router = APIRouter(prefix="/comptabilite", tags=["comptabilite"])

@router.get("/dashboard", response_class=HTMLResponse)
async def comptabilite_dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("comptable", "directeur", "soc")),
):
    """
    Audit ou Gestion : affiche tous les comptes (hors SECRET pour le comptable).
    Règle 4 : détection exfiltration massive.
    """
    from secureDataMonitor.services.detection import record_data_access
    from secureDataMonitor.events.dispatcher import dispatcher
    from app.config import get_settings
    
    settings = get_settings()
    ip = request.client.host
    username = user_data["username"]
    role = user_data["role"]

    # Règle 4 : détection exfiltration massive
    triggered, count = record_data_access(username)
    if triggered:
        await dispatcher.emit("mass_data_access", {
            "ip": ip,
            "username": username,
            "count": count,
            "window": settings.MASS_ACCESS_WINDOW,
        })

    # Filtrage par rôle
    if role == "comptable":
        # Hors SECRET
        query = select(BankAccount).where(
            BankAccount.classification.in_([
                AccountClassification.public,
                AccountClassification.confidentiel,
            ])
        )
    else:
        # Directeur/SOC : tout (mais SOC a d'abord été bloqué par require_role si pas soc)
        # En fait soc peut tout auditer mais pas modifier.
        query = select(BankAccount)
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

    # Liste des utilisateurs pour la création de compte
    users_result = await db.execute(
        select(User).where(User.role == UserRole.utilisateur)
    )
    users_list = users_result.scalars().all()

    return templates.TemplateResponse("comptabilite/dashboard.html", {
        "request": request,
        "user": user_data,
        "accounts": accounts_data,
        "total": len(accounts_data),
        "users_list": users_list,
    })

@router.post("/accounts/create")
async def create_account(
    request: Request,
    id_compte: str = Form(...),
    titulaire: str = Form(...),
    solde: float = Form(...),
    classification: str = Form(...),
    owner_username: str = Form(...),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("comptable")),
):
    """Création d'un compte bancaire par le comptable."""
    # Validation du propriétaire
    owner_result = await db.execute(
        select(User).where(User.username == owner_username)
    )
    owner = owner_result.scalar_one_or_none()

    if not owner or owner.role != UserRole.utilisateur:
        return RedirectResponse(
            url="/comptabilite/dashboard?error=Propriétaire+invalide",
            status_code=302
        )

    # Le comptable ne peut pas créer de comptes SECRET
    if classification == AccountClassification.secret.value:
         return RedirectResponse(
            url="/comptabilite/dashboard?error=Action+non+autorisée",
            status_code=302
        )

    try:
        new_account = BankAccount(
            id_compte=id_compte,
            titulaire=titulaire,
            solde=Decimal(str(solde)),
            classification=AccountClassification(classification),
            owner_id=owner.id,
            historique="[]",
        )
        db.add(new_account)
        await db.commit()
        return RedirectResponse(
            url="/comptabilite/dashboard?success=Compte+créé",
            status_code=302
        )
    except Exception as e:
        await db.rollback()
        return RedirectResponse(
            url="/comptabilite/dashboard?error=Erreur+interne",
            status_code=302
        )
@router.get("/export-pdf")
async def export_accounts_pdf(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("comptable", "directeur")),
):
    """Génère un rapport PDF des comptes (vision comptable)."""
    # On réutilise la même logique de filtrage que le dashboard
    query = select(BankAccount).where(
        BankAccount.classification.in_([
            AccountClassification.public,
            AccountClassification.confidentiel,
        ])
    ).order_by(BankAccount.id_compte.asc())
    
    result = await db.execute(query)
    accounts = result.scalars().all()
    
    accounts_data = []
    for acc in accounts:
        accounts_data.append({
            "id_compte": acc.id_compte,
            "titulaire": acc.titulaire,
            "solde": float(acc.solde),
            "classification": acc.classification.value,
            "created_at": acc.created_at,
        })
    
    pdf_content = ReportService.generate_accounts_pdf(accounts_data, user_data["username"])
    
    return Response(
        content=bytes(pdf_content),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=rapport_comptes.pdf"}
    )
