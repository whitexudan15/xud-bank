# ============================================================
# XUD-BANK  -  app/routers/comptabilite.py
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
    user_data: dict = Depends(require_role("comptable")),
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
@router.get("/rapport")
async def export_accounts_pdf(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("comptable")),
):
    from fpdf import FPDF

    query = select(BankAccount).where(
        BankAccount.classification.in_([
            AccountClassification.public,
            AccountClassification.confidentiel,
        ])
    ).order_by(BankAccount.classification.asc(), BankAccount.id_compte.asc())

    result = await db.execute(query)
    accounts = result.scalars().all()

    grouped_accounts = {"public": [], "confidentiel": []}
    totals = {"public": 0, "confidentiel": 0, "global": 0}
    stats  = {"public": 0, "confidentiel": 0}

    for acc in accounts:
        acc_data = {
            "id_compte":      acc.id_compte,
            "titulaire":      acc.titulaire,
            "solde":          float(acc.solde),
            "classification": acc.classification.value,
            "created_at":     acc.created_at,
        }
        cl = acc.classification.value
        grouped_accounts[cl].append(acc_data)
        totals[cl]       += float(acc.solde)
        totals["global"] += float(acc.solde)
        stats[cl]        += 1

    # ─── Palette ─────────────────────────────────────────────────────────────
    NAVY       = (10,  18,  50)
    GOLD       = (196, 158, 75)
    GOLD_LIGHT = (232, 205, 140)
    WHITE      = (255, 255, 255)
    LIGHT_BG   = (245, 246, 250)
    MID_GRAY   = (180, 184, 200)
    DARK_TEXT  = (30,  35,  60)
    ROW_ALT    = (238, 240, 248)

    SEC_COLORS = {
        "public":       (45,  130, 90),
        "confidentiel": (190, 120, 40),
    }
    SEC_LABELS = {
        "public":       "PUBLIC",
        "confidentiel": "CONFIDENTIEL",
    }

    # ─── PDF ─────────────────────────────────────────────────────────────────
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    W = pdf.w - pdf.l_margin - pdf.r_margin

    # ── Bandeau header ────────────────────────────────────────────────────────
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, pdf.w, 42, "F")

    pdf.set_y(7)
    pdf.set_font("helvetica", "B", 20)
    pdf.set_text_color(*GOLD)
    pdf.cell(0, 10, "XUD-BANK", ln=False, align="C")

    pdf.set_y(19)
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(*GOLD_LIGHT)
    pdf.cell(0, 6, "RAPPORT DES COMPTES - COMPTABILITE", ln=True, align="C")

    pdf.set_y(28)
    pdf.set_font("helvetica", "", 8)
    pdf.set_text_color(*MID_GRAY)
    pdf.cell(0, 5,
             f"Genere le {datetime.utcnow().strftime('%d/%m/%Y a %H:%M UTC')}  -  "
             f"{user_data['username']}  -  Role : Comptable  -  "
             f"Acces : PUBLIC / CONFIDENTIEL",
             ln=True, align="C")

    pdf.set_y(42)
    pdf.set_draw_color(*GOLD)
    pdf.set_line_width(0.6)
    pdf.line(pdf.l_margin, 42, pdf.w - pdf.r_margin, 42)
    pdf.set_line_width(0.2)
    pdf.ln(6)

    # ── Cards résumé (3 cards) ────────────────────────────────────────────────
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(*MID_GRAY)
    pdf.cell(0, 5, "RÉSUMÉ GLOBAL", ln=True)
    pdf.ln(1)

    card_w = W / 3 - 2
    cards = [
        ("Total (XOF)",                    f"{totals['global']:,.0f}"),
        (f"Public ({stats['public']})",     f"{totals['public']:,.0f} XOF"),
        (f"Confidentiel ({stats['confidentiel']})", f"{totals['confidentiel']:,.0f} XOF"),
    ]

    x0 = pdf.l_margin
    y0 = pdf.get_y()
    for i, (label, value) in enumerate(cards):
        cx = x0 + i * (card_w + 3)
        pdf.set_fill_color(*LIGHT_BG)
        pdf.set_draw_color(*MID_GRAY)
        pdf.rect(cx, y0, card_w, 18, "FD")

        pdf.set_xy(cx + 2, y0 + 2)
        pdf.set_font("helvetica", "", 7)
        pdf.set_text_color(*MID_GRAY)
        pdf.cell(card_w - 4, 5, label.upper(), ln=True)

        pdf.set_xy(cx + 2, y0 + 8)
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(*DARK_TEXT)
        pdf.cell(card_w - 4, 7, value)

    pdf.set_y(y0 + 22)
    pdf.ln(6)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def h_rule(pdf, color=MID_GRAY, width=0.3):
        pdf.set_draw_color(*color)
        pdf.set_line_width(width)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(4)

    COL_W   = [40, 60, 36, 42]
    HEADERS = ["ID Compte", "Titulaire", "Solde (XOF)", "Créé le"]

    def draw_table_header(pdf, sec_color):
        pdf.set_fill_color(*sec_color)
        pdf.set_text_color(*WHITE)
        pdf.set_font("helvetica", "B", 7.5)
        for w, h in zip(COL_W, HEADERS):
            pdf.cell(w, 7, h, border=0, fill=True)
        pdf.ln()
        pdf.set_draw_color(*sec_color)
        pdf.set_line_width(0.4)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.set_line_width(0.2)

    def add_section(pdf, key, accounts_list):
        if pdf.get_y() > 210:
            pdf.add_page()

        color = SEC_COLORS[key]
        label = SEC_LABELS[key]

        pdf.set_fill_color(*color)
        pdf.set_draw_color(*color)
        pdf.rect(pdf.l_margin, pdf.get_y(), W, 9, "F")

        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(*WHITE)
        pdf.cell(W * 0.55, 9,
                 f"  {label}   -   {len(accounts_list)} compte(s)",
                 border=0, fill=False)
        pdf.set_font("helvetica", "", 8)
        pdf.cell(W * 0.45, 9,
                 f"Sous-total : {totals[key]:,.2f} XOF",
                 border=0, fill=False, align="R", ln=True)

        pdf.ln(1)
        draw_table_header(pdf, color)

        pdf.set_font("helvetica", "", 7.5)
        for idx, acc in enumerate(accounts_list):
            if pdf.get_y() > 262:
                pdf.add_page()
                draw_table_header(pdf, color)

            fill_color = ROW_ALT if idx % 2 == 0 else WHITE
            pdf.set_fill_color(*fill_color)
            pdf.set_text_color(*DARK_TEXT)

            date_str = (acc["created_at"].strftime("%d/%m/%Y %H:%M")
                        if hasattr(acc["created_at"], "strftime")
                        else str(acc["created_at"]))

            row = [
                str(acc["id_compte"]),
                str(acc["titulaire"]),
                f"{acc['solde']:,.2f}",
                date_str,
            ]
            for w, val in zip(COL_W, row):
                pdf.cell(w, 6, val, border=0, fill=True)
            pdf.ln()

            pdf.set_draw_color(*ROW_ALT)
            pdf.line(pdf.l_margin, pdf.get_y(),
                     pdf.w - pdf.r_margin, pdf.get_y())

        pdf.ln(6)

    # ── Sections ──────────────────────────────────────────────────────────────
    for key in ("public", "confidentiel"):
        if grouped_accounts[key]:
            add_section(pdf, key, grouped_accounts[key])
        else:
            h_rule(pdf)
            pdf.set_font("helvetica", "I", 8)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 7,
                     f"  Aucun compte {SEC_LABELS[key]} enregistré.",
                     ln=True)
            pdf.ln(3)

    # ── Footer ────────────────────────────────────────────────────────────────
    h_rule(pdf, color=GOLD, width=0.5)
    pdf.set_font("helvetica", "I", 7)
    pdf.set_text_color(*MID_GRAY)
    pdf.cell(W / 2, 5,
             "Document confidentiel  -  usage interne uniquement",
             align="L")
    pdf.cell(W / 2, 5,
             f"XUD-BANK Security System  ·  p. {pdf.page_no()}",
             align="R", ln=True)

    # ── Output ────────────────────────────────────────────────────────────────
    pdf_content = pdf.output()

    return Response(
        content=bytes(pdf_content),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'inline; filename="rapport_comptabilite_'
                f'{datetime.utcnow().strftime("%Y%m%d_%H%M")}.pdf"'
            )
        }
    )