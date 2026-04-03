# ============================================================
# XUD-BANK  -  app/routers/direction.py
# Routes de la direction générale (Gestion Personnel)
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================
from __future__ import annotations

import logging
import uuid
import time
import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from app.services.report_service import ReportService
from app.config import templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc

from app.database import get_db
from app.config import get_settings
from app.models.user import User
from app.models.bank_account import BankAccount, AccountClassification
from app.models.security_event import SecurityEvent, SeverityLevel, EventType
from app.models.alert import Alert
from app.services.auth_service import require_role, get_current_user_data
from secureDataMonitor.services.logger import resolve_alert, close_event

settings = get_settings()
log = logging.getLogger("xud_bank.router.admin")

router = APIRouter(prefix="/direction", tags=["direction"])

# ════════════════════════════════════════════════════════════
# CACHE  -  Dashboard stats avec TTL de 5 secondes
# ════════════════════════════════════════════════════════════

_dashboard_cache = {"data": None, "timestamp": 0}
CACHE_TTL = 5  # seconds


async def get_dashboard_stats(db: AsyncSession):
    """
    Récupère les statistiques du dashboard avec cache 5s.
    Combine les COUNT queries en une seule requête SQL.
    """
    now = time.time()
    if _dashboard_cache["data"] and (now - _dashboard_cache["timestamp"]) < CACHE_TTL:
        return _dashboard_cache["data"]

    # Requête combinée pour les compteurs (SecurityEvent + Alert + User)
    # Utilise COUNT(*) FILTER (WHERE ...) pour compter conditionnellement
    stats_query = select(
        func.count(SecurityEvent.id).label("total_events"),
        func.count(SecurityEvent.id).filter(SecurityEvent.event_type == EventType.SQL_INJECTION).label("sqli_attempts"),
    ).select_from(SecurityEvent)

    # Requête séparée pour les alertes non résolues (table différente)
    alerts_query = select(
        func.count(Alert.id).label("unresolved_alerts")
    ).where(Alert.resolved == False)

    # Requête séparée pour les comptes verrouillés (table différente)
    users_query = select(
        func.count(User.id).label("locked_accounts")
    ).where(User.is_locked == True)

    # Exécution en parallèle des 3 requêtes (une par table)
    stats_result = await db.execute(stats_query)
    alerts_result = await db.execute(alerts_query)
    users_result = await db.execute(users_query)

    stats_row = stats_result.one()
    alerts_row = alerts_result.one()
    users_row = users_result.one()

    stats = {
        "total_events": stats_row.total_events,
        "sqli_attempts": stats_row.sqli_attempts,
        "unresolved_alerts": alerts_row.unresolved_alerts,
        "locked_accounts": users_row.locked_accounts,
    }

    _dashboard_cache["data"] = stats
    _dashboard_cache["timestamp"] = now
    return stats


# ════════════════════════════════════════════════════════════
# MIDDLEWARE  -  Vérification accès admin (Règle 3)
# ════════════════════════════════════════════════════════════

async def _require_admin_or_analyst(request: Request, db: AsyncSession) -> dict:
    """Vérifie rôle admin ou directeur, émet événement si refus d'accès."""
    from secureDataMonitor.events.dispatcher import dispatcher
    
    try:
        user_data = get_current_user_data(request)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            await dispatcher.emit("unauthorized", {
                "ip": request.client.host,
                "username": "anonymous",
                "role": "none",
                "path": str(request.url.path),
                "reason": "token absent ou expiré"
            })
            raise
        raise

    allowed_roles = {"soc", "directeur"}
    if user_data.get("role") not in allowed_roles:
        await dispatcher.emit("unauthorized", {
            "ip": request.client.host,
            "username": user_data.get("username"),
            "role": user_data.get("role"),
            "path": str(request.url.path),
            "reason": "rôle insuffisant"
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès refusé : droits insuffisants",
        )

    return user_data


# ════════════════════════════════════════════════════════════
# GET /admin/  -  Vue synthèse principale
# ════════════════════════════════════════════════════════════

@router.get("/", response_class=HTMLResponse)
async def admin_index(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """
    Vue principale admin/SOC :
    - Compteurs globaux
    - Dernières alertes critiques
    - Derniers événements
    - Top IPs suspectes
    """
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)

    # Compteurs optimisés avec cache (combine les COUNT en requêtes groupées)
    stats = await get_dashboard_stats(db)

    # Derniers 10 événements
    recent_events_result = await db.execute(
        select(SecurityEvent)
        .order_by(desc(SecurityEvent.timestamp))
        .limit(10)
    )
    recent_events = recent_events_result.scalars().all()

    # Dernières 10 alertes non résolues
    recent_alerts_result = await db.execute(
        select(Alert)
        .where(Alert.resolved == False)
        .order_by(desc(Alert.timestamp))
        .limit(10)
    )
    recent_alerts = recent_alerts_result.scalars().all()

    # Top 5 IPs suspectes (dernières 24h)
    top_ips_result = await db.execute(
        select(SecurityEvent.ip_address, func.count(SecurityEvent.id).label("count"))
        .where(SecurityEvent.timestamp >= last_24h)
        .group_by(SecurityEvent.ip_address)
        .order_by(desc("count"))
        .limit(5)
    )
    top_ips = top_ips_result.all()

    # Répartition par severity (dernières 24h)
    severity_stats_result = await db.execute(
        select(SecurityEvent.severity, func.count(SecurityEvent.id).label("count"))
        .where(SecurityEvent.timestamp >= last_24h)
        .group_by(SecurityEvent.severity)
    )
    severity_stats = {row.severity.value: row.count for row in severity_stats_result.all()}

    # Données graphe alertes par heure et severity (24h)
    chart_result = await db.execute(
        select(
            func.date_trunc("hour", Alert.timestamp).label("hour"),
            Alert.alert_level,
            func.count(Alert.id).label("count"),
        )
        .where(Alert.timestamp >= last_24h)
        .group_by("hour", Alert.alert_level)
        .order_by("hour")
    )
    chart_rows = chart_result.all()

    slots = []
    slot = last_24h.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    while slot <= now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1):
        slots.append(slot.strftime('%H:%M'))
        slot += timedelta(hours=1)

    chart_data = {"labels": slots}
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        chart_data[level] = [
            sum(r.count for r in chart_rows
                if str(r.hour)[11:16] == h and r.alert_level.value == level)
            for h in slots
        ]

    # Stats globales alertes par severity
    alert_severity_result = await db.execute(
        select(Alert.alert_level, func.count(Alert.id).label("count"))
        .group_by(Alert.alert_level)
    )
    alert_severity_stats = {r.alert_level.value: r.count for r in alert_severity_result.all()}

    return templates.TemplateResponse("direction/dashboard.html", {
        "request": request,
        "user": user_data,
        "stats": stats,
        "recent_alerts": recent_alerts,
        "severity_stats": alert_severity_stats,
        "chart_data": chart_data,
    })


# ════════════════════════════════════════════════════════════
# GET /direction/dashboard  -  Tableau de bord sécurité temps réel
# ════════════════════════════════════════════════════════════

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """
    Tableau de bord sécurité avec WebSocket pour alertes temps réel.
    Graphe fréquence événements 24h, stats severity, top IPs.
    """
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)

    # Fréquence événements par heure (dernières 24h)
    events_by_hour_result = await db.execute(
        select(
            func.date_trunc("hour", SecurityEvent.timestamp).label("hour"),
            func.count(SecurityEvent.id).label("count"),
        )
        .where(SecurityEvent.timestamp >= last_24h)
        .group_by("hour")
        .order_by("hour")
    )
    events_by_hour = [
        {"hour": str(row.hour), "count": row.count}
        for row in events_by_hour_result.all()
    ]

    # Dernières 10 alertes
    alerts_result = await db.execute(
        select(Alert)
        .order_by(desc(Alert.timestamp))
        .limit(10)
    )
    alerts = alerts_result.scalars().all()

    # Derniers 10 événements
    events_result = await db.execute(
        select(SecurityEvent)
        .order_by(desc(SecurityEvent.timestamp))
        .limit(10)
    )
    events = events_result.scalars().all()

    # Stats severity
    # Stats severity (pour la légende du graphe)
    severity_result = await db.execute(
        select(SecurityEvent.severity, func.count(SecurityEvent.id).label("count"))
        .where(SecurityEvent.timestamp >= last_24h)
        .group_by(SecurityEvent.severity)
    )
    severity_stats = {row.severity.value: row.count for row in severity_result.all()}

    # Data pour le graphe (alertes par heure et severity)
    chart_result = await db.execute(
        select(
            func.date_trunc("hour", Alert.timestamp).label("hour"),
            Alert.alert_level,
            func.count(Alert.id).label("count"),
        )
        .where(Alert.timestamp >= last_24h)
        .group_by("hour", Alert.alert_level)
        .order_by("hour")
    )
    chart_rows = chart_result.all()

    slots = []
    slot = last_24h.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    while slot <= now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1):
        slots.append(slot.strftime('%H:%M'))
        slot += timedelta(hours=1)

    chart_data = {"labels": slots}
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        chart_data[level] = [
            sum(r.count for r in chart_rows
                if str(r.hour)[11:16] == h and r.alert_level.value == level)
            for h in slots
        ]

    # Stats pour les compteurs haut
    stats = await get_dashboard_stats(db)

    return templates.TemplateResponse("direction/dashboard.html", {
        "request": request,
        "user": user_data,
        "stats": stats,
        "severity_stats": severity_stats,
        "chart_data": chart_data,
        "alerts": alerts,
        "events": events,
        "ws_url": f"ws://{request.headers.get('host')}/ws/alerts",
    })


# ════════════════════════════════════════════════════════════
# GET /direction/users  -  Gestion utilisateurs
# ════════════════════════════════════════════════════════════

@router.get("/users", response_class=HTMLResponse)
async def direction_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """Liste du personnel (soc, directeur, comptable) avec action de suppression."""
    from app.models.user import UserRole
    personnel_roles = [UserRole.soc, UserRole.directeur, UserRole.comptable]
    
    result = await db.execute(
        select(User)
        .where(User.role.in_(personnel_roles))
        .order_by(User.created_at.desc())
    )
    users = result.scalars().all()

    return templates.TemplateResponse("direction/users.html", {
        "request": request,
        "user": user_data,
        "users": users,
    })


# GET /direction/users/new  -  Formulaire création utilisateur
@router.get("/users/new", response_class=HTMLResponse)
async def new_user_page(
    request: Request,
    user_data: dict = Depends(require_role("directeur")),
):
    return templates.TemplateResponse("direction/new_user.html", {
        "request": request,
        "user": user_data,
        "roles": ["soc", "directeur", "comptable", "utilisateur"],
    })


# POST /direction/users/new  -  Création
@router.post("/users/new", response_class=HTMLResponse)
async def create_user_admin(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    from app.services.auth_service import create_user, UserRole
    try:
        await create_user(db, username=username, email=email,
                         password=password, role=UserRole(role))
        await db.commit()
        log.info(f"[ADMIN] {user_data['username']} a créé l'utilisateur '{username}'")
        return RedirectResponse(url="/direction/users?created=1", status_code=302)
    except Exception as e:
        error_str = str(e).lower()
        if "unique" in error_str or "duplicate" in error_str:
            error = "Ce nom d'utilisateur ou email est déjà pris."
        else:
            error = "Une erreur est survenue."
        return templates.TemplateResponse("direction/new_user.html", {
            "request": request,
            "user": user_data,
            "roles": ["soc", "directeur", "comptable", "utilisateur"],
            "error": error,
        })


@router.post("/users/{id}/delete")
async def delete_user(
    id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """Supprime un utilisateur (Relever de ses fonctions)."""
    result = await db.execute(select(User).where(User.id == id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    
    if user.id == uuid.UUID(user_data["user_id"]):
         raise HTTPException(status_code=400, detail="Vous ne pouvez pas vous supprimer vous-même")

    await db.delete(user)
    await db.commit()
    log.warning(f"[DIRECTION] {user_data['username']} a rélevé de ses fonctions '{user.username}:{user.email}'")
    return RedirectResponse(url="/direction/users?deleted=1", status_code=302)


# ════════════════════════════════════════════════════════════
# GET /admin/events  -  Historique security_events
# ════════════════════════════════════════════════════════════

@router.get("/events", response_class=HTMLResponse)
async def admin_events(
    request: Request,
    severity: str = None,
    event_type: str = None,
    page: int = 1,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """
    Historique complet des security_events.
    Filtres : severity, event_type. Pagination 20/page.
    """
    per_page = 20
    offset = (page - 1) * per_page

    query = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp))
    count_query = select(func.count(SecurityEvent.id))

    if severity:
        query = query.where(SecurityEvent.severity == severity)
        count_query = count_query.where(SecurityEvent.severity == severity)
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
        count_query = count_query.where(SecurityEvent.event_type == event_type)

    total = (await db.execute(count_query)).scalar_one()
    events_result = await db.execute(query.offset(offset).limit(per_page))
    events = events_result.scalars().all()

    return templates.TemplateResponse("direction/events.html", {
        "request": request,
        "user": user_data,
        "events": events,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
        "severity_filter": severity,
        "event_type_filter": event_type,
        "severity_levels": [s.value for s in SeverityLevel],
        "event_types": [e.value for e in EventType],
    })


# ════════════════════════════════════════════════════════════
# GET /admin/alerts  -  Gestion des alertes
# ════════════════════════════════════════════════════════════

@router.get("/alerts", response_class=HTMLResponse)
async def admin_alerts(
    request: Request,
    resolved: str = "false",
    page: int = 1,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """Alertes actives et résolues avec résolution manuelle."""
    per_page = 20
    offset = (page - 1) * per_page
    show_resolved = resolved.lower() == "true"

    query = (
        select(Alert)
        .where(Alert.resolved == show_resolved)
        .order_by(desc(Alert.timestamp))
    )
    count_query = select(func.count(Alert.id)).where(Alert.resolved == show_resolved)

    total = (await db.execute(count_query)).scalar_one()
    alerts_result = await db.execute(query.offset(offset).limit(per_page))
    alerts = alerts_result.scalars().all()

    unresolved_count = (await db.execute(
        select(func.count(Alert.id)).where(Alert.resolved == False)
    )).scalar_one()

    return templates.TemplateResponse("direction/alerts.html", {
        "request": request,
        "user": user_data,
        "alerts": alerts,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
        "show_resolved": show_resolved,
        "unresolved_count": unresolved_count,
    })


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert_route(
    alert_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """Marque une alerte comme résolue."""
    import uuid
    await resolve_alert(db, uuid.UUID(alert_id))
    await db.commit()
    log.info(f"[ADMIN] Alerte {alert_id} résolue par {user_data['username']}")
    return RedirectResponse(url="/direction/alerts", status_code=302)

# ════════════════════════════════════════════════════════════
# GET /admin/logs/raw  -  Affichage brut du fichier de log
# ════════════════════════════════════════════════════════════

@router.get("/logs/raw")
async def view_raw_logs(
    request: Request,
    user_data: dict = Depends(require_role("directeur")),
):
    """
    Renvoie le contenu brut du fichier security.log
    Affichage sous forme de texte brut dans le navigateur.
    """
    import os
    from fastapi.responses import PlainTextResponse
    
    log_file = settings.LOG_FILE_PATH
    if os.path.exists(log_file):
        # Lecture du fichier (pour de très gros logs, FileResponse serait mieux mais pour notre TP ça ira)
        with open(log_file, "r", encoding="utf-8") as f:
            content = f.read()
            # Si le fichier est vide, on renvoie une phrase propre
            if not content.strip():
                content = "--- Fichier de log vide ---"
        return PlainTextResponse(content)
    
    return PlainTextResponse("Erreur : Fichier de log introuvable sur le serveur.", status_code=404)


# ════════════════════════════════════════════════════════════
# GET /admin/clear-data  -  Page de suppression des données
# ════════════════════════════════════════════════════════════

@router.get("/clear-data", response_class=HTMLResponse)
async def clear_data_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """
    Page de confirmation pour la suppression de toutes les alertes et événements.
    """
    # Compte les alertes et événements actuels
    alerts_count_result = await db.execute(select(func.count(Alert.id)))
    events_count_result = await db.execute(select(func.count(SecurityEvent.id)))
    
    alerts_count = alerts_count_result.scalar_one()
    events_count = events_count_result.scalar_one()
    
    return templates.TemplateResponse("direction/clear_data.html", {
        "request": request,
        "user": user_data,
        "alerts_count": alerts_count,
        "events_count": events_count,
    })


# ════════════════════════════════════════════════════════════
# POST /admin/clear-data  -  Suppression effective
# ════════════════════════════════════════════════════════════

@router.post("/clear-data")
async def clear_all_data(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """
    Supprime toutes les alertes et événements de la base de données.
    Action réservée aux admin et directeur.
    """
    from secureDataMonitor.events.dispatcher import dispatcher
    from fastapi.responses import RedirectResponse
    
    # Émet un événement avant la suppression
    await dispatcher.emit("data_cleared", {
        "ip": request.client.host,
        "username": user_data.get("username"),
        "role": user_data.get("role"),
        "action": "clear_all_alerts_and_events",
    })
    
    # Supprime d'abord les alertes (elles ont une foreign key vers events)
    await db.execute(
        Alert.__table__.delete()
    )
    
    # Puis supprime les événements
    await db.execute(
        SecurityEvent.__table__.delete()
    )
    
    await db.commit()
    
    log.warning(f"[ADMIN] {user_data['username']} a supprimé toutes les alertes et événements")
    
    return RedirectResponse(url="/direction/clear-data?deleted=1", status_code=302)

@router.get("/export-pdf")
async def export_accounts_pdf_direction(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """Génère un rapport PDF global pour la Direction."""
    # La Direction voit TOUS les comptes
    query = select(BankAccount).order_by(BankAccount.id_compte.asc())
    
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
    
    pdf_content = ReportService.generate_accounts_pdf(accounts_data, f"{user_data['username']} (Direction)")
    
    return Response(
        content=bytes(pdf_content),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=rapport_direction_global.pdf"}
    )


# ════════════════════════════════════════════════════════════
# GET /direction/accounts  -  Gestion des comptes bancaires
# ════════════════════════════════════════════════════════════

@router.get("/accounts", response_class=HTMLResponse)
async def direction_accounts(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    """
    Tableau de bord des comptes bancaires pour le directeur.
    Affiche TOUS les comptes (y compris SECRET) avec statistiques.
    """
    from secureDataMonitor.services.detection import record_data_access
    from secureDataMonitor.events.dispatcher import dispatcher
    from app.config import get_settings
    
    settings = get_settings()
    ip = request.client.host
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

    # Récupère TOUS les comptes (le directeur a accès complet)
    query = select(BankAccount).order_by(BankAccount.created_at.desc())
    result = await db.execute(query)
    accounts = result.scalars().all()

    # Préparation des données
    accounts_data = []
    total_solde = 0
    stats = {"public": 0, "confidentiel": 0, "secret": 0}
    
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
        
        total_solde += float(acc.solde)
        stats[acc.classification.value] += 1

    return templates.TemplateResponse("direction/accounts.html", {
        "request": request,
        "user": user_data,
        "accounts": accounts_data,
        "total": len(accounts_data),
        "total_solde": total_solde,
        "stats": stats,
    })


# ════════════════════════════════════════════════════════════
# GET /direction/rapport  -  Rapport détaillé des comptes (PDF)
# ════════════════════════════════════════════════════════════

@router.get("/rapport")
async def direction_rapport_pdf(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("directeur")),
):
    from fpdf import FPDF

    query = select(BankAccount).order_by(
        BankAccount.classification.asc(),
        BankAccount.id_compte.asc()
    )
    result = await db.execute(query)
    accounts = result.scalars().all()

    grouped_accounts = {"public": [], "confidentiel": [], "secret": []}
    totals = {"public": 0, "confidentiel": 0, "secret": 0, "global": 0}
    stats  = {"public": 0, "confidentiel": 0, "secret": 0}

    for acc in accounts:
        historique = []
        if acc.historique:
            try:
                historique = json.loads(acc.historique)
            except:
                pass
        acc_data = {
            "id_compte":      acc.id_compte,
            "titulaire":      acc.titulaire,
            "solde":          float(acc.solde),
            "classification": acc.classification.value,
            "created_at":     acc.created_at,
            "historique":     historique,
        }
        cl = acc.classification.value
        grouped_accounts[cl].append(acc_data)
        totals[cl]       += float(acc.solde)
        totals["global"] += float(acc.solde)
        stats[cl]        += 1

    # ─── Palette ────────────────────────────────────────────────────────────
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
        "secret":       (175, 50,  60),
    }
    SEC_LABELS = {
        "public":       "PUBLIC",
        "confidentiel": "CONFIDENTIEL",
        "secret":       "SECRET",
    }

    # ─── PDF ────────────────────────────────────────────────────────────────
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    W = pdf.w - pdf.l_margin - pdf.r_margin   # largeur utile

    # ── Bandeau header ──────────────────────────────────────────────────────
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, pdf.w, 42, "F")

    pdf.set_y(7)
    pdf.set_font("helvetica", "B", 20)
    pdf.set_text_color(*GOLD)
    pdf.cell(0, 10, "XUD-BANK", ln=False, align="C")

    pdf.set_y(19)
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(*GOLD_LIGHT)
    pdf.cell(0, 6, "RAPPORT DETAILLE DES COMPTES - USAGE INTERNE CONFIDENTIEL", ln=True, align="C")

    pdf.set_y(28)
    pdf.set_font("helvetica", "", 8)
    pdf.set_text_color(*MID_GRAY)
    pdf.cell(0, 5,
             f"Genere le {datetime.utcnow().strftime('%d/%m/%Y a %H:%M UTC')}  -  "
             f"{user_data['username']}  -  Role : Directeur  -  "
             f"Acces : PUBLIC / CONFIDENTIEL / SECRET",
             ln=True, align="C")

    # Trait or doré sous le header
    pdf.set_y(42)
    pdf.set_draw_color(*GOLD)
    pdf.set_line_width(0.6)
    pdf.line(pdf.l_margin, 42, pdf.w - pdf.r_margin, 42)
    pdf.set_line_width(0.2)
    pdf.ln(6)

    # ── Résumé global (4 cards) ─────────────────────────────────────────────
    pdf.set_text_color(*DARK_TEXT)
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(*MID_GRAY)
    pdf.cell(0, 5, "RÉSUMÉ GLOBAL", ln=True)
    pdf.ln(1)

    card_w = W / 4 - 2
    cards = [
        ("Total (XOF)",       f"{totals['global']:,.0f}"),
        ("Comptes total",     str(len(accounts))),
        (f"Public ({stats['public']})",         f"{totals['public']:,.0f} XOF"),
        (f"Confidentiel ({stats['confidentiel']})", f"{totals['confidentiel']:,.0f} XOF"),
    ]

    x0 = pdf.l_margin
    y0 = pdf.get_y()
    for i, (label, value) in enumerate(cards):
        cx = x0 + i * (card_w + 2.5)
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

    # Ajouter card Secret séparément sur la même ligne
    cx = x0 + 3 * (card_w + 2.5)
    pdf.set_fill_color(*LIGHT_BG)
    pdf.set_draw_color(*MID_GRAY)
    pdf.rect(cx, y0, card_w, 18, "FD")
    pdf.set_xy(cx + 2, y0 + 2)
    pdf.set_font("helvetica", "", 7)
    pdf.set_text_color(*MID_GRAY)
    pdf.cell(card_w - 4, 5, f"SECRET ({stats['secret']})".upper(), ln=True)
    pdf.set_xy(cx + 2, y0 + 8)
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(*DARK_TEXT)
    pdf.cell(card_w - 4, 7, f"{totals['secret']:,.0f} XOF")

    pdf.set_y(y0 + 22)
    pdf.ln(6)

    # ── Séparateur ──────────────────────────────────────────────────────────
    def h_rule(pdf, color=MID_GRAY, width=0.3):
        pdf.set_draw_color(*color)
        pdf.set_line_width(width)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(4)

    # ── Section par classification ───────────────────────────────────────────
    COL_W = [38, 52, 32, 40, 16]   # ID · Titulaire · Solde · Créé le · Ops
    HEADERS = ["ID Compte", "Titulaire", "Solde (XOF)", "Créé le", "Opérations"]

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

        # Barre de titre de section
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
            nb_ops = len(acc.get("historique", []))

            row = [
                str(acc["id_compte"]),
                str(acc["titulaire"]),
                f"{acc['solde']:,.2f}",
                date_str,
                str(nb_ops),
            ]
            for w, val in zip(COL_W, row):
                pdf.cell(w, 6, val, border=0, fill=True)
            pdf.ln()

            # Ligne de séparation légère
            pdf.set_draw_color(*ROW_ALT)
            pdf.line(pdf.l_margin, pdf.get_y(),
                     pdf.w - pdf.r_margin, pdf.get_y())

        pdf.ln(6)

    for key in ("public", "confidentiel", "secret"):
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

    # ── Footer ───────────────────────────────────────────────────────────────
    h_rule(pdf, color=GOLD, width=0.5)
    pdf.set_font("helvetica", "I", 7)
    pdf.set_text_color(*MID_GRAY)
    pdf.cell(W / 2, 5,
             "Document confidentiel  -  usage interne uniquement",
             align="L")
    pdf.cell(W / 2, 5,
             f"XUD-BANK Security System  ·  p. {pdf.page_no()}",
             align="R", ln=True)

    # ── Output ───────────────────────────────────────────────────────────────
    pdf_content = pdf.output()

    return Response(
        content=bytes(pdf_content),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'inline; filename="rapport_'
                f'{datetime.utcnow().strftime("%Y%m%d_%H%M")}.pdf"'
            )
        }
    )