# ============================================================
# XUD-BANK — secureDataMonitor/routers/admin.py
# Routes du tableau de bord sécurité (SOC / Admin)
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================

import logging
import time
from datetime import datetime, timedelta
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from app.templates_config import templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc

from app.database import get_db
from app.config import get_settings
from app.models.user import User
from app.models.security_event import SecurityEvent, SeverityLevel, EventType
from app.models.alert import Alert
from app.services.auth_service import require_role, get_current_user_data
from secureDataMonitor.services.logger import resolve_alert, close_event

settings = get_settings()
log = logging.getLogger("xud_bank.router.admin")

router = APIRouter(prefix="/admin", tags=["admin"])

# ════════════════════════════════════════════════════════════
# CACHE — Dashboard stats avec TTL de 5 secondes
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
# MIDDLEWARE — Vérification accès admin (Règle 3)
# ════════════════════════════════════════════════════════════

async def _require_admin_or_analyst(request: Request, db: AsyncSession) -> dict:
    """Vérifie rôle admin ou analyste, émet événement si refus."""
    from secureDataMonitor.events.dispatcher import dispatcher
    try:
        user_data = require_role("admin", "directeur")(request)
        return user_data
    except HTTPException:
        user_data = get_current_user_data(request)
        await dispatcher.emit("unauthorized", {
            "ip": request.client.host,
            "username": user_data.get("username"),
            "role": user_data.get("role"),
            "path": str(request.url.path),
        })
        raise


# ════════════════════════════════════════════════════════════
# GET /admin/ — Vue synthèse principale
# ════════════════════════════════════════════════════════════

@router.get("/", response_class=HTMLResponse)
async def admin_index(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("admin", "directeur")),
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

    return templates.TemplateResponse("admin/index.html", {
        "request": request,
        "user": user_data,
        "stats": stats,
        "recent_alerts": recent_alerts,
        "severity_stats": alert_severity_stats,
        "chart_data": chart_data,
    })


# ════════════════════════════════════════════════════════════
# GET /admin/dashboard — Tableau de bord sécurité temps réel
# ════════════════════════════════════════════════════════════

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("admin", "directeur")),
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
    severity_result = await db.execute(
        select(SecurityEvent.severity, func.count(SecurityEvent.id).label("count"))
        .where(SecurityEvent.timestamp >= last_24h)
        .group_by(SecurityEvent.severity)
    )
    severity_data = {row.severity.value: row.count for row in severity_result.all()}

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user_data,
        "events_by_hour": events_by_hour,
        "alerts": alerts,
        "events": events,
        "severity_data": severity_data,
        "ws_url": f"ws://{request.headers.get('host')}/ws/alerts",
    })


# ════════════════════════════════════════════════════════════
# GET /admin/users — Gestion utilisateurs
# ════════════════════════════════════════════════════════════

@router.get("/users", response_class=HTMLResponse)
async def admin_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("admin")),
):
    """Liste des utilisateurs avec actions de verrouillage/déverrouillage."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()

    return templates.TemplateResponse("admin/users.html", {
        "request": request,
        "user": user_data,
        "users": users,
    })


@router.post("/users/{username}/lock")
async def lock_user(
    username: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("admin")),
):
    """Verrouille un compte utilisateur (admin uniquement)."""
    from secureDataMonitor.services.detection import lock_account
    await lock_account(db, username)
    await db.commit()
    log.info(f"[ADMIN] {user_data['username']} a verrouillé '{username}'")
    return RedirectResponse(url="/admin/users", status_code=302)


@router.post("/users/{username}/unlock")
async def unlock_user(
    username: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("admin")),
):
    """Déverrouille un compte utilisateur (admin uniquement)."""
    from app.services.auth_service import unlock_account
    await unlock_account(db, username)
    await db.commit()
    log.info(f"[ADMIN] {user_data['username']} a déverrouillé '{username}'")
    return RedirectResponse(url="/admin/users", status_code=302)


# ════════════════════════════════════════════════════════════
# GET /admin/events — Historique security_events
# ════════════════════════════════════════════════════════════

@router.get("/events", response_class=HTMLResponse)
async def admin_events(
    request: Request,
    severity: str = None,
    event_type: str = None,
    page: int = 1,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("admin", "directeur")),
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

    return templates.TemplateResponse("admin/events.html", {
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
# GET /admin/alerts — Gestion des alertes
# ════════════════════════════════════════════════════════════

@router.get("/alerts", response_class=HTMLResponse)
async def admin_alerts(
    request: Request,
    resolved: str = "false",
    page: int = 1,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("admin", "directeur")),
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

    return templates.TemplateResponse("admin/alerts.html", {
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
    user_data: dict = Depends(require_role("admin", "directeur")),
):
    """Marque une alerte comme résolue."""
    import uuid
    await resolve_alert(db, uuid.UUID(alert_id))
    await db.commit()
    log.info(f"[ADMIN] Alerte {alert_id} résolue par {user_data['username']}")
    return RedirectResponse(url="/admin/alerts", status_code=302)

# GET /admin/users/new — Formulaire création utilisateur
@router.get("/users/new", response_class=HTMLResponse)
async def new_user_page(
    request: Request,
    user_data: dict = Depends(require_role("admin", "directeur")),
):
    return templates.TemplateResponse("admin/new_user.html", {
        "request": request,
        "user": user_data,
        "roles": ["admin", "directeur", "comptable", "utilisateur"],
    })


# POST /admin/users/new — Création
@router.post("/users/new", response_class=HTMLResponse)
async def create_user_admin(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("admin", "directeur")),
):
    from app.services.auth_service import create_user, UserRole
    try:
        await create_user(db, username=username, email=email,
                         password=password, role=UserRole(role))
        await db.commit()
        return RedirectResponse(url="/admin/users?created=1", status_code=302)
    except Exception as e:
        error_str = str(e).lower()
        if "unique" in error_str or "duplicate" in error_str:
            error = "Ce nom d'utilisateur ou email est déjà pris."
        else:
            error = "Une erreur est survenue."
        return templates.TemplateResponse("admin/new_user.html", {
            "request": request,
            "user": user_data,
            "roles": ["admin", "directeur", "comptable", "utilisateur"],
            "error": error,
        })


# ════════════════════════════════════════════════════════════
# GET /admin/logs/raw — Affichage brut du fichier de log
# ════════════════════════════════════════════════════════════

@router.get("/logs/raw")
async def view_raw_logs(
    request: Request,
    user_data: dict = Depends(require_role("admin", "directeur")),
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