# ============================================================
# XUD-BANK — secureDataMonitor/routers/admin.py
# Routes du tableau de bord sécurité (SOC / Admin)
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================

import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
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
templates = Jinja2Templates(directory="secureDataMonitor/templates")


# ════════════════════════════════════════════════════════════
# MIDDLEWARE — Vérification accès admin (Règle 3)
# ════════════════════════════════════════════════════════════

async def _require_admin_or_analyst(request: Request, db: AsyncSession) -> dict:
    """Vérifie rôle admin ou analyste, émet événement si refus."""
    from secureDataMonitor.events.dispatcher import dispatcher
    try:
        user_data = require_role("admin", "analyste")(request)
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
    user_data: dict = Depends(require_role("admin", "analyste")),
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

    # Compteurs
    total_events = (await db.execute(select(func.count(SecurityEvent.id)))).scalar_one()
    unresolved_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.resolved == False)
    )).scalar_one()
    locked_accounts = (await db.execute(
        select(func.count(User.id)).where(User.is_locked == True)
    )).scalar_one()
    sqli_attempts = (await db.execute(
        select(func.count(SecurityEvent.id))
        .where(SecurityEvent.event_type == EventType.SQL_INJECTION)
    )).scalar_one()

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

    return templates.TemplateResponse("admin/index.html", {
        "request": request,
        "user": user_data,
        "stats": {
            "total_events": total_events,
            "unresolved_alerts": unresolved_alerts,
            "locked_accounts": locked_accounts,
            "sqli_attempts": sqli_attempts,
        },
        "recent_events": recent_events,
        "recent_alerts": recent_alerts,
        "top_ips": top_ips,
        "severity_stats": severity_stats,
    })


# ════════════════════════════════════════════════════════════
# GET /admin/dashboard — Tableau de bord sécurité temps réel
# ════════════════════════════════════════════════════════════

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_role("admin", "analyste")),
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
    user_data: dict = Depends(require_role("admin", "analyste")),
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
    user_data: dict = Depends(require_role("admin", "analyste")),
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
    user_data: dict = Depends(require_role("admin", "analyste")),
):
    """Marque une alerte comme résolue."""
    import uuid
    await resolve_alert(db, uuid.UUID(alert_id))
    await db.commit()
    log.info(f"[ADMIN] Alerte {alert_id} résolue par {user_data['username']}")
    return RedirectResponse(url="/admin/alerts", status_code=302)