# ============================================================
# XUD-BANK — secureDataMonitor/events/handlers.py
# Gestionnaires d'événements (Handlers)
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================
#
# Chaque handler :
#   1. Reçoit les données de l'événement (dict)
#   2. Appelle detection.py pour vérifier les règles
#   3. Appelle logger.py pour journaliser
#   4. Déclenche une alerte si règle franchie
#   5. Effectue l'action automatique (verrouillage, blocage...)
#
# Enregistrement des handlers → register_all_handlers()
# Appelé une seule fois dans main.py au démarrage
# ============================================================

import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models.security_event import EventType, SeverityLevel
from secureDataMonitor.services import detection, logger as sec_logger
from secureDataMonitor.events.dispatcher import dispatcher
from secureDataMonitor.routers.api_alerts import broadcast_alert, broadcast_event

log = logging.getLogger("secureDataMonitor.handlers")


# ════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════

async def _get_session() -> AsyncSession:
    """Ouvre une session BDD indépendante pour les handlers."""
    return AsyncSessionLocal()


# ════════════════════════════════════════════════════════════
# 8.1 — ÉVÉNEMENTS D'AUTHENTIFICATION
# ════════════════════════════════════════════════════════════

async def handle_login_success(data: dict) -> None:
    """
    Événement : LOGIN_SUCCESS
    Actions   : log, reset compteur échecs
    """
    async with AsyncSessionLocal() as db:
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.LOGIN_SUCCESS,
            severity=SeverityLevel.LOW,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"Connexion réussie pour {data.get('username')}",
            action_taken="Reset compteur échecs",
        )
        await broadcast_event(event)
        await detection.reset_failed_attempts(db, data["username"])
        await db.commit()

    log.info(f"[LOGIN_SUCCESS] {data.get('username')} depuis {data['ip']}")


async def handle_failed_login(data: dict) -> None:
    """
    Événement : LOGIN_FAILED
    Règle 1   : 3 échecs < 2 min → MEDIUM + verrouillage
    """
    async with AsyncSessionLocal() as db:
        # Enregistre la tentative
        await detection.record_login_attempt(
            db, ip=data["ip"], username=data["username"], success=False
        )

        # Vérifie Règle 1
        brute_force = await detection.check_brute_force(
            db, username=data["username"], ip=data["ip"]
        )

        action = "Compteur échecs incrémenté"

        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.LOGIN_FAILED,
            severity=SeverityLevel.MEDIUM,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"Échec connexion #{data.get('attempt', '?')} pour '{data.get('username')}' depuis {data['ip']}",
            action_taken=action,
        )
        await broadcast_event(event)

        if brute_force:
            # Verrouillage du compte
            await detection.lock_account(db, data["username"])
            alert = await sec_logger.create_alert(
                db=db,
                level=SeverityLevel.MEDIUM,
                source_event_id=event.id,
                message=f"Brute force détecté : compte '{data['username']}' verrouillé après 3 échecs depuis {data['ip']}",
            )
            await broadcast_alert(alert)
            # Émet un événement secondaire de verrouillage
            await dispatcher.emit("account_locked", {
                "username": data["username"],
                "ip": data["ip"],
            })

        await db.commit()

    log.warning(f"[LOGIN_FAILED] {data.get('username')} depuis {data['ip']}")


async def handle_account_locked(data: dict) -> None:
    """
    Événement : LOGIN_LOCKED
    Actions   : log, alerte MEDIUM
    """
    async with AsyncSessionLocal() as db:
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.LOGIN_LOCKED,
            severity=SeverityLevel.MEDIUM,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"Compte '{data['username']}' verrouillé suite à brute force depuis {data['ip']}",
            action_taken="Compte verrouillé (is_locked=TRUE)",
        )
        await broadcast_event(event)
        await db.commit()

    log.warning(f"[LOGIN_LOCKED] Compte {data['username']} verrouillé")


async def handle_unknown_user(data: dict) -> None:
    """
    Événement : UNKNOWN_USER
    Actions   : log, tracking IP pour Règle 5
    """
    async with AsyncSessionLocal() as db:
        await detection.record_login_attempt(
            db, ip=data["ip"], username=data["username"], success=False
        )

        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.UNKNOWN_USER,
            severity=SeverityLevel.MEDIUM,
            username=None,
            ip_address=data["ip"],
            description=f"Tentative sur utilisateur inexistant : '{data['username']}' depuis {data['ip']}",
            action_taken="Tracking IP activé",
        )
        await broadcast_event(event)

        # Vérifie Règle 5 (énumération)
        enum_detected = await detection.check_enumeration(db, ip=data["ip"])
        if enum_detected:
            await dispatcher.emit("enum_attempt", {
                "ip": data["ip"],
                "source_event_id": event.id,
            })

        await db.commit()

    log.warning(f"[UNKNOWN_USER] '{data['username']}' depuis {data['ip']}")


# ════════════════════════════════════════════════════════════
# 8.2 — ÉVÉNEMENTS D'AUTORISATION
# ════════════════════════════════════════════════════════════

async def handle_unauthorized(data: dict) -> None:
    """
    Événement : UNAUTHORIZED_ACCESS
    Règle 3   : accès /admin/ sans rôle admin → HIGH
    """
    async with AsyncSessionLocal() as db:
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.UNAUTHORIZED_ACCESS,
            severity=SeverityLevel.HIGH,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"Accès non autorisé à '{data.get('path')}' par '{data.get('username')}' (rôle={data.get('role')})",
            action_taken="Redirection 403",
        )
        await broadcast_event(event)
        alert = await sec_logger.create_alert(
            db=db,
            level=SeverityLevel.HIGH,
            source_event_id=event.id,
            message=f"Accès non autorisé à {data.get('path')} par {data.get('username')} (rôle={data.get('role')})",
        )
        await broadcast_alert(alert)
        await db.commit()

    log.error(f"[UNAUTHORIZED] {data.get('username')} → {data.get('path')}")


async def handle_privilege_escalation(data: dict) -> None:
    """
    Événement : PRIVILEGE_ESCALATION
    Actions   : log, alerte HIGH, blocage requête
    """
    async with AsyncSessionLocal() as db:
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.PRIVILEGE_ESCALATION,
            severity=SeverityLevel.HIGH,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"Tentative d'élévation de privilège par '{data.get('username')}' : {data.get('detail')}",
            action_taken="Requête bloquée",
        )
        await broadcast_event(event)
        alert = await sec_logger.create_alert(
            db=db,
            level=SeverityLevel.HIGH,
            source_event_id=event.id,
            message=f"Élévation de privilège détectée pour {data.get('username')}",
        )
        await broadcast_alert(alert)
        await db.commit()

    log.error(f"[PRIV_ESCALATION] {data.get('username')}")


# ════════════════════════════════════════════════════════════
# 8.3 — ÉVÉNEMENTS APPLICATIFS
# ════════════════════════════════════════════════════════════

async def handle_rate_limit(data: dict) -> None:
    """
    Événement : RATE_LIMIT
    Actions   : log, alerte MEDIUM
    """
    async with AsyncSessionLocal() as db:
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.RATE_LIMIT,
            severity=SeverityLevel.MEDIUM,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"Pic de requêtes détecté depuis {data['ip']} : {data.get('count')} req en {data.get('window')}s",
            action_taken="Throttle IP appliqué",
        )
        await broadcast_event(event)
        alert = await sec_logger.create_alert(
            db=db,
            level=SeverityLevel.MEDIUM,
            source_event_id=event.id,
            message=f"Rate limit dépassé depuis {data['ip']} ({data.get('count')} req/{data.get('window')}s)",
        )
        await broadcast_alert(alert)
        await db.commit()

    log.warning(f"[RATE_LIMIT] {data['ip']} — {data.get('count')} requêtes")


async def handle_mass_access(data: dict) -> None:
    """
    Événement : MASS_DATA_ACCESS
    Règle 4   : >20 consultations < 1 min → CRITICAL
    """
    async with AsyncSessionLocal() as db:
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.MASS_DATA_ACCESS,
            severity=SeverityLevel.CRITICAL,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"Exfiltration massive détectée : {data.get('count')} consultations en {data.get('window')}s par '{data.get('username')}'",
            action_taken="Alerte CRITICAL créée, session signalée",
        )
        await broadcast_event(event)
        alert = await sec_logger.create_alert(
            db=db,
            level=SeverityLevel.CRITICAL,
            source_event_id=event.id,
            message=f"EXFILTRATION MASSIVE : {data.get('count')} accès aux données sensibles en moins d'1 minute par {data.get('username')} depuis {data['ip']}",
        )
        await broadcast_alert(alert)
        await db.commit()

    log.critical(f"[MASS_ACCESS] {data.get('username')} — {data.get('count')} accès")


async def handle_off_hours(data: dict) -> None:
    """
    Événement : OFF_HOURS_ACCESS
    Actions   : log, alerte LOW
    """
    async with AsyncSessionLocal() as db:
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.OFF_HOURS_ACCESS,
            severity=SeverityLevel.LOW,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"Accès hors horaires ({data.get('hour')}h UTC) par '{data.get('username')}'",
            action_taken="Événement loggé",
        )
        await broadcast_event(event)
        alert = await sec_logger.create_alert(
            db=db,
            level=SeverityLevel.LOW,
            source_event_id=event.id,
            message=f"Connexion hors plage autorisée (07h-20h) : {data.get('username')} à {data.get('hour')}h UTC",
        )
        await broadcast_alert(alert)
        await db.commit()

    log.info(f"[OFF_HOURS] {data.get('username')} à {data.get('hour')}h UTC")


# ════════════════════════════════════════════════════════════
# 8.4 — ÉVÉNEMENTS D'ATTAQUE
# ════════════════════════════════════════════════════════════

async def handle_sql_injection(data: dict) -> None:
    """
    Événement : SQL_INJECTION
    Règle 2   : pattern SQL détecté → HIGH + rejet
    """
    async with AsyncSessionLocal() as db:
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"Pattern SQL injection dans champ '{data.get('field')}' : {data.get('payload')[:100]}",
            action_taken="Requête rejetée immédiatement",
        )
        await broadcast_event(event)
        alert = await sec_logger.create_alert(
            db=db,
            level=SeverityLevel.HIGH,
            source_event_id=event.id,
            message=f"SQL Injection détectée depuis {data['ip']} — payload: {data.get('payload')[:80]}",
        )
        await broadcast_alert(alert)
        await db.commit()

    log.error(f"[SQL_INJECTION] {data['ip']} — champ: {data.get('field')}")


async def handle_enum_attempt(data: dict) -> None:
    """
    Événement : ENUM_ATTEMPT
    Règle 5   : même IP, 3 usernames différents < 5 min → MEDIUM
    """
    async with AsyncSessionLocal() as db:
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.ENUM_ATTEMPT,
            severity=SeverityLevel.MEDIUM,
            username=None,
            ip_address=data["ip"],
            description=f"Énumération d'identifiants détectée depuis {data['ip']} : plusieurs comptes ciblés en moins de 5 minutes",
            action_taken="IP signalée, alerte MEDIUM créée",
        )
        await broadcast_event(event)
        alert = await sec_logger.create_alert(
            db=db,
            level=SeverityLevel.MEDIUM,
            source_event_id=event.id,
            message=f"Tentative d'énumération depuis {data['ip']} : {data.get('count', 3)} usernames différents en 5 minutes",
        )
        await broadcast_alert(alert)
        await db.commit()

    log.warning(f"[ENUM_ATTEMPT] IP {data['ip']}")


async def handle_suspicious_url(data: dict) -> None:
    """
    Événement : SUSPICIOUS_URL
    Actions   : log, alerte HIGH, blocage
    """
    async with AsyncSessionLocal() as db:
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.SUSPICIOUS_URL,
            severity=SeverityLevel.HIGH,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"URL suspecte détectée depuis {data['ip']} : {data.get('url')}",
            action_taken="Requête bloquée (403)",
        )
        await broadcast_event(event)
        alert = await sec_logger.create_alert(
            db=db,
            level=SeverityLevel.HIGH,
            source_event_id=event.id,
            message=f"URL suspecte / path traversal depuis {data['ip']} : {data.get('url')}",
        )
        await broadcast_alert(alert)
        await db.commit()

    log.error(f"[SUSPICIOUS_URL] {data['ip']} → {data.get('url')}")


# ════════════════════════════════════════════════════════════
# ENREGISTREMENT DE TOUS LES HANDLERS
# ════════════════════════════════════════════════════════════

def register_all_handlers() -> None:
    """
    Abonne tous les handlers au dispatcher.
    Appelé une seule fois dans main.py au démarrage (lifespan).
    """
    # Auth
    dispatcher.subscribe("login_success",    handle_login_success)
    dispatcher.subscribe("login_failed",     handle_failed_login)
    dispatcher.subscribe("account_locked",   handle_account_locked)
    dispatcher.subscribe("unknown_user",     handle_unknown_user)

    # Autorisation
    dispatcher.subscribe("unauthorized",          handle_unauthorized)
    dispatcher.subscribe("privilege_escalation",  handle_privilege_escalation)

    # Applicatifs
    dispatcher.subscribe("rate_limit",       handle_rate_limit)
    dispatcher.subscribe("mass_data_access", handle_mass_access)
    dispatcher.subscribe("off_hours_access", handle_off_hours)

    # Attaques
    dispatcher.subscribe("sql_injection",    handle_sql_injection)
    dispatcher.subscribe("enum_attempt",     handle_enum_attempt)
    dispatcher.subscribe("suspicious_url",   handle_suspicious_url)

    log.info(f"Handlers enregistrés : {dispatcher.list_events()}")