# ============================================================
# XUD-BANK — secureDataMonitor/services/logger.py
# Journalisation double cible : fichier + base de données
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================
#
# Double journalisation :
#   1. Fichier logs/security.log (RotatingFileHandler, 5MB × 3)
#   2. Table security_events en base PostgreSQL
#
# Champs journalisés (exigences complètes) :
#   date/heure, utilisateur, IP source, type d'événement,
#   gravité, détail, action entreprise, statut final
# ============================================================

import uuid
import logging
import logging.handlers
import os
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_event import SecurityEvent, EventType, SeverityLevel, EventStatus
from app.models.alert import Alert
from app.config import get_settings

settings = get_settings()


# ════════════════════════════════════════════════════════════
# CONFIGURATION DU LOGGER FICHIER
# ════════════════════════════════════════════════════════════

def setup_file_logger() -> logging.Logger:
    """
    Configure le logger fichier avec rotation automatique.
    Appelé une seule fois au démarrage dans main.py.

    Format structuré :
    2026-03-27 14:32:11 | MEDIUM | LOGIN_FAILED | jdoe | 192.168.1.45 | message
    """
    # Crée le dossier logs/ si inexistant
    os.makedirs(os.path.dirname(settings.LOG_FILE_PATH), exist_ok=True)

    file_logger = logging.getLogger("xud_bank.security")
    file_logger.setLevel(logging.DEBUG)

    # Évite les doublons si appelé plusieurs fois
    if file_logger.handlers:
        return file_logger

    # Handler fichier avec rotation
    handler = logging.handlers.RotatingFileHandler(
        filename=settings.LOG_FILE_PATH,
        maxBytes=settings.LOG_MAX_BYTES,
        backupCount=settings.LOG_BACKUP_COUNT,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    file_logger.addHandler(handler)

    # Handler console (dev)
    if settings.DEBUG:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        file_logger.addHandler(console)

    return file_logger


# Instance du logger fichier
_file_logger = setup_file_logger()


# ════════════════════════════════════════════════════════════
# JOURNALISATION EN BASE DE DONNÉES
# ════════════════════════════════════════════════════════════

async def log_event(
    db: AsyncSession,
    event_type: EventType,
    severity: SeverityLevel,
    ip_address: str,
    description: str,
    username: str | None = None,
    action_taken: str | None = None,
    status: EventStatus = EventStatus.open,
) -> SecurityEvent:
    """
    Journalise un événement de sécurité :
      1. Dans la table security_events (BDD)
      2. Dans le fichier logs/security.log

    Retourne l'objet SecurityEvent créé (pour récupérer son id
    et le passer à create_alert).

    Args:
        db           : session BDD async
        event_type   : type d'événement (EventType enum)
        severity     : niveau de gravité (SeverityLevel enum)
        ip_address   : IP source de la requête
        description  : détail complet de l'événement
        username     : utilisateur impliqué (None si inconnu)
        action_taken : action automatique déclenchée
        status       : statut initial (open par défaut)
    """
    # ── 1. Persistance BDD ────────────────────────────────────
    event = SecurityEvent(
        timestamp=datetime.utcnow(),
        username=username,
        ip_address=ip_address,
        event_type=event_type,
        severity=severity,
        description=description,
        status=status,
        action_taken=action_taken,
    )
    db.add(event)
    await db.flush()   # obtenir l'id sans commit

    # ── 2. Fichier log structuré ──────────────────────────────
    _write_to_file(
        severity=severity,
        event_type=event_type,
        username=username,
        ip_address=ip_address,
        description=description,
        action_taken=action_taken,
        status=status,
        event_id=event.id,
    )

    return event


def _write_to_file(
    severity: SeverityLevel,
    event_type: EventType,
    username: str | None,
    ip_address: str,
    description: str,
    action_taken: str | None,
    status: EventStatus,
    event_id: uuid.UUID,
) -> None:
    """
    Écrit une ligne structurée dans security.log.

    Format :
    SEVERITY | EVENT_TYPE | user=X | ip=X | description | action=X | status=X | id=X
    """
    line = (
        f"{severity.value:<8} | "
        f"{event_type.value:<22} | "
        f"user={username or 'anonymous':<20} | "
        f"ip={ip_address:<16} | "
        f"{description[:120]:<120} | "
        f"action={action_taken or 'none':<40} | "
        f"status={status.value} | "
        f"id={event_id}"
    )

    # Niveau Python selon severity
    level_map = {
        SeverityLevel.LOW:      logging.INFO,
        SeverityLevel.MEDIUM:   logging.WARNING,
        SeverityLevel.HIGH:     logging.ERROR,
        SeverityLevel.CRITICAL: logging.CRITICAL,
    }
    _file_logger.log(level_map[severity], line)


# ════════════════════════════════════════════════════════════
# CRÉATION D'ALERTES
# ════════════════════════════════════════════════════════════

async def create_alert(
    db: AsyncSession,
    level: SeverityLevel,
    source_event_id: uuid.UUID,
    message: str,
) -> Alert:
    """
    Crée une alerte en base de données liée à un security_event.
    Également loggée dans le fichier avec préfixe [ALERT].

    Args:
        db               : session BDD async
        level            : niveau d'alerte (LOW/MEDIUM/HIGH/CRITICAL)
        source_event_id  : UUID de l'événement déclencheur
        message          : message descriptif de l'alerte
    """
    alert = Alert(
        timestamp=datetime.utcnow(),
        alert_level=level,
        source_event_id=source_event_id,
        message=message,
        resolved=False,
    )
    db.add(alert)
    await db.flush()

    # Log fichier
    level_map = {
        SeverityLevel.LOW:      logging.INFO,
        SeverityLevel.MEDIUM:   logging.WARNING,
        SeverityLevel.HIGH:     logging.ERROR,
        SeverityLevel.CRITICAL: logging.CRITICAL,
    }
    _file_logger.log(
        level_map[level],
        f"[ALERT-{level.value}] {message[:150]} | alert_id={alert.id} | event_id={source_event_id}"
    )

    return alert


# ════════════════════════════════════════════════════════════
# UTILITAIRES
# ════════════════════════════════════════════════════════════

async def resolve_alert(db: AsyncSession, alert_id: uuid.UUID) -> Alert | None:
    """Marque une alerte comme résolue."""
    from sqlalchemy import select
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert:
        alert.resolved = True
        await db.flush()
        _file_logger.info(f"[ALERT-RESOLVED] alert_id={alert_id}")
    return alert


async def close_event(db: AsyncSession, event_id: uuid.UUID) -> SecurityEvent | None:
    """Passe un security_event en statut 'closed'."""
    from sqlalchemy import select
    result = await db.execute(select(SecurityEvent).where(SecurityEvent.id == event_id))
    event = result.scalar_one_or_none()
    if event:
        event.status = EventStatus.closed
        await db.flush()
    return event