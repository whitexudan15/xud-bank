# ============================================================
# XUD-BANK — secureDataMonitor/services/detection.py
# Règles de détection des comportements suspects
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================
#
# 5 règles implémentées :
#   Règle 1 — Brute Force        : 3 échecs < 2 min → verrouillage
#   Règle 2 — Injection SQL      : patterns dans les inputs
#   Règle 3 — Accès admin        : rôle insuffisant → /admin/*
#   Règle 4 — Exfiltration masse : >20 consultations < 1 min
#   Règle 5 — Énumération        : même IP, 3 usernames < 5 min
# ============================================================

import re
import logging
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, distinct

from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_event import SecurityEvent, EventType
from app.config import get_settings

settings = get_settings()
log = logging.getLogger("secureDataMonitor.detection")

# ── Patterns SQL Injection (Règle 2) ──────────────────────────
SQL_INJECTION_PATTERNS = [
    r"(?:'|\"|`)\s*(?:or|and|\|\||&&)\s+[\w'\"` ]+\s*=\s*[\w'\"` ]+",          # ' OR 'a'='a
    r"\b(?:or|and)\s+\d+\s*=\s*\d+",                                            # OR 1=1
    r"\b(?:or|and)\s+(?:true|false|null\s+is\s+null|not\s+false)\b",            # OR true / OR NOT false
    r"\b(?:or|and)\s+'[^']*'\s*like\s*'[^']*'",
        # ── UNION injection (obfusqué lettre par lettre) ─────────────────────────
    r"\bunion\s+(?:all\s+)?select\s+@@version",                                  # version leak
    r"\bunion\s+(?:all\s+)?select\s+(?:user|database|schema)\s*\(",             # info leak

    # ── Stacked queries / terminateurs ───────────────────────────────────────
    r";\s*(?:drop|delete|update|insert|exec|truncate|create|alter)\b",           # ; DROP ...
    r";\s*/\*",                                                                  # ; /*
    r"';\s*\w",                                                                  # '; ANYTHING

    # ── Boolean-based blind ───────────────────────────────────────────────────
    r"'\s+and\s+\d+\s*=\s*\d+\s*--",                                            # ' AND 1=1--

    # ── Encodages & obfuscation ───────────────────────────────────────────────
    r"%(?:27|22|3b|2d%2d|3d|2f%2a)",                                            # URL-encodé : ' " ; -- = /*
    r"(?:%[0-9a-f]{2}){4,}",                                                     # séquence longue d'URL-encoding

    # ── XSS dans contexte SQL / injection mixte ───────────────────────────────
    r"<script[\s>]",
    r"javascript\s*:",
]

SQL_REGEX = re.compile(
    "|".join(SQL_INJECTION_PATTERNS),
    re.IGNORECASE
)

# ── Patterns URL suspects (Règle 3 étendue) ───────────────────
SUSPICIOUS_URL_PATTERNS = [
    r"(?:\.\.[\\/]){2,}",                                                        # ../../..
    r"(?:%2e%2e%2f|%2e%2e/|\.\.%2f){2,}",                                      # encodé
    r"/etc/passwd",
    r"/etc/shadow",
    r"\.php$",
    r"\.asp$",
    r"wp-admin",
    r"phpMyAdmin",
    r"\.env$",
    r"\.git/",
]

URL_REGEX = re.compile(
    "|".join(SUSPICIOUS_URL_PATTERNS),
    re.IGNORECASE
)


# ════════════════════════════════════════════════════════════
# RÈGLE 1 — Brute Force Login
# ════════════════════════════════════════════════════════════

async def record_login_attempt(
    db: AsyncSession,
    ip: str,
    username: str,
    success: bool,
) -> LoginAttempt:
    """Enregistre une tentative de connexion dans login_attempts."""
    attempt = LoginAttempt(
        ip_address=ip,
        username_tried=username,
        success=success,
        timestamp=datetime.utcnow(),
    )
    db.add(attempt)
    await db.flush()
    return attempt


async def check_brute_force(
    db: AsyncSession,
    username: str,
    ip: str,
) -> bool:
    """
    Règle 1 : 3 échecs pour un même username en moins de 2 minutes.
    Retourne True si le seuil est atteint.
    """
    window_start = datetime.utcnow() - timedelta(seconds=settings.BRUTE_FORCE_WINDOW)

    result = await db.execute(
        select(func.count(LoginAttempt.id))
        .where(
            and_(
                LoginAttempt.username_tried == username,
                LoginAttempt.success == False,
                LoginAttempt.timestamp >= window_start,
            )
        )
    )
    count = result.scalar_one()

    if count >= settings.MAX_LOGIN_ATTEMPTS:
        log.warning(f"[Règle 1] Brute force : {count} échecs pour '{username}' en {settings.BRUTE_FORCE_WINDOW}s")
        return True
    return False


async def lock_account(db: AsyncSession, username: str) -> None:
    """Verrouille un compte utilisateur (is_locked = TRUE)."""
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user:
        user.is_locked = True
        user.failed_attempts = settings.MAX_LOGIN_ATTEMPTS
        await db.flush()
        log.warning(f"[Règle 1] Compte '{username}' verrouillé")


async def reset_failed_attempts(db: AsyncSession, username: str) -> None:
    """Remet à zéro le compteur d'échecs après un login réussi."""
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user:
        user.failed_attempts = 0
        user.last_failed_at = None
        await db.flush()


async def increment_failed_attempts(db: AsyncSession, username: str) -> int:
    """Incrémente le compteur d'échecs et met à jour last_failed_at."""
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user:
        user.failed_attempts += 1
        user.last_failed_at = datetime.utcnow()
        await db.flush()
        return user.failed_attempts
    return 0


# ════════════════════════════════════════════════════════════
# RÈGLE 2 — Injection SQL
# ════════════════════════════════════════════════════════════

def check_sql_injection(value: str) -> bool:
    """
    Règle 2 : détecte les patterns SQL injection dans une chaîne.
    Retourne True si un pattern est trouvé.
    Synchrone — utilisé dans les middlewares et routers.
    """
    if not value:
        return False
    match = SQL_REGEX.search(value)
    if match:
        log.warning(f"[Règle 2] SQL injection détectée : '{value[:80]}' (match: '{match.group()}')")
        return True
    return False


def check_suspicious_url(url: str) -> bool:
    """
    Détecte les URL suspectes (path traversal, fichiers sensibles...).
    Retourne True si l'URL est suspecte.
    """
    if not url:
        return False
    match = URL_REGEX.search(url)
    if match:
        log.warning(f"[URL suspecte] '{url}' (match: '{match.group()}')")
        return True
    return False


def check_special_characters(value: str, field: str = "") -> bool:
    """
    Détecte les caractères spéciaux dangereux dans les champs critiques.
    Retourne True si des caractères suspects sont trouvés.
    """
    dangerous = re.search(r"[<>\"';\\/\x00-\x1f]", value)
    if dangerous:
        log.warning(f"[Chars suspects] Champ '{field}' : '{value[:50]}'")
        return True
    return False


# ════════════════════════════════════════════════════════════
# RÈGLE 3 — Accès Admin non autorisé
# ════════════════════════════════════════════════════════════

def check_admin_access(path: str, role: str) -> bool:
    """
    Règle 3 : utilisateur sans rôle admin tente d'accéder à /admin/*.
    Retourne True si l'accès est interdit.
    """
    if path.startswith("/admin") and role != "admin":
        log.warning(f"[Règle 3] Accès /admin refusé pour rôle='{role}'")
        return True
    return False


# ════════════════════════════════════════════════════════════
# RÈGLE 4 — Exfiltration massive
# ════════════════════════════════════════════════════════════

async def check_mass_access(
    db: AsyncSession,
    username: str,
) -> tuple[bool, int]:
    """
    Règle 4 : >20 consultations de données sensibles en moins d'1 minute.
    Retourne (True, count) si le seuil est atteint.
    """
    window_start = datetime.utcnow() - timedelta(seconds=settings.MASS_ACCESS_WINDOW)

    result = await db.execute(
        select(func.count(SecurityEvent.id))
        .where(
            and_(
                SecurityEvent.username == username,
                SecurityEvent.event_type == EventType.LOGIN_SUCCESS,
                SecurityEvent.timestamp >= window_start,
            )
        )
    )
    # On compte les accès aux données (event MASS_DATA_ACCESS en cours de création)
    # Ici on utilise un compteur en mémoire via un cache simple
    count = result.scalar_one()

    if count >= settings.MASS_ACCESS_LIMIT:
        log.warning(f"[Règle 4] Exfiltration : {count} accès par '{username}' en {settings.MASS_ACCESS_WINDOW}s")
        return True, count
    return False, count


# Compteur en mémoire pour les accès aux données sensibles (Règle 4)
# { username: [timestamp1, timestamp2, ...] }
_access_counters: dict[str, list[datetime]] = {}


def record_data_access(username: str) -> tuple[bool, int]:
    """
    Enregistre un accès aux données sensibles et vérifie Règle 4.
    Retourne (True, count) si le seuil est atteint.
    Utilise un compteur en mémoire (fenêtre glissante).
    """
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=settings.MASS_ACCESS_WINDOW)

    if username not in _access_counters:
        _access_counters[username] = []

    # Purge les accès hors fenêtre
    _access_counters[username] = [
        t for t in _access_counters[username] if t >= window_start
    ]
    _access_counters[username].append(now)

    count = len(_access_counters[username])

    if count >= settings.MASS_ACCESS_LIMIT:
        log.warning(f"[Règle 4] Exfiltration massive : {count} accès par '{username}' en {settings.MASS_ACCESS_WINDOW}s")
        return True, count
    return False, count


# ════════════════════════════════════════════════════════════
# RÈGLE 5 — Énumération d'identifiants
# ════════════════════════════════════════════════════════════

async def check_enumeration(
    db: AsyncSession,
    ip: str,
) -> tuple[bool, int]:
    """
    Règle 5 : même IP ayant tenté 3 usernames différents en moins de 5 minutes.
    Retourne (True, count) si le seuil est atteint.
    """
    window_start = datetime.utcnow() - timedelta(seconds=settings.ENUM_WINDOW)

    result = await db.execute(
        select(func.count(distinct(LoginAttempt.username_tried)))
        .where(
            and_(
                LoginAttempt.ip_address == ip,
                LoginAttempt.success == False,
                LoginAttempt.timestamp >= window_start,
            )
        )
    )
    count = result.scalar_one()

    if count >= settings.ENUM_USERNAMES_LIMIT:
        log.warning(f"[Règle 5] Énumération : {count} usernames distincts depuis {ip} en {settings.ENUM_WINDOW}s")
        return True, count
    return False, count


# ════════════════════════════════════════════════════════════
# RÈGLE 6 — Accès hors horaires
# ════════════════════════════════════════════════════════════

def check_off_hours(hour: int | None = None) -> bool:
    """
    Vérifie si l'heure actuelle est hors de la plage autorisée.
    Retourne True si hors horaires.
    """
    current_hour = hour if hour is not None else datetime.utcnow().hour
    outside = not (settings.ALLOWED_HOURS_START <= current_hour < settings.ALLOWED_HOURS_END)
    if outside:
        log.info(f"[Règle 6] Accès hors horaires : {current_hour}h UTC")
    return outside