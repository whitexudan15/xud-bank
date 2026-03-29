# ============================================================
# XUD-BANK — SecureDataMonitor
# Configuration centrale de l'application
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================

from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    """
    Toutes les variables de configuration chargées depuis .env
    Pydantic valide les types et lève une erreur au démarrage
    si une variable obligatoire est manquante.
    """

    # ── Application ───────────────────────────────────────────
    APP_NAME: str = "xud-bank"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # ── Base de données (Railway PostgreSQL) ─────────────────
    DATABASE_URL: str = Field(
        ...,
        description="postgresql+asyncpg://user:password@host:5432/dbname"
    )

    # ── Sécurité sessions ─────────────────────────────────────
    SECRET_KEY: str = Field(
        ...,
        description="Clé secrète pour signer les cookies de session (min 32 chars)"
    )
    SESSION_COOKIE_NAME: str = "xud_session"
    SESSION_MAX_AGE: int = 3600          # secondes (1 heure)
    COOKIE_HTTPONLY: bool = True
    COOKIE_SAMESITE: str = "lax"

    # ── Règle 1 : Brute Force ─────────────────────────────────
    MAX_LOGIN_ATTEMPTS: int = 3          # échecs max avant verrouillage
    BRUTE_FORCE_WINDOW: int = 120        # fenêtre en secondes (2 minutes)

    # ── Règle 4 : Exfiltration massive ────────────────────────
    MASS_ACCESS_LIMIT: int = 20          # consultations max par minute
    MASS_ACCESS_WINDOW: int = 60         # fenêtre en secondes (1 minute)

    # ── Règle 5 : Énumération d'identifiants ──────────────────
    ENUM_USERNAMES_LIMIT: int = 3        # usernames distincts max par IP
    ENUM_WINDOW: int = 300               # fenêtre en secondes (5 minutes)

    # ── Règle 6 : Accès hors horaires ─────────────────────────
    ALLOWED_HOURS_START: int = 7         # heure de début (UTC)
    ALLOWED_HOURS_END: int = 20          # heure de fin (UTC)

    # ── Journalisation ────────────────────────────────────────
    LOG_FILE_PATH: str = "logs/security.log"
    LOG_MAX_BYTES: int = 5 * 1024 * 1024    # 5 MB par fichier
    LOG_BACKUP_COUNT: int = 3               # 3 fichiers de rotation

    # ── WebSocket ─────────────────────────────────────────────
    WS_HEARTBEAT_INTERVAL: int = 30      # ping/pong en secondes

    # ── CORS (dev uniquement) ─────────────────────────────────
    ALLOWED_ORIGINS: list[str] = ["http://localhost:8000", "http://127.0.0.1:8000"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """
    Retourne une instance unique des settings (singleton via lru_cache).
    À utiliser partout via : from app.config import get_settings
    """
    return Settings()


# Instance globale accessible directement si besoin
settings = get_settings()