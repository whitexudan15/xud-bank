# ============================================================
# XUD-BANK — SecureDataMonitor
# Connexion asynchrone à la base de données PostgreSQL (Railway)
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from app.config import get_settings

settings = get_settings()


# ── Moteur async SQLAlchemy ───────────────────────────────────
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,            # Log SQL en mode debug uniquement
    pool_size=5,                    # Connexions simultanées maintenues
    max_overflow=10,                # Connexions supplémentaires si pool plein
    pool_timeout=30,                # Secondes avant timeout d'acquisition
    pool_recycle=1800,              # Recycle connexions toutes les 30 min (Railway)
    pool_pre_ping=True,             # Vérifie la connexion avant utilisation
    connect_args={
        "server_settings": {
            "application_name": "xud-bank",
        },
    },
)


# ── Session factory ───────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,         # Évite les lazy-load après commit
    autoflush=False,
    autocommit=False,
)


# ── Base déclarative (héritée par tous les modèles) ───────────
class Base(DeclarativeBase):
    """
    Classe de base pour tous les modèles SQLAlchemy.
    Tous les models/ héritent de cette classe.
    Usage : from app.database import Base
    """
    pass


# ── Dependency FastAPI ────────────────────────────────────────
async def get_db() -> AsyncSession:
    """
    Dependency injection FastAPI.
    Fournit une session BDD par requête HTTP, fermée automatiquement.

    Usage dans un router :
        async def ma_route(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Vérification de connexion ─────────────────────────────────
async def check_db_connection() -> bool:
    """
    Vérifie que la base de données est accessible.
    Appelé au démarrage de l'application dans main.py (lifespan).
    Retourne True si OK, lève une exception sinon.
    """
    async with AsyncSessionLocal() as session:
        await session.execute(text("SELECT 1"))
    return True


# ── Création des tables (dev / init) ──────────────────────────
async def create_all_tables() -> None:
    """
    Crée toutes les tables définies dans les modèles.
    À utiliser uniquement en développement ou si init_db.sql
    n'a pas encore été exécuté sur Railway.
    En production : utiliser init_db.sql via votre interface SQL.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# ── Fermeture propre du pool ──────────────────────────────────
async def close_db() -> None:
    """
    Ferme toutes les connexions du pool.
    Appelé à l'arrêt de l'application dans main.py (lifespan).
    """
    await engine.dispose()