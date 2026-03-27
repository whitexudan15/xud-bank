# ============================================================
# XUD-BANK — app/services/auth_service.py
# Logique métier d'authentification
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================

import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.models.user import User, UserRole
from app.config import get_settings

settings = get_settings()
log = logging.getLogger("xud_bank.auth")

# ── Contexte bcrypt ───────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Sérialiseur de session ────────────────────────────────────
serializer = URLSafeTimedSerializer(settings.SECRET_KEY)


# ════════════════════════════════════════════════════════════
# MOTS DE PASSE
# ════════════════════════════════════════════════════════════

def hash_password(plain: str) -> str:
    """Hash bcrypt cost=12 d'un mot de passe en clair."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Vérifie un mot de passe contre son hash bcrypt."""
    return pwd_context.verify(plain, hashed)


# ════════════════════════════════════════════════════════════
# SESSIONS (cookies signés itsdangerous)
# ════════════════════════════════════════════════════════════

def create_session_token(user: User) -> str:
    """
    Crée un token de session signé contenant :
    user_id, username, role
    """
    data = {
        "user_id": str(user.id),
        "username": user.username,
        "role": user.role.value,
    }
    return serializer.dumps(data, salt="session")


def decode_session_token(token: str) -> dict | None:
    """
    Décode et valide un token de session.
    Retourne le dict de données ou None si invalide / expiré.
    """
    try:
        data = serializer.loads(
            token,
            salt="session",
            max_age=settings.SESSION_MAX_AGE,
        )
        return data
    except (BadSignature, SignatureExpired):
        return None


# ════════════════════════════════════════════════════════════
# CRUD UTILISATEURS
# ════════════════════════════════════════════════════════════

async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    """Récupère un utilisateur par son username."""
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    """Récupère un utilisateur par son UUID."""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def create_user(
    db: AsyncSession,
    username: str,
    email: str,
    password: str,
    role: UserRole = UserRole.utilisateur,
) -> User:
    """Crée un nouvel utilisateur avec mot de passe hashé."""
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=role,
        is_locked=False,
        failed_attempts=0,
        created_at=datetime.utcnow(),
    )
    db.add(user)
    await db.flush()
    return user


async def unlock_account(db: AsyncSession, username: str) -> User | None:
    """Déverrouille un compte (admin uniquement)."""
    user = await get_user_by_username(db, username)
    if user:
        user.is_locked = False
        user.failed_attempts = 0
        user.last_failed_at = None
        await db.flush()
        log.info(f"Compte '{username}' déverrouillé")
    return user


# ════════════════════════════════════════════════════════════
# AUTHENTIFICATION
# ════════════════════════════════════════════════════════════

class AuthResult:
    """Résultat d'une tentative d'authentification."""
    def __init__(self, success: bool, user: User | None = None, reason: str = ""):
        self.success = success
        self.user = user
        self.reason = reason   # "invalid_password" | "account_locked" | "unknown_user"


async def authenticate(
    db: AsyncSession,
    username: str,
    password: str,
) -> AuthResult:
    """
    Vérifie les credentials d'un utilisateur.
    Message d'erreur générique côté client (anti-énumération).
    Retourne AuthResult avec le détail interne pour le dispatcher.
    """
    user = await get_user_by_username(db, username)

    # Utilisateur inexistant
    if user is None:
        log.warning(f"Tentative sur utilisateur inexistant : '{username}'")
        return AuthResult(success=False, user=None, reason="unknown_user")

    # Compte verrouillé
    if user.is_locked:
        log.warning(f"Tentative sur compte verrouillé : '{username}'")
        return AuthResult(success=False, user=user, reason="account_locked")

    # Mot de passe incorrect
    if not verify_password(password, user.password_hash):
        user.failed_attempts += 1
        user.last_failed_at = datetime.utcnow()
        await db.flush()
        return AuthResult(success=False, user=user, reason="invalid_password")

    # Succès
    return AuthResult(success=True, user=user, reason="")


# ════════════════════════════════════════════════════════════
# DEPENDENCY FASTAPI — Session courante
# ════════════════════════════════════════════════════════════

from fastapi import Request, HTTPException, status


def get_current_user_data(request: Request) -> dict:
    """
    Dependency FastAPI : lit et valide le cookie de session.
    Retourne le dict {user_id, username, role}.
    Lève HTTP 401 si absent ou invalide.
    """
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Non authentifié",
        )
    data = decode_session_token(token)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expirée ou invalide",
        )
    return data


def require_role(*roles: str):
    """
    Dependency FastAPI : vérifie le rôle de l'utilisateur connecté.
    Usage : Depends(require_role("admin", "analyste"))

    Exemple :
        @router.get("/admin/")
        async def admin_page(user=Depends(require_role("admin"))):
            ...
    """
    def _checker(request: Request) -> dict:
        user_data = get_current_user_data(request)
        if user_data["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Accès refusé : privilèges insuffisants",
            )
        return user_data
    return _checker