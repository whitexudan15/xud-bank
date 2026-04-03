# ============================================================
# XUD-BANK — app/models/user.py
# Modèle SQLAlchemy : Table users
# ============================================================

import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, Integer, DateTime, Enum as SAEnum, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base
import enum


class UserRole(str, enum.Enum):
    soc         = "soc"
    directeur   = "directeur"
    comptable   = "comptable"
    utilisateur = "utilisateur"


class User(Base):
    __tablename__ = "users"

    id              : Mapped[uuid.UUID]         = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username        : Mapped[str]               = mapped_column(String(50),  unique=True, nullable=False)
    email           : Mapped[str]               = mapped_column(String(100), unique=True, nullable=False)
    password_hash   : Mapped[str]               = mapped_column(String(255), nullable=False)
    role            : Mapped[UserRole]          = mapped_column(SAEnum(UserRole, name="user_role", create_type=False), nullable=False, default=UserRole.utilisateur)
    is_locked       : Mapped[bool]              = mapped_column(Boolean, nullable=False, default=False)
    failed_attempts : Mapped[int]               = mapped_column(Integer, nullable=False, default=0)
    last_failed_at  : Mapped[datetime | None]   = mapped_column(DateTime(timezone=False), nullable=True)
    created_at      : Mapped[datetime]          = mapped_column(DateTime(timezone=False), nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_users_email', 'email'),
        Index('idx_users_is_locked', 'is_locked'),
    )

    def __repr__(self) -> str:
        return f"<User {self.username} [{self.role}] locked={self.is_locked}>"