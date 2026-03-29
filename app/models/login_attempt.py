# ============================================================
# XUD-BANK — app/models/login_attempt.py
# Modèle SQLAlchemy : Table login_attempts
# Tracking des tentatives pour Règles 1 (brute force) & 5 (énumération)
# ============================================================

import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, INET as PGINET
from app.database import Base


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id             : Mapped[uuid.UUID]  = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_address     : Mapped[str]        = mapped_column(PGINET, nullable=False)
    username_tried : Mapped[str]        = mapped_column(String(50), nullable=False)
    timestamp      : Mapped[datetime]   = mapped_column(DateTime(timezone=False), nullable=False, default=datetime.utcnow)
    success        : Mapped[bool]       = mapped_column(Boolean, nullable=False)

    __table_args__ = (
        Index('idx_login_attempts_username_success_time', 'username_tried', 'success', 'timestamp'),
    )

    def __repr__(self) -> str:
        status = "OK" if self.success else "FAIL"
        return f"<LoginAttempt {self.username_tried} from {self.ip_address} [{status}]>"