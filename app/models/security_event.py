# ============================================================
# XUD-BANK — app/models/security_event.py
# Modèle SQLAlchemy : Table security_events (journal central)
# ============================================================

import uuid
from datetime import datetime
from sqlalchemy import String, Text, DateTime, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, INET as PGINET
from app.database import Base
import enum


class EventType(str, enum.Enum):
    LOGIN_SUCCESS       = "LOGIN_SUCCESS"
    LOGIN_FAILED        = "LOGIN_FAILED"
    LOGIN_LOCKED        = "LOGIN_LOCKED"
    UNKNOWN_USER        = "UNKNOWN_USER"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    PRIVILEGE_ESCALATION= "PRIVILEGE_ESCALATION"
    SQL_INJECTION       = "SQL_INJECTION"
    RATE_LIMIT          = "RATE_LIMIT"
    MASS_DATA_ACCESS    = "MASS_DATA_ACCESS"
    ENUM_ATTEMPT        = "ENUM_ATTEMPT"
    OFF_HOURS_ACCESS    = "OFF_HOURS_ACCESS"
    SUSPICIOUS_URL      = "SUSPICIOUS_URL"


class SeverityLevel(str, enum.Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class EventStatus(str, enum.Enum):
    open          = "open"
    investigating = "investigating"
    closed        = "closed"


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id           : Mapped[uuid.UUID]         = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp    : Mapped[datetime]          = mapped_column(DateTime(timezone=False), nullable=False, default=datetime.utcnow)
    username     : Mapped[str | None]        = mapped_column(String(50), nullable=True)
    ip_address   : Mapped[str]              = mapped_column(PGINET, nullable=False)
    event_type   : Mapped[EventType]         = mapped_column(SAEnum(EventType, name="event_type", create_type=False), nullable=False)
    severity     : Mapped[SeverityLevel]     = mapped_column(SAEnum(SeverityLevel, name="severity_level", create_type=False), nullable=False)
    description  : Mapped[str]              = mapped_column(Text, nullable=False)
    status       : Mapped[EventStatus]       = mapped_column(SAEnum(EventStatus, name="event_status", create_type=False), nullable=False, default=EventStatus.open)
    action_taken : Mapped[str | None]        = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<SecurityEvent {self.event_type} [{self.severity}] {self.timestamp}>"