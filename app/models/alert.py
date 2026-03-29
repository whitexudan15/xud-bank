# ============================================================
# XUD-BANK — app/models/alert.py
# Modèle SQLAlchemy : Table alerts
# ============================================================

import uuid
from datetime import datetime
from sqlalchemy import Text, Boolean, DateTime, Enum as SAEnum, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base
from app.models.security_event import SeverityLevel


class Alert(Base):
    __tablename__ = "alerts"

    id              : Mapped[uuid.UUID]      = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp       : Mapped[datetime]       = mapped_column(DateTime(timezone=False), nullable=False, default=datetime.utcnow)
    alert_level     : Mapped[SeverityLevel]  = mapped_column(SAEnum(SeverityLevel, name="severity_level", create_type=False), nullable=False)
    source_event_id : Mapped[uuid.UUID]      = mapped_column(UUID(as_uuid=True), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False)
    message         : Mapped[str]           = mapped_column(Text, nullable=False)
    resolved        : Mapped[bool]           = mapped_column(Boolean, nullable=False, default=False)

    # Relation ORM (accès via alert.source_event)
    source_event = relationship("SecurityEvent", backref="alerts", lazy="joined")

    __table_args__ = (
        Index('idx_alerts_resolved_timestamp', 'resolved', 'timestamp'),
    )

    def __repr__(self) -> str:
        return f"<Alert [{self.alert_level}] resolved={self.resolved} {self.timestamp}>"