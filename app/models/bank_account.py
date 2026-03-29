# ============================================================
# XUD-BANK — app/models/bank_account.py
# Modèle SQLAlchemy : Table bank_accounts (données sensibles)
# ============================================================

import uuid
from datetime import datetime
from decimal import Decimal
from sqlalchemy import String, Numeric, Text, DateTime, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base
import enum


class AccountClassification(str, enum.Enum):
    public       = "public"
    confidentiel = "confidentiel"
    secret       = "secret"


class BankAccount(Base):
    __tablename__ = "bank_accounts"

    id             : Mapped[uuid.UUID]               = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    id_compte      : Mapped[str]                     = mapped_column(String(20), unique=True, nullable=False)
    titulaire      : Mapped[str]                     = mapped_column(String(100), nullable=False)
    solde          : Mapped[Decimal]                 = mapped_column(Numeric(15, 2), nullable=False, default=Decimal("0.00"))
    historique     : Mapped[str | None]              = mapped_column(Text, nullable=True)   # JSON sérialisé
    classification : Mapped[AccountClassification]   = mapped_column(SAEnum(AccountClassification, name="account_classification", create_type=False), nullable=False, default=AccountClassification.confidentiel)
    owner_id       : Mapped[uuid.UUID]               = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at     : Mapped[datetime]                = mapped_column(DateTime(timezone=False), nullable=False, default=datetime.utcnow)

    # Relation ORM (accès via account.owner)
    owner = relationship("User", backref="accounts", lazy="joined")

    def __repr__(self) -> str:
        return f"<BankAccount {self.id_compte} [{self.classification}] solde={self.solde}>"