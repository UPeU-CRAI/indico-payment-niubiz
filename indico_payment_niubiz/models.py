"""Database models used by the Niubiz plugin."""

from __future__ import annotations

from datetime import datetime

from indico.core.db import db
from indico.util.date_time import now_utc


class NiubizStoredToken(db.Model):
    """Stores tokenized Niubiz cards for a user."""

    __tablename__ = "niubiz_stored_tokens"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.users.id"),
        nullable=False,
        index=True,
    )

    token = db.Column(db.String(128), nullable=False, unique=True)  # Consider encrypting if needed
    alias = db.Column(db.String(80), nullable=True)
    brand = db.Column(db.String(40), nullable=True)
    masked_card = db.Column(db.String(32), nullable=True)
    eci = db.Column(db.String(8), nullable=True)
    expiry_month = db.Column(db.Integer, nullable=True)
    expiry_year = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Useful for soft-deletion or disabling token temporarily
    active = db.Column(db.Boolean, nullable=False, default=True)

    user = db.relationship("User", backref=db.backref("niubiz_tokens", lazy="dynamic"))

    @property
    def label(self) -> str:
        """Return a human-readable label for this token/card."""
        parts = [self.brand or "Tarjeta"]
        if self.masked_card:
            parts.append(self.masked_card)
        if self.expiry_month and self.expiry_year:
            parts.append(f"{self.expiry_month:02d}/{self.expiry_year}")
        return " - ".join(parts)

    @property
    def is_expired(self) -> bool:
        """Check if the stored card is expired."""
        if not self.expiry_month or not self.expiry_year:
            return False  # Can't determine
        now = datetime.utcnow()
        return (
            self.expiry_year < now.year
            or (self.expiry_year == now.year and self.expiry_month < now.month)
        )

    def update_from_token_response(self, payload: dict) -> None:
        """Update token metadata using response from Niubiz."""
        card_data = payload.get("card") if isinstance(payload.get("card"), dict) else payload
        if not isinstance(card_data, dict):
            return

        # Try to handle different key names (lower/upper/camelcase)
        self.brand = str(card_data.get("brand") or card_data.get("BRAND") or self.brand)
        self.masked_card = str(card_data.get("maskedCard") or card_data.get("PAN") or self.masked_card)
        self.eci = str(card_data.get("eci") or card_data.get("ECI") or self.eci)

        try:
            exp_month = card_data.get("expiryMonth") or card_data.get("EXPIRY_MONTH")
            exp_year = card_data.get("expiryYear") or card_data.get("EXPIRY_YEAR")
            if exp_month:
                self.expiry_month = int(exp_month)
            if exp_year:
                self.expiry_year = int(exp_year)
        except (TypeError, ValueError):
            pass  # Invalid data, ignore

        self.updated_at = now_utc()
