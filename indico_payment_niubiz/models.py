"""Database models used by the Niubiz plugin."""

from __future__ import annotations

from indico.core.db import db
from indico.util.date_time import now_utc


class NiubizStoredToken(db.Model):
    __tablename__ = "niubiz_stored_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.users.id"), nullable=False, index=True)
    token = db.Column(db.String(128), nullable=False, unique=True)
    alias = db.Column(db.String(80), nullable=True)
    brand = db.Column(db.String(40), nullable=True)
    masked_card = db.Column(db.String(32), nullable=True)
    eci = db.Column(db.String(8), nullable=True)
    expiry_month = db.Column(db.Integer, nullable=True)
    expiry_year = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    user = db.relationship("User", backref=db.backref("niubiz_tokens", lazy="dynamic"))

    @property
    def label(self) -> str:
        parts = [self.brand or "Tarjeta"]
        if self.masked_card:
            parts.append(self.masked_card)
        if self.expiry_month and self.expiry_year:
            parts.append(f"{self.expiry_month:02d}/{self.expiry_year}")
        return " - ".join(parts)

    def update_from_token_response(self, payload: dict) -> None:
        card_data = payload.get("card") if isinstance(payload.get("card"), dict) else payload
        if not isinstance(card_data, dict):
            return
        brand = card_data.get("brand") or card_data.get("BRAND")
        masked = card_data.get("maskedCard") or card_data.get("PAN")
        exp_month = card_data.get("expiryMonth") or card_data.get("EXPIRY_MONTH")
        exp_year = card_data.get("expiryYear") or card_data.get("EXPIRY_YEAR")
        eci = card_data.get("eci") or card_data.get("ECI")
        if brand:
            self.brand = str(brand)
        if masked:
            self.masked_card = str(masked)
        if eci:
            self.eci = str(eci)
        try:
            if exp_month:
                self.expiry_month = int(exp_month)
            if exp_year:
                self.expiry_year = int(exp_year)
        except (TypeError, ValueError):
            pass
        self.updated_at = now_utc()
