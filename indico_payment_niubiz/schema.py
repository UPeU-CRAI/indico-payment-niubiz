"""Structured data objects used across the Niubiz integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional

try:  # pragma: no cover - executed during runtime when Indico is present
    from indico.modules.events.payment.models.transactions import TransactionStatus
except Exception:  # pragma: no cover - fallback for the standalone test suite
    from enum import Enum

    class TransactionStatus(Enum):  # type: ignore[override]
        successful = "successful"
        failed = "failed"
        pending = "pending"
        cancelled = "cancelled"


@dataclass(frozen=True)
class AmountCurrency:
    """Represents a validated monetary amount and currency pair."""

    amount: Decimal
    currency: str

    def __post_init__(self) -> None:
        normalized_amount = self._normalize_amount(self.amount)
        normalized_currency = self._normalize_currency(self.currency)
        object.__setattr__(self, "amount", normalized_amount)
        object.__setattr__(self, "currency", normalized_currency)

    @staticmethod
    def _normalize_amount(value: Any) -> Decimal:
        try:
            decimal_value = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise ValueError("Invalid amount") from exc
        if decimal_value <= 0:
            raise ValueError("Amount must be greater than zero")
        return decimal_value.quantize(Decimal("0.01"))

    @staticmethod
    def _normalize_currency(value: Any) -> str:
        if not value:
            raise ValueError("Currency is required")
        currency = str(value).strip().upper()
        if currency not in {"PEN", "USD"}:
            raise ValueError("Unsupported currency")
        return currency


@dataclass(frozen=True)
class CheckoutSession:
    """Payload returned when creating a checkout session in Niubiz."""

    session_key: str
    amount: Decimal
    currency: str
    purchase_number: str
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OrderStatus:
    """Represents the status payload for a Niubiz order."""

    success: bool
    status: Optional[str]
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RefundResponse:
    """Common structure for refund/void/reverse responses."""

    success: bool
    status: Optional[str]
    transaction_id: Optional[str]
    action: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StatusMapping:
    """Maps Niubiz status information into Indico's transaction status enum."""

    status: TransactionStatus
    manual_confirmation: bool = False
    reason: Optional[str] = None


@dataclass(frozen=True)
class WebhookDetails:
    """Normalized representation of Niubiz webhook payloads."""

    purchase_number: Optional[str]
    transaction_id: Optional[str]
    status: Optional[str]
    status_order: Optional[str]
    action_code: Optional[str]
    payment_method: Optional[str]
    action_description: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return a serialisable version of the webhook data."""

        return {
            "purchase_number": self.purchase_number,
            "transaction_id": self.transaction_id,
            "status": self.status,
            "status_order": self.status_order,
            "action_code": self.action_code,
            "payment_method": self.payment_method,
            "action_description": self.action_description,
            "raw": self.raw,
        }
