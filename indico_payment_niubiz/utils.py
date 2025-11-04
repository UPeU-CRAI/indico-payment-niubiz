"""Utilidades de negocio para el flujo NO-PCI de Niubiz."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Iterable, Optional

from indico.modules.events.payment.models.transactions import TransactionStatus

from .status_mapping import DEFAULT_STATUS, NIUBIZ_STATUS_MAP

# URLs oficiales del checkout.js de Niubiz
CHECKOUT_JS_URLS = {
    "sandbox": "https://static-content-qas.vnforapps.com/env/sandbox/js/checkout.js",
    "prod": "https://static-content.vnforapps.com/v2/js/checkout.js",
}

DEFAULT_CURRENCY = "PEN"


@dataclass(frozen=True)
class StatusMapping:
    """Resultado del mapeo de estados desde Niubiz."""

    status: TransactionStatus
    summary: str
    toggle_paid: bool
    manual_confirmation: bool = False


def normalize_currency(value: Optional[str]) -> str:
    if not value:
        return DEFAULT_CURRENCY
    currency = value.strip().upper()
    if len(currency) != 3:
        raise ValueError(f"Moneda inválida: {value!r}")
    return currency


def parse_amount(value: Any) -> Decimal:
    if isinstance(value, Decimal):
        amount = value
    else:
        try:
            amount = Decimal(str(value))
        except (InvalidOperation, ValueError, TypeError) as exc:
            raise ValueError(f"Monto inválido: {value!r}") from exc
    if amount <= Decimal("0"):
        raise ValueError("El monto debe ser mayor a cero")
    return amount.quantize(Decimal("0.01"))


def format_amount(value: Any) -> str:
    return f"{parse_amount(value):.2f}"


def generate_purchase_number(event_id: int, registration_id: int) -> str:
    return f"{event_id}-{registration_id}"


def generate_external_transaction_id(prefix: str = "nbz") -> str:
    identifier = uuid.uuid4().hex
    return f"{prefix}-{identifier}"


def get_checkout_script_url(endpoint: str) -> str:
    key = "sandbox" if (endpoint or "sandbox").lower() == "sandbox" else "prod"
    return CHECKOUT_JS_URLS[key]


def _get_status_config(status: Optional[str]) -> Dict[str, Any]:
    normalized = (status or "").strip().upper()
    return NIUBIZ_STATUS_MAP.get(normalized, DEFAULT_STATUS)


def map_status(
    *,
    status: Optional[str],
    action_code: Optional[str] = None,
    status_order: Optional[str] = None,
    payment_method: Optional[str] = None,
    action_description: Optional[str] = None,
) -> StatusMapping:
    """Convierte el estado Niubiz en un :class:`TransactionStatus`."""

    status_config = _get_status_config(status)
    mapping_status = status_config.get("status")

    if not isinstance(mapping_status, TransactionStatus):
        # Compatibilidad con mapeos anteriores basados en acción
        action = status_config.get("action")
        if action == TransactionStatus.successful:
            mapping_status = TransactionStatus.successful
        elif action == TransactionStatus.cancelled:
            mapping_status = TransactionStatus.cancelled
        elif action == TransactionStatus.pending:
            mapping_status = TransactionStatus.pending
        else:
            mapping_status = TransactionStatus.failed

    manual_confirmation = False
    status_order_value = (status_order or "").strip().lower()
    status_value = (status or "").strip().lower()

    if status_order_value == "completed":
        mapping_status = TransactionStatus.successful
    elif status_order_value in {"expired", "cancelled", "canceled"}:
        mapping_status = TransactionStatus.cancelled
    elif status_order_value == "pending":
        mapping_status = TransactionStatus.pending

    if status_value == "confirmed":
        manual_confirmation = True
        mapping_status = TransactionStatus.successful

    summary = status_config.get("summary") or "Estado desconocido recibido desde Niubiz"
    toggle_paid = bool(status_config.get("toggle_paid"))

    return StatusMapping(
        status=mapping_status,
        summary=summary,
        toggle_paid=toggle_paid,
        manual_confirmation=manual_confirmation,
    )


def extract_purchase_numbers(purchase_number: Optional[str]) -> tuple[Optional[int], Optional[int]]:
    if not purchase_number or "-" not in purchase_number:
        return None, None
    event_str, registration_str = purchase_number.split("-", 1)
    try:
        return int(event_str), int(registration_str)
    except (TypeError, ValueError):
        return None, None


def flatten_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    queue: list[Dict[str, Any]] = [payload]
    flattened: Dict[str, Any] = {}

    while queue:
        current = queue.pop()
        for key, value in current.items():
            if isinstance(value, dict):
                queue.append(value)
            elif isinstance(value, list):
                queue.extend(item for item in value if isinstance(item, dict))
            else:
                flattened.setdefault(key, value)
                flattened.setdefault(key.lower(), value)
                flattened.setdefault(key.upper(), value)
    return flattened


def extract_details(payload: Dict[str, Any]) -> Dict[str, Any]:
    data = flatten_payload(payload)
    return {
        "purchase_number": data.get("purchaseNumber") or data.get("purchase_number"),
        "transaction_id": data.get("transactionId") or data.get("transaction_id"),
        "status": data.get("status"),
        "status_order": data.get("statusOrder") or data.get("status_order"),
        "action_code": data.get("actionCode") or data.get("action_code"),
        "action_description": data.get("actionDescription") or data.get("message"),
        "transaction_identifier": data.get("transactionIdentifier") or data.get("transactionidentifier"),
        "operation_number": data.get("operationNumber") or data.get("operation_number"),
        "amount": data.get("amount"),
        "currency": data.get("currency"),
        "brand": data.get("brand"),
        "masked_card": data.get("maskedCard") or data.get("pan"),
    }


__all__ = [
    "CHECKOUT_JS_URLS",
    "DEFAULT_CURRENCY",
    "StatusMapping",
    "extract_details",
    "extract_purchase_numbers",
    "flatten_payload",
    "format_amount",
    "generate_external_transaction_id",
    "generate_purchase_number",
    "get_checkout_script_url",
    "map_status",
    "normalize_currency",
    "parse_amount",
]
