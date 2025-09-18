from __future__ import annotations

import logging
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional

from indico.modules.events.payment.models.transactions import TransactionAction
from indico.modules.events.payment.util import register_transaction

logger = logging.getLogger(__name__)


# -----------------------------------------------------
# Utilidades de conversión
# -----------------------------------------------------
def parse_amount(value: Any, fallback: Optional[Decimal]) -> Optional[Decimal]:
    """Convierte un valor a Decimal, o retorna el fallback si no es válido."""
    if value is None:
        return fallback
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return fallback


# -----------------------------------------------------
# Construcción de datos
# -----------------------------------------------------
def build_transaction_data(
    *,
    payload: Optional[Dict[str, Any]] = None,
    source: Optional[str] = None,
    status: Optional[str] = None,
    action_code: Optional[str] = None,
    transaction_id: Optional[str] = None,
    order_id: Optional[str] = None,
    external_id: Optional[str] = None,
    message: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Crea un diccionario con los datos adicionales de la transacción."""
    data: Dict[str, Any] = {"provider": "niubiz"}
    if source:
        data["source"] = source
    if payload is not None:
        data["payload"] = payload
    if status:
        data["status"] = status
    if action_code:
        data["action_code"] = action_code
    if transaction_id:
        data["transaction_id"] = transaction_id
    if order_id:
        data["order_id"] = order_id
    if external_id:
        data["external_id"] = external_id
    if message:
        data["message"] = message
    if reason:
        data["reason"] = reason
    return data


# -----------------------------------------------------
# Registro de transacciones
# -----------------------------------------------------
def record_payment_transaction(
    *,
    registration,
    amount: Any,
    currency: str,
    action: TransactionAction,
    data: Optional[Dict[str, Any]] = None,
):
    """
    Crea una transacción de pago en Indico (completada, fallida, cancelada, reembolso, pendiente).
    
    Esta función debe ser llamada siempre que llegue un callback de Niubiz
    para mantener el historial consistente en Indico.
    """
    try:
        amount_value = float(amount)
    except (TypeError, ValueError):
        amount_value = float(getattr(registration, "price", 0) or 0)

    return register_transaction(
        registration=registration,
        amount=amount_value,
        currency=currency,
        action=action,
        provider="niubiz",
        data=data or {},
    )
