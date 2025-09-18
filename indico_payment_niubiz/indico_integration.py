from __future__ import annotations

import logging
from copy import deepcopy
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional

from indico.modules.events.payment.models.transactions import TransactionAction, TransactionStatus
from indico.modules.events.payment.util import register_transaction

# Opcionales según versión de Indico
try:  # pragma: no cover
    from indico.modules.events.payment.util import toggle_registration_payment as _toggle_registration_payment
except ImportError:
    _toggle_registration_payment = None

try:  # pragma: no cover
    from indico.modules.events.registration.util import apply_registration_status as _apply_registration_status
except ImportError:
    _apply_registration_status = None

try:  # pragma: no cover
    from indico.modules.events.logs.models.entries import EventLogRealm, LogKind
except Exception:  # fallback en entornos limitados (tests)
    from enum import Enum

    class EventLogRealm(Enum):  # type: ignore
        participants = "participants"

    class LogKind(Enum):  # type: ignore
        positive = "positive"
        negative = "negative"
        warning = "warning"
        change = "change"


logger = logging.getLogger(__name__)

NIUBIZ_MODULE_NAME = "Niubiz"


# -----------------------------------------------------
# Utilidades
# -----------------------------------------------------
def parse_amount(value: Any, fallback: Optional[Decimal]) -> Optional[Decimal]:
    """Convierte un valor genérico a Decimal o retorna el fallback."""
    if value is None:
        return fallback
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return fallback


def build_transaction_data(
    *,
    payload: Optional[Dict[str, Any]] = None,
    source: str = "callback",
    status: Optional[str] = None,
    action_code: Optional[str] = None,
    transaction_id: Optional[str] = None,
    order_id: Optional[str] = None,
    external_id: Optional[str] = None,
    message: Optional[str] = None,
    reason: Optional[str] = None,
    **extra: Any,
) -> Dict[str, Any]:
    """Crea un diccionario con los datos extra de la transacción."""
    data: Dict[str, Any] = {"provider": "niubiz"}
    if payload is not None:
        data["payload"] = payload
    if source:
        data["source"] = source
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
    if extra:
        data.update(extra)
    return data


def _prepare_transaction_payload(
    data: Optional[Dict[str, Any]],
    *,
    transaction_id: Optional[str],
    status: Optional[str],
    amount: Optional[Decimal],
    currency: Optional[str],
) -> Dict[str, Any]:
    """Completa el diccionario data con campos básicos faltantes."""
    payload = deepcopy(data) if data else {}
    payload.setdefault("provider", "niubiz")
    payload.setdefault("payload", None)
    if transaction_id and not payload.get("transaction_id"):
        payload["transaction_id"] = transaction_id
    if status and not payload.get("status"):
        payload["status"] = status
    if amount is not None:
        try:
            payload["amount"] = float(amount)
        except (TypeError, ValueError):
            pass
    if currency and not payload.get("currency"):
        payload["currency"] = currency
    return payload


# -----------------------------------------------------
# Estado de inscripción
# -----------------------------------------------------
def _apply_registration_paid_state(registration, paid: bool) -> bool:
    """
    Marca una inscripción como pagada/no pagada usando la mejor opción disponible
    según la versión de Indico instalada.
    """
    if _toggle_registration_payment is not None:
        try:
            _toggle_registration_payment(registration, paid)
            return True
        except Exception:
            logger.exception("toggle_registration_payment falló; probando alternativas")

    if _apply_registration_status is not None:
        try:
            _apply_registration_status(registration, paid=paid)
            return True
        except Exception:
            logger.exception("apply_registration_status falló")

    if callable(getattr(registration, "update_state", None)):
        try:
            registration.update_state(paid=paid)
            return True
        except Exception:
            logger.exception("update_state falló en inscripción")

    if callable(getattr(registration, "set_paid", None)):
        try:
            registration.set_paid(paid)
            return True
        except Exception:
            logger.exception("set_paid falló en inscripción")

    return False


# -----------------------------------------------------
# Logging
# -----------------------------------------------------
def _log_event(
    registration,
    *,
    summary: str,
    kind,
    status: Optional[str],
    transaction_id: Optional[str],
    amount: Optional[Decimal],
    currency: Optional[str],
    data: Optional[Dict[str, Any]],
) -> None:
    """Escribe un log en el evento para que quede visible en la UI de Indico."""
    event = getattr(registration, "event", None)
    if not event or not hasattr(event, "log"):
        return

    log_data: Dict[str, Any] = {
        "provider": "Niubiz",
        "status": status,
        "transaction_id": transaction_id,
    }
    if amount is not None:
        try:
            log_data["amount"] = float(amount)
        except Exception:
            pass
    if currency:
        log_data["currency"] = currency
    if data:
        log_data["payload_present"] = bool(data.get("payload"))
        extra = {k: v for k, v in data.items() if k not in {"payload", "provider"}}
        if extra:
            log_data["details"] = extra

    try:
        event.log(
            EventLogRealm.participants,
            kind,
            NIUBIZ_MODULE_NAME,
            summary,
            data=log_data,
        )
    except Exception:
        logger.exception("No se pudo registrar el log Niubiz en el evento")


# -----------------------------------------------------
# Transacciones
# -----------------------------------------------------
def record_payment_transaction(
    *,
    registration,
    amount: Optional[Decimal],
    currency: Optional[str],
    action: TransactionAction,
    data: Optional[Dict[str, Any]] = None,
):
    """Crea una transacción en Indico y asegura la persistencia del payload."""
    if amount is None:
        amount = parse_amount(getattr(registration, "price", None), Decimal("0")) or Decimal("0")
    try:
        amount_value = float(amount)
    except Exception:
        amount_value = float(parse_amount(getattr(registration, "price", None), Decimal("0")) or 0)

    currency_value = currency or getattr(registration, "currency", None) or "PEN"
    data_payload = _prepare_transaction_payload(
        data,
        transaction_id=None,
        status=None,
        amount=amount,
        currency=currency_value,
    )

    try:
        return register_transaction(
            registration=registration,
            amount=amount_value,
            currency=currency_value,
            action=action,
            provider="niubiz",
            data=data_payload,
        )
    except Exception:
        logger.exception("Error registrando transacción Niubiz para inscripción %s", getattr(registration, "id", "?"))
        return None


# -----------------------------------------------------
# Funciones de alto nivel (callbacks)
# -----------------------------------------------------
def handle_successful_payment(
    registration,
    *,
    amount: Optional[Decimal],
    currency: Optional[str],
    transaction_id: Optional[str],
    status: Optional[str],
    summary: str,
    data: Optional[Dict[str, Any]],
    toggle_paid: bool = False,
):
    transaction = record_payment_transaction(
        registration=registration,
        amount=amount,
        currency=currency,
        action=TransactionAction.complete,
        data=data,
    )
    if toggle_paid and (transaction is None or getattr(transaction, "status", None) != TransactionStatus.successful):
        _apply_registration_paid_state(registration, True)

    _log_event(
        registration,
        summary=summary,
        kind=LogKind.positive,
        status=status,
        transaction_id=transaction_id,
        amount=amount,
        currency=currency,
        data=data,
    )
    return transaction


def handle_failed_payment(
    registration,
    *,
    amount: Optional[Decimal],
    currency: Optional[str],
    transaction_id: Optional[str],
    status: Optional[str],
    summary: str,
    data: Optional[Dict[str, Any]],
    cancelled: bool = False,
    toggle_paid: bool = False,
):
    action = TransactionAction.cancel if cancelled else TransactionAction.reject
    transaction = record_payment_transaction(
        registration=registration,
        amount=amount,
        currency=currency,
        action=action,
        data=data,
    )
    if (cancelled or toggle_paid) and (
        transaction is None or getattr(transaction, "status", None) not in {TransactionStatus.cancelled}
    ):
        _apply_registration_paid_state(registration, False)

    _log_event(
        registration,
        summary=summary,
        kind=LogKind.change if cancelled else LogKind.negative,
        status=status,
        transaction_id=transaction_id,
        amount=amount,
        currency=currency,
        data=data,
    )
    return transaction


def handle_refund(
    registration,
    *,
    amount: Optional[Decimal],
    currency: Optional[str],
    transaction_id: Optional[str],
    status: Optional[str],
    summary: str,
    data: Optional[Dict[str, Any]],
    success: bool = True,
):
    action = TransactionAction.cancel if success else TransactionAction.reject
    transaction = record_payment_transaction(
        registration=registration,
        amount=amount,
        currency=currency,
        action=action,
        data=data,
    )
    if success and (transaction is None or getattr(transaction, "status", None) not in {TransactionStatus.cancelled}):
        _apply_registration_paid_state(registration, False)

    _log_event(
        registration,
        summary=summary,
        kind=LogKind.change if success else LogKind.negative,
        status=status,
        transaction_id=transaction_id,
        amount=amount,
        currency=currency,
        data=data,
    )
    return transaction


def handle_pending_payment(
    registration,
    *,
    amount: Optional[Decimal],
    currency: Optional[str],
    transaction_id: Optional[str],
    status: Optional[str],
    summary: str,
    data: Optional[Dict[str, Any]],
):
    transaction = record_payment_transaction(
        registration=registration,
        amount=amount,
        currency=currency,
        action=TransactionAction.pending,
        data=data,
    )
    _log_event(
        registration,
        summary=summary,
        kind=LogKind.warning,
        status=status,
        transaction_id=transaction_id,
        amount=amount,
        currency=currency,
        data=data,
    )
    return transaction


__all__ = [
    "build_transaction_data",
    "handle_failed_payment",
    "handle_pending_payment",
    "handle_refund",
    "handle_successful_payment",
    "parse_amount",
    "record_payment_transaction",
]
