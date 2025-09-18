"""Utility helpers used by the Niubiz payment plugin."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

from indico.modules.events.payment.models.transactions import TransactionStatus


logger = logging.getLogger(__name__)


CHECKOUT_JS_URLS = {
    "sandbox": "https://static-content-qas.vnforapps.com/env/sandbox/js/checkout.js",
    "prod": "https://static-content.vnforapps.com/v2/js/checkout.js",
}

# Official production IP ranges published by Niubiz for callbacks.
DEFAULT_CALLBACK_IPS = (
    "200.48.119.0/24",
    "200.48.62.0/24",
    "200.48.63.0/24",
    "200.37.132.0/24",
    "200.37.133.0/24",
)

# Additional codes documented as rejections or technical failures.
REJECTED_CODES = {"101", "102", "116", "129", "180", "191"}
FAILED_CODES = {"670", "678", "754", "666"}
CANCELLED_CODES = {"9997", "9905"}
TIMEOUT_CODES = {"909", "9999"}


@dataclass(frozen=True)
class StatusMapping:
    """Structured result describing the mapped transaction status."""

    status: TransactionStatus
    manual_confirmation: bool = False
    reason: Optional[str] = None


def _collect_dicts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return a flat list with every nested dictionary in ``payload``."""

    if not isinstance(payload, dict):
        return []

    seen: set[int] = set()
    stack: List[Dict[str, Any]] = [payload]
    result: List[Dict[str, Any]] = []

    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        result.append(current)
        for value in current.values():
            if isinstance(value, dict):
                stack.append(value)
            elif isinstance(value, list):
                stack.extend(item for item in value if isinstance(item, dict))

    return result


def _extract_value(payload: Dict[str, Any], *keys: str) -> Optional[Any]:
    """Try to retrieve the first existing key from the payload hierarchy."""

    dictionaries = _collect_dicts(payload)
    for dictionary in dictionaries:
        for key in keys:
            if key in dictionary and dictionary[key] not in (None, ""):
                return dictionary[key]
            upper = key.upper()
            if upper in dictionary and dictionary[upper] not in (None, ""):
                return dictionary[upper]
            lower = key.lower()
            if lower in dictionary and dictionary[lower] not in (None, ""):
                return dictionary[lower]
    return None


def extract_callback_details(payload: Dict[str, Any]) -> Dict[str, Optional[Any]]:
    """Normalize raw Niubiz callback payloads into a flat dictionary."""

    if not isinstance(payload, dict):
        return {}

    details: Dict[str, Optional[Any]] = {
        "purchase_number": _extract_value(
            payload,
            "purchaseNumber",
            "purchase_number",
            "orderId",
            "order_id",
        ),
        "transaction_id": _extract_value(
            payload,
            "transactionId",
            "transaction_id",
            "TRANSACTION_ID",
            "operationNumber",
            "operation_number",
        ),
        "status": _extract_value(payload, "status", "STATUS"),
        "status_order": _extract_value(payload, "statusOrder", "status_order"),
        "action_code": _extract_value(payload, "actionCode", "ACTION_CODE"),
        "action_description": _extract_value(
            payload,
            "actionDescription",
            "ACTION_DESCRIPTION",
            "message",
            "detalle",
        ),
        "transaction_date": _extract_value(payload, "transactionDate", "TRANSACTION_DATE"),
        "amount": _extract_value(payload, "amount"),
        "currency": _extract_value(payload, "currency"),
        "authorization_code": _extract_value(payload, "authorizationCode", "AUTHORIZATION_CODE"),
        "trace_number": _extract_value(payload, "traceNumber", "TRACE_NUMBER"),
        "brand": _extract_value(payload, "brand", "BRAND"),
        "masked_card": _extract_value(payload, "maskedCard", "masked_card", "PAN", "pan"),
        "eci": _extract_value(payload, "eci", "ECI"),
        "cip": _extract_value(payload, "cip", "CIP"),
        "operation_number": _extract_value(payload, "operationNumber", "operation_number"),
        "payment_method": _extract_value(payload, "paymentMethod", "payment_method"),
        "channel": _extract_value(payload, "channel"),
    }

    # ``purchaseNumber`` is sometimes nested within ``order`` and should override
    # the ``orderId`` fallback when available.
    order_purchase = _extract_value(payload, "purchaseNumber", "purchase_number")
    if order_purchase:
        details["purchase_number"] = order_purchase

    return details


def validate_nbz_signature(secret: str, body: bytes, signature: str) -> bool:
    """Validate the ``NBZ-Signature`` header using HMAC SHA-256."""

    if not secret or not signature:
        return False

    computed = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    provided = signature.strip().lower()
    return hmac.compare_digest(provided, computed.lower())


def get_checkout_script_url(endpoint: str = "sandbox") -> str:
    endpoint_key = "sandbox" if (endpoint or "sandbox").lower() == "sandbox" else "prod"
    return CHECKOUT_JS_URLS[endpoint_key]


def map_niubiz_status(
    *,
    status: Optional[str],
    action_code: Optional[str] = None,
    status_order: Optional[str] = None,
    payment_method: Optional[str] = None,
    action_description: Optional[str] = None,
) -> StatusMapping:
    """Map Niubiz fields into the internal :class:`TransactionStatus` enum."""

    status_value = (status or "").strip()
    status_lower = status_value.lower()
    status_order_value = (status_order or "").strip()
    status_order_lower = status_order_value.lower()
    action_code_value = (action_code or "").strip()
    action_code_upper = action_code_value.upper()
    payment_method_lower = (payment_method or "").strip().lower()
    action_description_lower = (action_description or "").strip().lower()

    manual_confirmation = False

    # ``statusOrder`` appears on Pago Link callbacks.
    if status_order_lower == "completed":
        return StatusMapping(TransactionStatus.successful)
    if status_order_lower in {"expired", "cancelled", "canceled"}:
        return StatusMapping(TransactionStatus.cancelled)
    if status_order_lower == "pending":
        return StatusMapping(TransactionStatus.pending)

    if status_lower == "confirmed":
        manual_confirmation = True
        return StatusMapping(TransactionStatus.successful, manual_confirmation=manual_confirmation)

    if status_lower == "authorized":
        if action_code_upper == "000":
            return StatusMapping(TransactionStatus.successful)
        return StatusMapping(TransactionStatus.failed)

    if status_lower in {"captured", "paid", "completed", "approved", "success"}:
        return StatusMapping(TransactionStatus.successful)

    if status_lower in {"not authorized", "not_authorized", "denied", "declined"}:
        return StatusMapping(TransactionStatus.failed)

    if status_lower == "review":
        return StatusMapping(TransactionStatus.pending)

    if status_lower in {"pending", "pendiente"}:
        return StatusMapping(TransactionStatus.pending)

    if status_lower in {"generated", "generado", "generada"}:
        return StatusMapping(TransactionStatus.pending)

    if status_lower in {"voided", "void", "anulado", "anulada"}:
        return StatusMapping(TransactionStatus.cancelled)

    if status_lower in {"cancelled", "canceled"}:
        return StatusMapping(TransactionStatus.cancelled)

    if status_lower in {"expired", "expirado", "expirada"}:
        return StatusMapping(TransactionStatus.cancelled)

    if status_lower in {"refunded", "refund", "reembolsado", "reembolsada"}:
        return StatusMapping(TransactionStatus.cancelled)

    if status_lower in {"rejected"}:
        return StatusMapping(TransactionStatus.failed)

    if status_lower in {"failed", "error"}:
        return StatusMapping(TransactionStatus.failed)

    if action_description_lower:
        if "cip" in action_description_lower and any(
            keyword in action_description_lower for keyword in ("gener", "pend", "esper")
        ):
            return StatusMapping(TransactionStatus.pending)
        if "yape" in action_description_lower and any(
            keyword in action_description_lower for keyword in ("esper", "pending", "pend", "wait")
        ):
            return StatusMapping(TransactionStatus.pending)
        if any(keyword in action_description_lower for keyword in ("anulad", "void")):
            return StatusMapping(TransactionStatus.cancelled)

    if payment_method_lower:
        if "pagoefectivo" in payment_method_lower or "pago efectivo" in payment_method_lower:
            return StatusMapping(TransactionStatus.pending)
        if "yape" in payment_method_lower:
            if action_code_upper != "000" or status_lower in {"pending", "review", "", "authorized"}:
                return StatusMapping(TransactionStatus.pending)

    if action_code_upper in CANCELLED_CODES or action_code_upper in TIMEOUT_CODES:
        return StatusMapping(TransactionStatus.cancelled)

    if action_code_upper in REJECTED_CODES or action_code_upper in FAILED_CODES:
        return StatusMapping(TransactionStatus.failed)

    if action_code_upper and action_code_upper != "000":
        return StatusMapping(TransactionStatus.failed)

    if action_code_upper == "000":
        return StatusMapping(TransactionStatus.pending)

    return StatusMapping(TransactionStatus.pending)


def map_action_code_to_status(action_code: str, status: str) -> TransactionStatus:
    """Compatibility wrapper around :func:`map_niubiz_status`."""

    return map_niubiz_status(status=status, action_code=action_code).status


def parse_ip_list(values: Sequence[str]) -> Sequence[ipaddress._BaseNetwork]:  # type: ignore[name-defined]
    networks = []
    for value in values:
        value = (value or "").strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid Niubiz callback IP range: %%s", value)
    return tuple(networks)


def ip_in_whitelist(ip: str, networks: Iterable[ipaddress._BaseNetwork]) -> bool:  # type: ignore[name-defined]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Received Niubiz callback from invalid IP address: %%s", ip)
        return False
    return any(address in network for network in networks)
