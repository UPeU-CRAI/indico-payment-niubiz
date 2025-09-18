"""Flask blueprint that exposes the HTTP entrypoints for the Niubiz plugin."""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, Optional, Tuple

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import Forbidden

from indico.modules.events.payment.models.transactions import (
    PaymentTransaction,
    TransactionStatus,
)
from indico.modules.events.registration.models.registrations import Registration

from indico_payment_niubiz import _
from indico_payment_niubiz.indico_integration import (
    build_transaction_data,
    handle_failed_payment,
    handle_pending_payment,
    handle_refund,
    handle_successful_payment,
    parse_amount,
)
from indico_payment_niubiz.settings import get_scoped_setting
from indico_payment_niubiz.status_mapping import DEFAULT_STATUS, NIUBIZ_STATUS_MAP
from indico_payment_niubiz.util import (
    DEFAULT_CALLBACK_IPS,
    StatusMapping,
    extract_callback_details,
    ip_in_whitelist,
    map_niubiz_status,
    parse_ip_list,
    validate_nbz_signature,
)


logger = logging.getLogger(__name__)


def _get_plugin() -> "NiubizPaymentPlugin":
    from indico_payment_niubiz.plugin import NiubizPaymentPlugin

    return NiubizPaymentPlugin.instance


def _parse_purchase_number(value: Optional[str]) -> Tuple[Optional[int], Optional[int]]:
    """Split the purchase number (``eventId-registrationId``)."""

    if not value or "-" not in value:
        return None, None

    try:
        event_id_str, registration_id_str = value.split("-", 1)
        return int(event_id_str), int(registration_id_str)
    except (TypeError, ValueError):
        return None, None


def _load_registration(
    *,
    registration_id: Optional[int],
    reg_form_id: int,
    event_id: int,
) -> Optional[Registration]:
    if registration_id is None:
        return None

    return Registration.query.filter_by(
        id=registration_id,
        event_id=event_id,
        registration_form_id=reg_form_id,
    ).first()


def _extract_authorization_header() -> str:
    value = (request.headers.get("Authorization") or "").strip()
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return value


def _collect_allowed_ips(extra_config: Optional[str]) -> Iterable[str]:
    configured = []
    if extra_config:
        configured = [line.strip() for line in extra_config.splitlines() if line.strip()]
    return DEFAULT_CALLBACK_IPS + tuple(configured)


def _validate_authorization(event, plugin) -> None:
    expected = get_scoped_setting(event, "callback_authorization_token", plugin)
    if not expected:
        return

    provided = _extract_authorization_header()
    if provided != expected:
        logger.warning("Token de autorización inválido para callback Niubiz")
        raise Forbidden("Invalid Authorization token")


def _validate_ip(event, plugin) -> None:
    whitelist_raw = get_scoped_setting(event, "callback_ip_whitelist", plugin) or ""
    networks = parse_ip_list(_collect_allowed_ips(whitelist_raw))

    if not networks:
        return

    remote_addr = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if "," in remote_addr:
        remote_addr = remote_addr.split(",", 1)[0].strip()

    if not remote_addr or not ip_in_whitelist(remote_addr, networks):
        logger.warning("Callback Niubiz desde IP no autorizada: %s", remote_addr or "<desconocida>")
        raise Forbidden("IP not allowed")


def _validate_signature(event, plugin, body: bytes) -> None:
    secret = get_scoped_setting(event, "callback_hmac_secret", plugin)
    if not secret:
        return

    received_signature = request.headers.get("NBZ-Signature", "")
    if not received_signature:
        logger.warning("Callback Niubiz sin cabecera NBZ-Signature")
        raise Forbidden("Missing NBZ-Signature header")

    if not validate_nbz_signature(secret, body, received_signature):
        logger.warning("Firma HMAC inválida para callback Niubiz")
        raise Forbidden("Invalid NBZ-Signature header")


def _build_transaction_extra(details: Dict[str, Any]) -> Dict[str, Any]:
    relevant_keys = {
        "transaction_date",
        "authorization_code",
        "trace_number",
        "brand",
        "masked_card",
        "eci",
        "cip",
        "operation_number",
        "status_order",
        "action_description",
        "payment_method",
        "channel",
    }
    return {key: details.get(key) for key in relevant_keys if details.get(key) is not None}


def _handle_success(
    registration,
    *,
    summary: str,
    amount,
    currency: str,
    transaction_id: Optional[str],
    status_value: Optional[str],
    data: Dict[str, Any],
    mapping: StatusMapping,
    toggle_paid: bool,
) -> None:
    summary_message = summary
    if mapping.manual_confirmation:
        summary_message = _("Niubiz confirmó manualmente el pago mediante notificación.")

    handle_successful_payment(
        registration,
        amount=amount,
        currency=currency,
        transaction_id=transaction_id,
        status=status_value,
        summary=summary_message,
        data=data,
        toggle_paid=toggle_paid or mapping.manual_confirmation,
    )


def _handle_cancelled(
    registration,
    *,
    summary: str,
    amount,
    currency: str,
    transaction_id: Optional[str],
    status_value: Optional[str],
    data: Dict[str, Any],
    is_refund: bool,
    toggle_paid: bool,
) -> None:
    if is_refund:
        handle_refund(
            registration,
            amount=amount,
            currency=currency,
            transaction_id=transaction_id,
            status=status_value,
            summary=summary,
            data=data,
            success=True,
        )
    else:
        handle_failed_payment(
            registration,
            amount=amount,
            currency=currency,
            transaction_id=transaction_id,
            status=status_value,
            summary=summary,
            data=data,
            cancelled=True,
            toggle_paid=toggle_paid,
        )


blueprint = Blueprint("payment_niubiz", __name__)


@blueprint.post(
    "/event/<int:event_id>/registrations/<int:reg_form_id>/payment/response/niubiz/notify"
)
def niubiz_callback(event_id: int, reg_form_id: int):
    plugin = _get_plugin()

    body = request.get_data(cache=True) or b""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        logger.warning("Callback Niubiz recibido sin JSON válido: %s", body[:256])
        return jsonify({"received": False, "error": "invalid_json"}), 400

    details = extract_callback_details(payload)
    purchase_number = details.get("purchase_number")
    event_from_purchase, registration_id = _parse_purchase_number(purchase_number)

    if event_from_purchase is not None and event_from_purchase != event_id:
        logger.warning(
            "Callback Niubiz con event_id inconsistente: URL=%s payload=%s",
            event_id,
            purchase_number,
        )
        return jsonify({"received": False, "error": "event_mismatch"}), 400

    registration = _load_registration(
        registration_id=registration_id,
        reg_form_id=reg_form_id,
        event_id=event_id,
    )
    if not registration:
        logger.warning(
            "Callback Niubiz sin inscripción asociada. purchase=%s event_id=%s",
            purchase_number,
            event_id,
        )
        return jsonify({"received": False, "error": "registration_not_found"}), 200

    event = registration.event

    _validate_authorization(event, plugin)
    _validate_signature(event, plugin, body)
    _validate_ip(event, plugin)

    expected_amount = parse_amount(getattr(registration, "price", None), None)
    expected_currency = getattr(registration, "currency", None) or "PEN"
    received_amount = parse_amount(details.get("amount"), expected_amount)
    received_currency = (details.get("currency") or expected_currency).upper()

    if (
        expected_amount is not None
        and received_amount is not None
        and float(expected_amount) != float(received_amount)
    ):
        logger.warning(
            "Monto inconsistente en callback Niubiz. Esperado=%s Recibido=%s",
            expected_amount,
            received_amount,
        )
        return jsonify({"received": False, "error": "amount_mismatch"}), 400

    if expected_currency != received_currency:
        logger.warning(
            "Moneda inconsistente en callback Niubiz. Esperada=%s Recibida=%s",
            expected_currency,
            received_currency,
        )
        return jsonify({"received": False, "error": "currency_mismatch"}), 400

    transaction_id = details.get("transaction_id")
    status_value = details.get("status")
    action_code = details.get("action_code")

    mapping = map_niubiz_status(
        status=status_value,
        action_code=action_code,
        status_order=details.get("status_order"),
        payment_method=details.get("payment_method"),
        action_description=details.get("action_description"),
    )

    status_key = (status_value or "").strip().upper()
    config = NIUBIZ_STATUS_MAP.get(status_key, DEFAULT_STATUS)
    summary = config.get("summary") or _("Estado desconocido recibido desde Niubiz")
    toggle_paid = bool(config.get("toggle_paid"))

    transaction_data = build_transaction_data(
        payload=payload,
        source="notify",
        status=status_value or None,
        action_code=action_code or None,
        transaction_id=transaction_id,
        order_id=purchase_number,
        external_id=details.get("operation_number"),
    )
    transaction_data.update(
        {
            "amount": float(received_amount) if received_amount is not None else None,
            "currency": received_currency,
            "manual_confirmation": mapping.manual_confirmation,
        }
    )
    transaction_data.update(_build_transaction_extra(details))

    amount_for_handlers = received_amount if received_amount is not None else expected_amount

    logger.info(
        "Callback Niubiz: purchase=%s status=%s action_code=%s mapped=%s",
        purchase_number,
        status_value,
        action_code,
        mapping.status.name,
    )

    if (
        mapping.status == TransactionStatus.successful
        and transaction_id
        and hasattr(PaymentTransaction, "external_transaction_id")
    ):
        existing = PaymentTransaction.query.filter_by(
            registration_id=registration.id,
            external_transaction_id=transaction_id,
        ).first()
        if existing:
            logger.info("Callback Niubiz duplicado ignorado — transaction_id=%s", transaction_id)
            return jsonify({"received": True, "duplicate": True}), 200

    status_lower = (status_value or "").strip().lower()
    is_refund = status_lower in {"refunded", "refund"}

    if mapping.status == TransactionStatus.successful:
        _handle_success(
            registration,
            summary=summary,
            amount=amount_for_handlers,
            currency=received_currency,
            transaction_id=transaction_id,
            status_value=status_value,
            data=transaction_data,
            mapping=mapping,
            toggle_paid=toggle_paid,
        )
    elif mapping.status == TransactionStatus.pending:
        handle_pending_payment(
            registration,
            amount=amount_for_handlers,
            currency=received_currency,
            transaction_id=transaction_id,
            status=status_value,
            summary=summary,
            data=transaction_data,
        )
    elif mapping.status == TransactionStatus.cancelled:
        _handle_cancelled(
            registration,
            summary=summary,
            amount=amount_for_handlers,
            currency=received_currency,
            transaction_id=transaction_id,
            status_value=status_value,
            data=transaction_data,
            is_refund=is_refund,
            toggle_paid=toggle_paid,
        )
    else:
        handle_failed_payment(
            registration,
            amount=amount_for_handlers,
            currency=received_currency,
            transaction_id=transaction_id,
            status=status_value,
            summary=summary,
            data=transaction_data,
            toggle_paid=toggle_paid,
        )

    return jsonify({"received": True, "status": mapping.status.name}), 200


__all__ = ["blueprint"]

