"""Vistas HTTP que implementan el flujo NO-PCI de Niubiz."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

from flask import jsonify, request
from werkzeug.exceptions import BadRequest, Forbidden, NotFound, TooManyRequests

from indico.modules.events.payment.models.transactions import (
    PaymentTransaction,
    TransactionStatus,
)
from indico.modules.events.registration.models.registrations import Registration

from . import _
from .client import NiubizClient
from .indico_integration import (
    build_transaction_data,
    handle_failed_payment,
    handle_pending_payment,
    handle_refund,
    handle_successful_payment,
    parse_amount as integration_parse_amount,
)
from .security import (
    DEFAULT_CALLBACK_IPS,
    check_rate_limit,
    extract_bearer_token,
    ip_in_whitelist,
    parse_ip_list,
    redact_payload,
    validate_nbz_signature,
)
from .settings import (
    get_credentials_for_event,
    get_endpoint_for_event,
    get_scoped_setting,
)
from .status_mapping import DEFAULT_STATUS, NIUBIZ_STATUS_MAP
from .utils import (
    extract_details,
    extract_purchase_numbers,
    generate_external_transaction_id,
    generate_purchase_number,
    get_checkout_script_url,
    map_status,
    normalize_currency,
    parse_amount,
)

logger = logging.getLogger(__name__)


def _get_plugin() -> "NiubizPaymentPlugin":
    from .plugin import NiubizPaymentPlugin

    return NiubizPaymentPlugin.instance


def _load_registration(*, event_id: int, reg_form_id: int, registration_id: int) -> Registration:
    registration = Registration.query.filter_by(
        id=registration_id,
        event_id=event_id,
        registration_form_id=reg_form_id,
    ).first()
    if not registration:
        raise NotFound("Registration not found")
    return registration


def _build_client(event) -> NiubizClient:
    plugin = _get_plugin()
    merchant_id = get_scoped_setting(event, "merchant_id", plugin)
    access_key, secret_key = get_credentials_for_event(event, plugin=plugin)
    endpoint = get_endpoint_for_event(event, plugin=plugin)
    return NiubizClient(
        merchant_id=merchant_id,
        access_key=access_key,
        secret_key=secret_key,
        endpoint=endpoint,
    )


def _collect_ips(extra_config: Optional[str]) -> Tuple[str, ...]:
    configured = []
    if extra_config:
        configured = [line.strip() for line in extra_config.splitlines() if line.strip()]
    return DEFAULT_CALLBACK_IPS + tuple(configured)


def _validate_callback_security(event, *, body: bytes) -> None:
    plugin = _get_plugin()
    expected_token = get_scoped_setting(event, "callback_authorization_token", plugin)
    if expected_token:
        provided_token = extract_bearer_token(request.headers.get("Authorization"))
        if provided_token != expected_token:
            logger.warning("Token de autorización inválido para callback Niubiz")
            raise Forbidden("Invalid Authorization token")

    whitelist_raw = get_scoped_setting(event, "callback_ip_whitelist", plugin)
    networks = parse_ip_list(_collect_ips(whitelist_raw))
    if networks:
        remote_addr = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        if "," in remote_addr:
            remote_addr = remote_addr.split(",", 1)[0].strip()
        if not remote_addr or not ip_in_whitelist(remote_addr, networks):
            logger.warning("Callback Niubiz desde IP no autorizada: %s", remote_addr or "<desconocida>")
            raise Forbidden("IP not allowed")

    secret = get_scoped_setting(event, "callback_hmac_secret", plugin)
    if secret:
        signature = request.headers.get("NBZ-Signature")
        if not signature or not validate_nbz_signature(secret, body, signature):
            logger.warning("Firma HMAC inválida para callback Niubiz")
            raise Forbidden("Invalid NBZ-Signature header")

    bucket = f"niubiz-callback:{getattr(event, 'id', 'global')}"
    if not check_rate_limit(bucket):
        raise TooManyRequests("Callback rate limit exceeded")


def start() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        event_id = int(payload["event_id"])
        reg_form_id = int(payload["reg_form_id"])
        registration_id = int(payload["registration_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BadRequest("Missing registration identifiers") from exc

    registration = _load_registration(
        event_id=event_id, reg_form_id=reg_form_id, registration_id=registration_id
    )
    event = registration.event
    client = _build_client(event)

    amount = parse_amount(payload.get("amount") or getattr(registration, "price", None))
    currency = normalize_currency(payload.get("currency") or getattr(registration, "currency", None))

    purchase_number = generate_purchase_number(event_id, registration_id)
    external_transaction_id = generate_external_transaction_id()

    session_data = client.create_session(
        amount=amount,
        currency=currency,
        purchase_number=purchase_number,
        data=payload.get("session_payload"),
    )

    response = {
        "sessionKey": session_data.get("sessionKey"),
        "purchaseNumber": purchase_number,
        "externalTransactionId": external_transaction_id,
        "amount": float(amount),
        "currency": currency,
        "merchantId": client.merchant_id,
        "checkoutUrl": get_checkout_script_url(client.endpoint),
    }
    return jsonify(response), 200


def return_payment() -> Any:
    payload = request.get_json(silent=True) or {}
    purchase_number = payload.get("purchaseNumber")
    transaction_token = payload.get("transactionToken")
    session_key = payload.get("sessionKey")
    external_transaction_id = payload.get("externalTransactionId")

    if not purchase_number or not transaction_token or not session_key or not external_transaction_id:
        raise BadRequest("Missing return payload data")

    event_id, registration_id = extract_purchase_numbers(purchase_number)
    if event_id is None or registration_id is None:
        raise BadRequest("Invalid purchase number")

    reg_form_id = int(payload.get("reg_form_id", 0)) or None
    if reg_form_id is None:
        raise BadRequest("Missing reg_form_id")

    registration = _load_registration(
        event_id=event_id, reg_form_id=reg_form_id, registration_id=registration_id
    )
    event = registration.event
    client = _build_client(event)

    amount = parse_amount(payload.get("amount") or getattr(registration, "price", None))
    currency = normalize_currency(payload.get("currency") or getattr(registration, "currency", None))

    token_response = client.get_token_card(
        transaction_token=transaction_token,
        session_key=session_key,
        purchase_number=purchase_number,
    )
    card_token = token_response.get("token") or token_response.get("card", {}).get("token")
    if not card_token:
        logger.error("Respuesta de tokenización Niubiz sin token válido: %s", token_response)
        raise BadRequest("Invalid card token response")

    push_response = client.push_payment(
        amount=amount,
        currency=currency,
        purchase_number=purchase_number,
        external_transaction_id=external_transaction_id,
        card_token=card_token,
        data=payload.get("payment_payload"),
    )

    flattened = extract_details(push_response)
    status_value = flattened.get("status") or push_response.get("status")
    action_code = flattened.get("action_code") or push_response.get("actionCode")
    transaction_id = (
        flattened.get("transaction_id")
        or flattened.get("transaction_identifier")
        or push_response.get("transactionIdentifier")
    )

    mapping = map_status(
        status=status_value,
        action_code=action_code,
        status_order=flattened.get("status_order"),
        payment_method=push_response.get("paymentMethod"),
        action_description=flattened.get("action_description"),
    )

    data = build_transaction_data(
        payload=redact_payload(push_response),
        source="return",
        status=status_value,
        action_code=action_code,
        transaction_id=transaction_id,
        order_id=purchase_number,
        external_id=external_transaction_id,
        purchase_number=purchase_number,
        external_transaction_id=external_transaction_id,
    )
    data["transaction_identifier"] = transaction_id

    amount_decimal = integration_parse_amount(amount, None)
    toggle_paid = mapping.toggle_paid and not getattr(registration, "is_paid", False)

    if mapping.status == TransactionStatus.successful:
        handle_successful_payment(
            registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=transaction_id,
            status=status_value,
            summary=mapping.summary,
            data=data,
            toggle_paid=toggle_paid or mapping.manual_confirmation,
        )
    elif mapping.status == TransactionStatus.pending:
        handle_pending_payment(
            registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=transaction_id,
            status=status_value,
            summary=mapping.summary,
            data=data,
        )
    elif mapping.status == TransactionStatus.cancelled:
        handle_refund(
            registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=transaction_id,
            status=status_value,
            summary=mapping.summary,
            data=data,
            success=True,
        )
    else:
        handle_failed_payment(
            registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=transaction_id,
            status=status_value,
            summary=mapping.summary,
            data=data,
            cancelled=False,
        )

    response = {
        "status": mapping.status.name,
        "transactionIdentifier": transaction_id,
        "actionCode": action_code,
    }
    return jsonify(response), 200


def notify() -> Any:
    payload = request.get_json(silent=True)
    body = request.get_data(cache=True) or b""
    if not isinstance(payload, dict):
        raise BadRequest("Invalid payload")

    details = extract_details(payload)
    purchase_number = details.get("purchase_number")
    event_id, registration_id = extract_purchase_numbers(purchase_number)

    if event_id is None or registration_id is None:
        logger.warning("Callback Niubiz con purchaseNumber inválido: %s", purchase_number)
        return jsonify({"received": False, "error": "invalid_purchase_number"}), 400

    reg_form_id = int(payload.get("reg_form_id", 0)) or None
    if reg_form_id is None:
        logger.warning("Callback Niubiz sin reg_form_id")
        return jsonify({"received": False, "error": "missing_reg_form"}), 400

    registration = _load_registration(
        event_id=event_id, reg_form_id=reg_form_id, registration_id=registration_id
    )
    event = registration.event

    _validate_callback_security(event, body=body)

    amount_expected = integration_parse_amount(getattr(registration, "price", None), None)
    currency_expected = getattr(registration, "currency", None) or "PEN"
    amount_received = integration_parse_amount(details.get("amount"), amount_expected)
    currency_received = normalize_currency(details.get("currency") or currency_expected)

    if (
        amount_expected is not None
        and amount_received is not None
        and float(amount_expected) != float(amount_received)
    ):
        logger.warning("Monto inconsistente en callback Niubiz")
        return jsonify({"received": False, "error": "amount_mismatch"}), 400

    if currency_expected.upper() != currency_received.upper():
        logger.warning("Moneda inconsistente en callback Niubiz")
        return jsonify({"received": False, "error": "currency_mismatch"}), 400

    status_value = details.get("status")
    action_code = details.get("action_code")
    transaction_id = details.get("transaction_id") or details.get("transaction_identifier")

    mapping = map_status(
        status=status_value,
        action_code=action_code,
        status_order=details.get("status_order"),
        payment_method=payload.get("paymentMethod"),
        action_description=details.get("action_description"),
    )

    config = NIUBIZ_STATUS_MAP.get((status_value or "").upper(), DEFAULT_STATUS)
    toggle_paid = bool(config.get("toggle_paid"))

    data = build_transaction_data(
        payload=payload,
        source="notify",
        status=status_value,
        action_code=action_code,
        transaction_id=transaction_id,
        order_id=purchase_number,
        external_id=details.get("operation_number"),
        purchase_number=purchase_number,
        external_transaction_id=details.get("operation_number"),
    )
    data["transaction_identifier"] = transaction_id

    amount_for_handler = amount_received or amount_expected

    if mapping.status == TransactionStatus.successful:
        existing = (
            PaymentTransaction.query.filter_by(
                registration_id=registration.id,
                provider="niubiz",
                external_transaction_id=transaction_id,
            ).first()
            if hasattr(PaymentTransaction, "external_transaction_id")
            else None
        )
        if existing:
            logger.info("Callback Niubiz duplicado ignorado transaction_id=%s", transaction_id)
            return jsonify({"received": True, "duplicate": True}), 200
        handle_successful_payment(
            registration,
            amount=amount_for_handler,
            currency=currency_received,
            transaction_id=transaction_id,
            status=status_value,
            summary=config.get("summary"),
            data=data,
            toggle_paid=toggle_paid or mapping.manual_confirmation,
        )
    elif mapping.status == TransactionStatus.pending:
        handle_pending_payment(
            registration,
            amount=amount_for_handler,
            currency=currency_received,
            transaction_id=transaction_id,
            status=status_value,
            summary=config.get("summary"),
            data=data,
        )
    elif mapping.status == TransactionStatus.cancelled:
        handle_refund(
            registration,
            amount=amount_for_handler,
            currency=currency_received,
            transaction_id=transaction_id,
            status=status_value,
            summary=config.get("summary"),
            data=data,
            success=True,
        )
    else:
        handle_failed_payment(
            registration,
            amount=amount_for_handler,
            currency=currency_received,
            transaction_id=transaction_id,
            status=status_value,
            summary=config.get("summary"),
            data=data,
            cancelled=False,
        )

    return jsonify({"received": True, "status": mapping.status.name}), 200


def refund() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        event_id = int(payload["event_id"])
        reg_form_id = int(payload["reg_form_id"])
        registration_id = int(payload["registration_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BadRequest("Missing registration identifiers") from exc

    registration = _load_registration(
        event_id=event_id, reg_form_id=reg_form_id, registration_id=registration_id
    )
    event = registration.event

    client = _build_client(event)
    try:
        client.refund_payment()
    except NotImplementedError:
        return jsonify({"error": "refund_not_implemented"}), 501

    return jsonify({"status": "queued"}), 202


__all__ = [
    "notify",
    "refund",
    "return_payment",
    "start",
]
