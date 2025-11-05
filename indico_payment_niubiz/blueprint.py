"""Flask blueprint that exposes the HTTP entrypoints for the Niubiz plugin."""

from __future__ import annotations

import json
import logging
from decimal import Decimal
from typing import Any, Dict, Iterable, Optional, Tuple

from flask import Blueprint, abort, flash, jsonify, redirect, request, url_for
from werkzeug.exceptions import BadRequest, Forbidden

from indico.modules.events.payment.models.transactions import (
    PaymentTransaction,
    TransactionStatus,
)
from indico.modules.events.registration.models.registrations import Registration

from indico_payment_niubiz import _
from indico_payment_niubiz.client import NiubizClientError
from indico_payment_niubiz.indico_integration import (
    build_transaction_data,
    handle_failed_payment,
    handle_pending_payment,
    handle_refund,
    handle_successful_payment,
    parse_amount,
)
from indico_payment_niubiz.payloads import build_antifraud_payload, collect_mdd_data
from indico_payment_niubiz.settings import (
    get_allowed_ips,
    get_authorization_token,
    get_default_currency,
    get_hmac_secret,
    get_merchant_defined_data,
    is_mdd_required,
)
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


def _get_plugin() -> "NiubizPlugin":
    from indico_payment_niubiz.plugin import NiubizPlugin

    return NiubizPlugin.instance


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
    expected = get_authorization_token(event, plugin)
    if not expected:
        return

    provided = _extract_authorization_header()
    if provided != expected:
        logger.warning("Token de autorización inválido para callback Niubiz")
        raise Forbidden("Invalid Authorization token")


def _validate_ip(event, plugin) -> None:
    extra_ips = get_allowed_ips(event, plugin)
    networks = parse_ip_list(_collect_allowed_ips("\n".join(extra_ips)))

    if not networks:
        return

    remote_addr = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if "," in remote_addr:
        remote_addr = remote_addr.split(",", 1)[0].strip()

    if not remote_addr or not ip_in_whitelist(remote_addr, networks):
        logger.warning("Callback Niubiz desde IP no autorizada: %s", remote_addr or "<desconocida>")
        raise Forbidden("IP not allowed")


def _validate_signature(event, plugin, body: bytes) -> None:
    secret = get_hmac_secret(event, plugin)
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


def _registration_redirect_url(registration) -> str:
    try:
        return registration.display_regform_url
    except Exception:
        locator = getattr(registration, "locator", None)
        if locator is not None and hasattr(locator, "registrant"):
            try:
                return url_for("event_registration.display_regform", locator.registrant)
            except Exception:
                pass
    return "/"


def _extract_method_payload() -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    if request.is_json:
        json_payload = request.get_json(silent=True)
        if isinstance(json_payload, dict):
            data.update(json_payload)
    data.update(request.values.to_dict())
    return data


def _extract_token_id(payload: Dict[str, Any]) -> Optional[str]:
    if not isinstance(payload, dict):
        return None

    for key in ("tokenId", "token_id", "TOKEN_ID", "token", "TOKEN"):
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)

    for nested_key in ("card", "order", "data", "dataMap", "result", "payload"):
        nested = payload.get(nested_key)
        if isinstance(nested, dict):
            token = _extract_token_id(nested)
            if token:
                return token
        elif isinstance(nested, list):
            for item in nested:
                if isinstance(item, dict):
                    token = _extract_token_id(item)
                    if token:
                        return token
    return None


@blueprint.post(
    "/event/<int:event_id>/registrations/<int:reg_form_id>/payment/niubiz/<int:reg_id>/start"
)
def start(event_id: int, reg_form_id: int, reg_id: int):
    registration = _load_registration(
        registration_id=reg_id,
        reg_form_id=reg_form_id,
        event_id=event_id,
    )
    if not registration:
        abort(404)

    plugin = _get_plugin()
    event = registration.event

    payload = _extract_method_payload()
    method = (payload.get("method") or "card").strip().lower()

    if method not in {"card", "yape", "pagoefectivo", "qr", "token"}:
        return jsonify({"success": False, "error": "invalid_method"}), 400

    if method == "token" and not plugin._get_bool(event, "enable_tokenization"):
        return jsonify({"success": False, "error": "tokenization_disabled"}), 400

    enabled_methods = plugin._collect_methods(event)
    if method != "token" and not enabled_methods.get(method, False):
        return jsonify({"success": False, "error": "method_disabled"}), 400

    amount = parse_amount(getattr(registration, "price", None), None) or Decimal("0.00")
    currency = (
        getattr(registration, "currency", None)
        or get_default_currency(event, plugin=plugin)
        or "PEN"
    )
    purchase_number = f"{event_id}-{reg_id}"

    client = plugin._build_client(event)

    merchant_defined_raw = get_merchant_defined_data(event, plugin=plugin)
    try:
        extra_mdd = json.loads(merchant_defined_raw) if merchant_defined_raw else {}
    except ValueError:
        logger.warning("Merchant Defined Data inválido en evento %s", event.id)
        extra_mdd = {}

    try:
        mdd_payload = collect_mdd_data(
            registration,
            extra=extra_mdd,
            require_all=is_mdd_required(event, plugin=plugin),
        )
    except Exception as exc:
        logger.exception("Error preparando Merchant Defined Data para Niubiz")
        return (
            jsonify(
                {
                    "success": False,
                    "error": "mdd_invalid",
                    "message": str(exc),
                }
            ),
            400,
        )

    antifraud_payload = build_antifraud_payload(
        registration,
        dict(mdd_payload),
        client_ip=request.headers.get("X-Forwarded-For", request.remote_addr),
    )

    session_kwargs: Dict[str, Any] = {
        "amount": amount,
        "currency": currency,
        "purchase_number": purchase_number,
        "payment_method": method,
        "data_map": mdd_payload,
        "antifraud": antifraud_payload,
    }

    if method == "token" and payload.get("token_id"):
        session_kwargs["token_id"] = payload.get("token_id")

    try:
        order_result = client.create_session(**session_kwargs)
    except NiubizClientError as exc:
        logger.exception("No se pudo iniciar sesión de pago en Niubiz")
        return (
            jsonify({"success": False, "error": "order_creation_failed", "message": str(exc)}),
            502,
        )

    order_data = order_result.get("data", {}) if isinstance(order_result, dict) else {}
    session_key = order_data.get("sessionKey")
    expiration = (
        order_data.get("expirationTime")
        or order_data.get("expirationDateTime")
        or order_data.get("expirationDate")
    )

    transaction_data = build_transaction_data(
        payload=order_data,
        source="session",
        status=order_data.get("status"),
        order_id=purchase_number,
        message="session_created",
    )
    transaction_data.update(
        {
            "purchase_number": purchase_number,
            "session_key": session_key,
            "payment_method": method,
            "mdd": mdd_payload,
            "antifraud": antifraud_payload,
        }
    )

    handle_pending_payment(
        registration,
        amount=amount,
        currency=currency,
        transaction_id=None,
        status=order_data.get("status") or "SESSION_CREATED",
        summary=_("Sesión de pago Niubiz iniciada."),
        data=transaction_data,
    )

    response_payload: Dict[str, Any] = {
        "success": True,
        "method": method,
        "purchase_number": purchase_number,
        "amount": f"{amount:.2f}",
        "currency": currency,
        "sessionKey": session_key,
        "session_expiration": expiration,
        "data": order_data,
        "merchantDefinedData": mdd_payload,
    }
    if method == "token" and payload.get("token_id"):
        response_payload["token_id"] = payload.get("token_id")

    return jsonify(response_payload)


def _complete_push_payment(
    registration,
    event,
    payload: Dict[str, Any],
    transaction_token: str,
    mdd_payload: Dict[str, str],
    plugin,
    *,
    client_ip: Optional[str] = None,
):
    amount = parse_amount(getattr(registration, "price", None), None) or Decimal("0.00")
    currency = (
        getattr(registration, "currency", None)
        or get_default_currency(event, plugin=plugin)
        or "PEN"
    )

    client = plugin._build_client(event)

    try:
        verification = client.verify_transaction_token(transaction_token)
    except NiubizClientError as exc:
        logger.exception("No se pudo verificar el token de transacción Niubiz")
        data = build_transaction_data(
            payload={"verification_error": str(exc)},
            source="success",
            status="verification_failed",
            message=str(exc),
        )
        handle_failed_payment(
            registration,
            amount=amount,
            currency=currency,
            transaction_id=None,
            status="verification_failed",
            summary=_("Niubiz no pudo verificar el token de transacción."),
            data=data,
            toggle_paid=True,
        )
        flash(_("No fue posible verificar tu tarjeta con Niubiz."), "error")
        return redirect(_registration_redirect_url(registration))

    verification_data = verification.get("data", {}) if isinstance(verification, dict) else {}
    verification_details = extract_callback_details(verification_data)
    verification_action = (verification_details.get("action_code") or "").strip()
    verification_status = (verification_details.get("status") or "").strip()

    if verification_action not in {"000", "0"} or verification_status.lower() not in {"verified", "authorized", "success"}:
        summary = _("Niubiz no pudo verificar la tarjeta tokenizada.")
        data = build_transaction_data(
            payload=verification_data,
            source="success",
            status=verification_status or None,
            action_code=verification_action or None,
            order_id=verification_details.get("purchase_number"),
            message="verification_rejected",
        )
        handle_failed_payment(
            registration,
            amount=amount,
            currency=currency,
            transaction_id=None,
            status=verification_status or "rejected",
            summary=summary,
            data=data,
            toggle_paid=True,
        )
        flash(summary, "error")
        return redirect(_registration_redirect_url(registration))

    token_id = _extract_token_id(verification_data)
    if not token_id:
        summary = _("Niubiz no devolvió un token de tarjeta válido.")
        data = build_transaction_data(
            payload=verification_data,
            source="success",
            status=verification_status or None,
            action_code=verification_action or None,
            order_id=verification_details.get("purchase_number"),
            message="token_missing",
        )
        handle_failed_payment(
            registration,
            amount=amount,
            currency=currency,
            transaction_id=None,
            status="token_missing",
            summary=summary,
            data=data,
            toggle_paid=True,
        )
        flash(summary, "error")
        return redirect(_registration_redirect_url(registration))

    purchase_number = verification_details.get("purchase_number") or f"{registration.event_id}-{registration.id}"

    antifraud_payload = build_antifraud_payload(
        registration,
        dict(mdd_payload),
        client_ip=client_ip,
    )

    try:
        push_response = client.authorize_payment(
            purchase_number=purchase_number,
            amount=amount,
            currency=currency,
            token_id=token_id,
            antifraud=antifraud_payload,
        )
    except NiubizClientError as exc:
        logger.exception("Error autorizando pago Niubiz")
        data = build_transaction_data(
            payload={"authorization_error": str(exc), "verification": verification_data},
            source="success",
            status="authorization_failed",
            action_code=None,
            order_id=purchase_number,
            message=str(exc),
        )
        handle_failed_payment(
            registration,
            amount=amount,
            currency=currency,
            transaction_id=None,
            status="authorization_failed",
            summary=_("No fue posible autorizar el pago con Niubiz."),
            data=data,
            toggle_paid=True,
        )
        flash(_("No fue posible completar tu pago con Niubiz. Inténtalo nuevamente."), "error")
        return redirect(_registration_redirect_url(registration))

    push_data = push_response.get("data", {}) if isinstance(push_response, dict) else {}
    push_action = push_response.get("action_code") or ""
    push_status = (push_data.get("status") or "").strip() or "PENDING"
    transaction_id = push_response.get("transaction_id") or push_data.get("transactionId")

    combined_payload = {
        "verification": verification_data,
        "push": push_data,
        "transactionToken": transaction_token,
        "token_id": token_id,
        "merchantDefinedData": mdd_payload,
        "antifraud": antifraud_payload,
    }

    data = build_transaction_data(
        payload=combined_payload,
        source="success",
        status=push_status,
        action_code=push_action,
        transaction_id=transaction_id,
        order_id=purchase_number,
        message="authorization",
    )

    if push_response.get("success"):
        summary = _("Pago completado correctamente a través de Niubiz.")
        handle_successful_payment(
            registration,
            amount=amount,
            currency=currency,
            transaction_id=transaction_id,
            status=push_status,
            summary=summary,
            data=data,
            toggle_paid=True,
        )
        flash(_("Tu pago con Niubiz se registró correctamente."), "success")
    else:
        normalized_status = (push_status or "").strip().lower()
        action_upper = (push_action or "").strip().upper()

        if normalized_status in {"pending", "review"} or action_upper in {"PENDING", "REVIEW"}:
            summary = _("Tu pago con Niubiz está en revisión.")
            handle_pending_payment(
                registration,
                amount=amount,
                currency=currency,
                transaction_id=transaction_id,
                status=push_status or "PENDING",
                summary=summary,
                data=data,
            )
            flash(summary, "warning")
        else:
            error_message = (
                push_data.get("errorMessage")
                or push_data.get("message")
                or _("Niubiz rechazó la transacción.")
            )
            if push_action:
                error_message = f"{error_message} (código {push_action})"
            handle_failed_payment(
                registration,
                amount=amount,
                currency=currency,
                transaction_id=transaction_id,
                status=push_status or "rejected",
                summary=error_message,
                data=data,
                toggle_paid=True,
            )
            flash(error_message, "error")

    return redirect(_registration_redirect_url(registration))


@blueprint.route(
    "/event/<int:event_id>/registrations/<int:reg_form_id>/payment/niubiz/<int:reg_id>/success",
    methods=["GET", "POST"],
)
def success(event_id: int, reg_form_id: int, reg_id: int):
    registration = _load_registration(
        registration_id=reg_id,
        reg_form_id=reg_form_id,
        event_id=event_id,
    )
    if not registration:
        abort(404)

    payload: Dict[str, Any] = {}
    if request.method == "POST":
        json_payload = request.get_json(silent=True)
        if isinstance(json_payload, dict):
            payload.update(json_payload)
        payload.update(request.form.to_dict())
    payload.update(request.args.to_dict())

    plugin = _get_plugin()
    event = registration.event

    merchant_defined_raw = get_merchant_defined_data(event, plugin=plugin)
    try:
        extra_mdd = json.loads(merchant_defined_raw) if merchant_defined_raw else {}
    except ValueError:
        extra_mdd = {}

    try:
        mdd_payload = collect_mdd_data(
            registration,
            extra=extra_mdd,
            require_all=is_mdd_required(event, plugin=plugin),
        )
    except BadRequest as exc:
        flash(str(exc), "error")
        return redirect(_registration_redirect_url(registration))

    transaction_token = (
        payload.get("transactionToken")
        or payload.get("transaction_token")
        or payload.get("TRANSACTIONTOKEN")
    )
    if transaction_token:
        return _complete_push_payment(
            registration,
            event,
            payload,
            transaction_token,
            mdd_payload,
            plugin,
            client_ip=request.headers.get("X-Forwarded-For", request.remote_addr),
        )

    amount = parse_amount(getattr(registration, "price", None), None)
    currency = getattr(registration, "currency", None)

    transaction_id = (
        payload.get("transactionId")
        or payload.get("transaction_id")
        or payload.get("transactionID")
    )
    status_value = payload.get("status") or payload.get("STATUS") or "AUTHORIZED"
    action_code = payload.get("actionCode") or payload.get("ACTION_CODE")
    purchase_number = payload.get("purchaseNumber") or f"{event_id}-{reg_id}"

    data = build_transaction_data(
        payload=payload,
        source="success",
        status=status_value,
        action_code=action_code,
        transaction_id=transaction_id,
        order_id=purchase_number,
    )

    handle_successful_payment(
        registration,
        amount=amount,
        currency=currency,
        transaction_id=transaction_id,
        status=status_value,
        summary=_("Pago completado correctamente a través de Niubiz."),
        data=data,
        toggle_paid=True,
    )

    flash(_("Tu pago con Niubiz se registró correctamente."), "success")
    return redirect(_registration_redirect_url(registration))


@blueprint.get(
    "/event/<int:event_id>/registrations/<int:reg_form_id>/payment/niubiz/<int:reg_id>/cancel"
)
def cancel(event_id: int, reg_form_id: int, reg_id: int):
    registration = _load_registration(
        registration_id=reg_id,
        reg_form_id=reg_form_id,
        event_id=event_id,
    )
    if not registration:
        abort(404)

    amount = parse_amount(getattr(registration, "price", None), None)
    currency = getattr(registration, "currency", None)
    payload = request.args.to_dict()

    transaction_id = (
        payload.get("transactionId")
        or payload.get("transaction_id")
        or payload.get("transactionID")
    )
    status_value = payload.get("status") or payload.get("STATUS") or "CANCELLED"
    action_code = payload.get("actionCode") or payload.get("ACTION_CODE")
    purchase_number = payload.get("purchaseNumber") or f"{event_id}-{reg_id}"

    data = build_transaction_data(
        payload=payload,
        source="cancel",
        status=status_value,
        action_code=action_code,
        transaction_id=transaction_id,
        order_id=purchase_number,
    )

    handle_failed_payment(
        registration,
        amount=amount,
        currency=currency,
        transaction_id=transaction_id,
        status=status_value,
        summary=_("El pago fue cancelado desde Niubiz."),
        data=data,
        cancelled=True,
        toggle_paid=True,
    )

    flash(_("El pago fue cancelado. Puedes intentarlo nuevamente cuando desees."), "warning")
    return redirect(_registration_redirect_url(registration))


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

