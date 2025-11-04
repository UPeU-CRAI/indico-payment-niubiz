"""Flask views and webhook handlers for the Niubiz integration."""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, Optional, Tuple

from flask import Blueprint, jsonify, render_template, request
from werkzeug.exceptions import Forbidden

from indico_payment_niubiz import _
from indico_payment_niubiz.indico_integration import (
    build_transaction_data,
    handle_failed_payment,
    handle_pending_payment,
    handle_refund,
    handle_successful_payment,
    parse_amount,
)
from indico_payment_niubiz.schema import StatusMapping
from indico_payment_niubiz.security import (
    DEFAULT_CALLBACK_IPS,
    ip_in_whitelist,
    parse_ip_list,
    validate_nbz_signature,
)
from indico_payment_niubiz.settings import get_scoped_setting
from indico_payment_niubiz.utils import (
    extract_callback_details,
    get_checkout_script_url,
    map_niubiz_status,
)

try:  # pragma: no cover - executed when Indico is available
    from indico.modules.events.registration.models.registrations import Registration
except Exception:  # pragma: no cover - fallback for the standalone test suite
    class Registration:  # type: ignore[override]
        pass


logger = logging.getLogger(__name__)

blueprint = Blueprint("payment_niubiz", __name__, url_prefix="/niubiz")


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

    try:  # pragma: no cover - database interaction not covered in tests
        return Registration.query.filter_by(
            id=registration_id,
            event_id=event_id,
            registration_form_id=reg_form_id,
        ).first()
    except Exception:  # pragma: no cover - defensive logging
        logger.exception("Unable to load registration %s for Niubiz callback", registration_id)
        return None


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


def _handle_pending(
    registration,
    *,
    summary: str,
    amount,
    currency: str,
    transaction_id: Optional[str],
    status_value: Optional[str],
    data: Dict[str, Any],
) -> None:
    handle_pending_payment(
        registration,
        amount=amount,
        currency=currency,
        transaction_id=transaction_id,
        status=status_value,
        summary=summary,
        data=data,
    )


@blueprint.get("/checkout")
def render_checkout() -> str:
    """Render the embedded Checkout.js flow using the dedicated template."""

    amount = request.args.get("amount", "0.00")
    currency = request.args.get("currency", "PEN")
    purchase_number = request.args.get("purchase_number", "N/A")
    description = request.args.get("description", _("Pago de inscripción"))
    endpoint = request.args.get("endpoint", "sandbox")
    checkout_js = get_checkout_script_url(endpoint)

    return render_template(
        "niubiz/checkout.html",
        checkout_js_url=checkout_js,
        endpoint=endpoint,
        amount=amount,
        currency=currency,
        purchase_number=purchase_number,
        description=description,
    )


@blueprint.get("/result")
def render_result() -> str:
    """Render the payment result page."""

    status = request.args.get("status", "pending")
    message = request.args.get("message", "")
    return render_template("niubiz/result.html", status=status, message=message)


@blueprint.post("/webhook")
def webhook_handler():  # pragma: no cover - integration heavy
    plugin = _get_plugin()
    body = request.get_data() or b""
    payload = request.json or {}

    purchase_details = extract_callback_details(payload)
    event_id, registration_id = _parse_purchase_number(purchase_details.purchase_number)

    if event_id is None or registration_id is None:
        logger.warning("Niubiz webhook without purchase number")
        return jsonify({"processed": False}), 400

    registration = _load_registration(
        registration_id=registration_id,
        reg_form_id=request.view_args.get("reg_form_id", 0),
        event_id=event_id,
    )
    if registration is None:
        logger.warning("Niubiz webhook for unknown registration %s", registration_id)
        return jsonify({"processed": False}), 404

    _validate_ip(registration.event, plugin)  # type: ignore[attr-defined]
    _validate_authorization(registration.event, plugin)  # type: ignore[attr-defined]
    _validate_signature(registration.event, plugin, body)  # type: ignore[attr-defined]

    amount = parse_amount(payload.get("amount"), parse_amount(getattr(registration, "price", None), None))
    currency = payload.get("currency") or getattr(registration, "currency", "PEN")

    mapping = map_niubiz_status(
        status=purchase_details.status,
        action_code=purchase_details.action_code,
        status_order=purchase_details.status_order,
        payment_method=purchase_details.payment_method,
        action_description=purchase_details.action_description,
    )

    transaction_data = build_transaction_data(
        payload=payload,
        status=purchase_details.status,
        action_code=purchase_details.action_code,
        transaction_id=purchase_details.transaction_id,
        order_id=purchase_details.purchase_number,
        message=purchase_details.action_description,
    )
    transaction_data.update(_build_transaction_extra(purchase_details.to_dict()))

    summary_config = purchase_details.status or mapping.status.name  # type: ignore[union-attr]

    if mapping.status.name == "successful":  # type: ignore[union-attr]
        _handle_success(
            registration,
            summary=summary_config,
            amount=amount,
            currency=currency,
            transaction_id=purchase_details.transaction_id,
            status_value=purchase_details.status,
            data=transaction_data,
            mapping=mapping,
            toggle_paid=True,
        )
    elif mapping.status.name == "cancelled":  # type: ignore[union-attr]
        _handle_cancelled(
            registration,
            summary=summary_config,
            amount=amount,
            currency=currency,
            transaction_id=purchase_details.transaction_id,
            status_value=purchase_details.status,
            data=transaction_data,
            is_refund=mapping.status.name == "cancelled",
            toggle_paid=False,
        )
    elif mapping.status.name == "pending":  # type: ignore[union-attr]
        _handle_pending(
            registration,
            summary=summary_config,
            amount=amount,
            currency=currency,
            transaction_id=purchase_details.transaction_id,
            status_value=purchase_details.status,
            data=transaction_data,
        )
    else:
        handle_failed_payment(
            registration,
            amount=amount,
            currency=currency,
            transaction_id=purchase_details.transaction_id,
            status=purchase_details.status,
            summary=summary_config,
            data=transaction_data,
        )

    return jsonify({"processed": True})
