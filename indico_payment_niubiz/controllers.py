"""Lógica de orquestación de pagos Niubiz por canal."""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Dict, Optional

from flask import flash, redirect
from werkzeug.exceptions import BadRequest

from indico_payment_niubiz import _
from indico_payment_niubiz.client import NiubizClientError
from indico_payment_niubiz.indico_integration import (
    build_transaction_data,
    handle_failed_payment,
    handle_pending_payment,
    handle_successful_payment,
    parse_amount,
)
from indico_payment_niubiz.settings import get_default_currency
from indico_payment_niubiz.util import extract_callback_details


logger = logging.getLogger(__name__)


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


def process_card_transaction(
    *,
    registration,
    event,
    plugin,
    payload: Dict[str, Any],
    transaction_token: str,
    antifraud_payload: Dict[str, Any],
    mdd_payload: Dict[str, str],
    redirect_url: str,
    client_ip: Optional[str] = None,
) -> Any:
    """Ejecuta el flujo push payment para tarjetas Niubiz."""

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
        return redirect(redirect_url)

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
        return redirect(redirect_url)

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
        return redirect(redirect_url)

    purchase_number = verification_details.get("purchase_number") or f"{registration.event_id}-{registration.id}"

    antifraud_payload = dict(antifraud_payload or {})
    if "deviceFingerprintId" not in antifraud_payload:
        logger.error("deviceFingerprintId ausente en antifraud para purchase %s", purchase_number)
        raise BadRequest("Falta el deviceFingerprintId requerido para antifraude.")

    if client_ip and "clientIp" not in antifraud_payload:
        antifraud_payload["clientIp"] = client_ip

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
        return redirect(redirect_url)

    push_data = push_response.get("data", {}) if isinstance(push_response, dict) else {}
    push_action = push_response.get("action_code") or ""
    push_status = (push_data.get("status") or "").strip() or "PENDING"
    transaction_id = push_response.get("transaction_id") or push_data.get("transactionId")

    combined_payload = {
        "verification": verification_data,
        "push": push_data,
        "transactionToken": transaction_token,
        "token_id": token_id,
        "merchantDefinedData": dict(mdd_payload or {}),
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

    return redirect(redirect_url)


def process_yape_transaction(**kwargs) -> Any:  # pragma: no cover - placeholder
    """Placeholder para el flujo Yape (pendiente de implementación)."""

    raise NotImplementedError("El canal de pago Yape aún no está implementado.")


def process_qr_transaction(**kwargs) -> Any:  # pragma: no cover - placeholder
    """Placeholder para el flujo QR (pendiente de implementación)."""

    raise NotImplementedError("El canal de pago QR aún no está implementado.")


def process_cash_transaction(**kwargs) -> Any:  # pragma: no cover - placeholder
    """Placeholder para PagoEfectivo / efectivo."""

    raise NotImplementedError("El canal de pago PagoEfectivo aún no está implementado.")


def perform_transaction(
    *,
    payment_channel: str,
    registration,
    event,
    plugin,
    payload: Dict[str, Any],
    transaction_token: Optional[str],
    antifraud_payload: Dict[str, Any],
    mdd_payload: Dict[str, str],
    redirect_url: str,
    client_ip: Optional[str] = None,
) -> Any:
    """Despacha el procesamiento según el canal de pago seleccionado."""

    normalized_channel = (payment_channel or "").strip().lower()
    handlers = {
        "card": process_card_transaction,
        "card_token": process_card_transaction,
        "token": process_card_transaction,
        "yape": process_yape_transaction,
        "qr": process_qr_transaction,
        "pagoefectivo": process_cash_transaction,
        "efectivo": process_cash_transaction,
    }

    handler = handlers.get(normalized_channel)
    if handler is None:
        logger.error("Canal de pago Niubiz no soportado: %s", payment_channel)
        raise BadRequest("Canal de pago Niubiz no soportado.")

    if handler is process_card_transaction and not transaction_token:
        logger.error("transactionToken ausente para canal tarjeta")
        raise BadRequest("Se requiere transactionToken para completar el pago.")

    return handler(
        registration=registration,
        event=event,
        plugin=plugin,
        payload=payload,
        transaction_token=transaction_token,
        antifraud_payload=antifraud_payload,
        mdd_payload=mdd_payload,
        redirect_url=redirect_url,
        client_ip=client_ip,
    )
