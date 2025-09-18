from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Dict

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import BadRequest, Forbidden

from indico.modules.events.payment.models.transactions import TransactionAction
from indico.modules.events.registration.models.registrations import Registration
from indico.web.rh import RH

from indico_payment_niubiz.indico_integration import (
    build_transaction_data,
    handle_failed_payment,
    handle_pending_payment,
    handle_refund,
    handle_successful_payment,
    parse_amount,
)
from indico_payment_niubiz.status_mapping import DEFAULT_STATUS, NIUBIZ_STATUS_MAP

if TYPE_CHECKING:
    from indico_payment_niubiz.plugin import NiubizPaymentPlugin

logger = logging.getLogger(__name__)


def _get_plugin() -> "NiubizPaymentPlugin":
    from indico_payment_niubiz.plugin import NiubizPaymentPlugin

    return NiubizPaymentPlugin.instance


class RHNiubizCallback(RH):
    """Procesa los callbacks de Niubiz y delega la lógica centralizada."""

    def _check_access(self):
        return True

    def _process(self):
        payload = request.get_json(force=True, silent=True)
        if not isinstance(payload, dict):
            logger.warning("Callback Niubiz recibido sin JSON válido")
            raise BadRequest("No se recibió un JSON válido.")

        plugin = _get_plugin()
        event_id = request.view_args.get("event_id")
        event = self._locate_event(event_id)

        self._validate_authorization(event, plugin)
        self._validate_signature(event, plugin)
        self._validate_ip(event, plugin)

        purchase_number = self._extract_value(payload, "purchaseNumber")
        if not purchase_number:
            return jsonify({"received": False, "error": "missing_purchase_number"})

        parsed_event_id, registration_id = self._parse_purchase_number(purchase_number)
        if not registration_id:
            return jsonify({"received": False, "error": "invalid_purchase_number"})
        if parsed_event_id and parsed_event_id != event.id:
            return jsonify({"received": False, "error": "event_mismatch"})

        registration = self._get_registration_from_id(registration_id)
        if not registration or registration.event_id != event.id:
            return jsonify({"received": False, "error": "registration_not_found"})

        transaction_id = self._extract_value(payload, "transactionId", "operationNumber")
        status_value = self._extract_value(payload, "STATUS", "status")
        action_code = self._extract_value(payload, "actionCode", "ACTION_CODE")
        amount_value = self._extract_value(payload, "amount")
        currency = (
            self._extract_value(payload, "currency")
            or getattr(registration, "currency", None)
            or "PEN"
        )

        amount_decimal = parse_amount(
            amount_value,
            fallback=parse_amount(getattr(registration, "price", None), Decimal("0")),
        )

        transaction_data = build_transaction_data(
            payload=payload,
            source="callback",
            status=status_value,
            action_code=action_code,
            transaction_id=transaction_id,
            order_id=purchase_number,
        )
        transaction_data.update(self._collect_additional_details(payload, currency, amount_decimal))

        status_key = (status_value or "").strip().upper()
        config = NIUBIZ_STATUS_MAP.get(status_key, DEFAULT_STATUS)
        action = config["action"]
        summary = config["summary"]
        toggle_paid = config.get("toggle_paid", False)

        logger.info(
            "Callback Niubiz recibido: purchase=%s, transaction_id=%s, status=%s",  # noqa: G004
            purchase_number,
            transaction_id,
            status_value,
        )
        logger.debug("Payload completo recibido: %r", payload)

        if status_key == "REFUNDED":
            handle_refund(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status_value,
                summary=summary,
                data=transaction_data,
                success=True,
            )
        elif action == TransactionAction.complete:
            handle_successful_payment(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status_value,
                summary=summary,
                data=transaction_data,
                toggle_paid=toggle_paid,
            )
        elif action == TransactionAction.pending:
            handle_pending_payment(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status_value,
                summary=summary,
                data=transaction_data,
            )
        elif action in {TransactionAction.reject, TransactionAction.cancel}:
            handle_failed_payment(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status_value,
                summary=summary,
                data=transaction_data,
                cancelled=(action == TransactionAction.cancel),
                toggle_paid=toggle_paid,
            )
        else:
            handle_failed_payment(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status_value,
                summary="Estado no reconocido recibido desde Niubiz",
                data=transaction_data,
                cancelled=False,
            )

        return jsonify({"received": True})

    # ------------------------------------------------------------------
    # Utilidades internas
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_value(payload: Dict[str, Any], *keys: str):
        order = payload.get("order") if isinstance(payload.get("order"), dict) else {}
        data_map = payload.get("dataMap") if isinstance(payload.get("dataMap"), dict) else {}
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        for key in keys:
            if key in order and order[key] is not None:
                return order[key]
            if key in data_map and data_map[key] is not None:
                return data_map[key]
            if key in data and data[key] is not None:
                return data[key]
            if key in payload and payload[key] is not None:
                return payload[key]
        return None

    @staticmethod
    def _parse_purchase_number(purchase_number: str) -> tuple[int | None, int | None]:
        if not purchase_number or "-" not in purchase_number:
            return None, None
        try:
            event_id_str, reg_id_str = purchase_number.split("-", 1)
            return int(event_id_str), int(reg_id_str)
        except (TypeError, ValueError):
            return None, None

    @staticmethod
    def _get_registration_from_id(registration_id: int | None) -> Registration | None:
        if registration_id is None:
            return None
        try:
            return Registration.query.filter_by(id=registration_id).first()
        except Exception:
            logger.exception("Error consultando inscripción id=%s", registration_id)
            return None

    @staticmethod
    def _collect_additional_details(payload: Dict[str, Any], currency: str, amount: Decimal | None) -> Dict[str, Any]:
        details: Dict[str, Any] = {
            "currency": currency,
            "amount": float(amount) if amount is not None else None,
            "status_order": RHNiubizCallback._extract_value(payload, "statusOrder"),
            "operation_number": RHNiubizCallback._extract_value(payload, "operationNumber"),
            "action_description": RHNiubizCallback._extract_value(payload, "actionDescription"),
            "channel": RHNiubizCallback._extract_value(payload, "channel"),
            "payment_method": RHNiubizCallback._extract_value(payload, "paymentMethod"),
            "cip": RHNiubizCallback._extract_value(payload, "cip"),
        }
        return {k: v for k, v in details.items() if v is not None}

    # ------------------------------------------------------------------
    # Validaciones de seguridad
    # ------------------------------------------------------------------
    def _validate_authorization(self, event, plugin):
        expected = plugin._get_setting(event, "callback_authorization_token")
        if expected and request.headers.get("Authorization") != expected:
            logger.warning("Callback rechazado: token Authorization inválido")
            raise Forbidden("Invalid Authorization token")

    def _validate_signature(self, event, plugin):
        secret = plugin._get_setting(event, "callback_hmac_secret")
        if not secret:
            return
        received_sig = request.headers.get("NBZ-Signature")
        if not received_sig:
            raise Forbidden("Missing NBZ-Signature header")
        computed_sig = hmac.new(
            secret.encode("utf-8"),
            msg=request.data,
            digestmod=hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(computed_sig, received_sig):
            logger.warning("Callback rechazado: firma inválida")
            raise Forbidden("Invalid signature")

    def _validate_ip(self, event, plugin):
        whitelist = plugin._get_setting(event, "callback_ip_whitelist")
        if not whitelist:
            return
        remote_ip = ipaddress.ip_address(request.remote_addr)
        ips = [ip.strip() for ip in whitelist.splitlines() if ip.strip()]
        for allowed in ips:
            try:
                if remote_ip in ipaddress.ip_network(allowed, strict=False):
                    return
            except ValueError:
                logger.warning("Entrada inválida en whitelist: %s", allowed)
        logger.warning("Callback desde IP no autorizada: %s", remote_ip)
        raise Forbidden("IP not allowed")


blueprint = Blueprint("payment_niubiz", __name__)
blueprint.add_url_rule(
    "/event/<int:event_id>/registrations/<int:reg_form_id>/payment/response/niubiz/notify",
    "callback",
    RHNiubizCallback,
    methods=("POST",),
)
