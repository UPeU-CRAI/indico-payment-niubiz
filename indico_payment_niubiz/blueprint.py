import hashlib
import hmac
import ipaddress
import logging
from decimal import Decimal
from typing import TYPE_CHECKING

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import BadRequest, Forbidden

from indico.web.rh import RH
from indico.modules.events.registration.models.registrations import Registration

from indico_payment_niubiz.indico_integration import (
    build_transaction_data,
    handle_successful_payment,
    handle_failed_payment,
    parse_amount,
)
from indico.modules.logs.models.entries import LogKind

if TYPE_CHECKING:
    from indico_payment_niubiz.plugin import NiubizPaymentPlugin

logger = logging.getLogger(__name__)


def _get_plugin() -> "NiubizPaymentPlugin":
    from indico_payment_niubiz.plugin import NiubizPaymentPlugin
    return NiubizPaymentPlugin.instance


class RHNiubizCallback(RH):
    """Maneja los callbacks (webhooks) enviados por Niubiz a Indico."""

    def _check_access(self):
        # No requiere autenticación del usuario
        return True

    def _process(self):
        payload = request.get_json(force=True, silent=True)
        if not payload:
            raise BadRequest("No se recibió un JSON válido.")

        plugin = _get_plugin()
        event_id = request.view_args.get("event_id")
        event = self._locate_event(event_id)

        # Seguridad
        self._validate_authorization(event, plugin)
        self._validate_signature(event, plugin)
        self._validate_ip(event, plugin)

        # Extraer datos del payload
        purchase_number = (
            payload.get("order", {}).get("purchaseNumber")
            or payload.get("purchaseNumber")
        )
        transaction_id = (
            payload.get("order", {}).get("transactionId")
            or payload.get("transactionId")
            or payload.get("operationNumber")
        )
        status = (
            payload.get("dataMap", {}).get("STATUS")
            or payload.get("STATUS")
            or payload.get("status")
        )
        amount = (
            payload.get("order", {}).get("amount")
            or payload.get("amount")
        )
        currency = (
            payload.get("order", {}).get("currency")
            or payload.get("currency")
            or "PEN"
        )
        action_code = (
            payload.get("order", {}).get("actionCode")
            or payload.get("actionCode")
        )

        logger.info(
            "Callback Niubiz: purchase_number=%s, txn_id=%s, status=%s, action_code=%s",
            purchase_number, transaction_id, status, action_code,
        )
        logger.debug("Payload completo recibido de Niubiz: %r", payload)

        # Buscar registro
        registration = self._get_registration_from_purchase_number(purchase_number)
        if not registration or registration.event_id != event.id:
            logger.warning("Registro no encontrado o evento incorrecto: %s", purchase_number)
            raise BadRequest("Registro no válido.")

        # Preparar datos comunes
        amount_decimal = parse_amount(amount, fallback=Decimal(registration.price or 0))
        transaction_data = build_transaction_data(
            payload=payload,
            source="callback",
            status=status,
            transaction_id=transaction_id,
            order_id=purchase_number,
            action_code=action_code,
        )

        # Procesar según estado
        if status and status.upper() == "AUTHORIZED":
            summary = "Pago confirmado exitosamente por Niubiz"
            handle_successful_payment(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status,
                action_code=action_code,
                summary=summary,
                data=transaction_data,
            )
        elif status and status.upper() in {"REJECTED", "NOT AUTHORIZED"}:
            summary = "Pago rechazado por Niubiz"
            handle_failed_payment(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status,
                action_code=action_code,
                summary=summary,
                data=transaction_data,
            )
        elif status and status.upper() in {"VOIDED", "CANCELLED"}:
            summary = "Pago anulado por Niubiz"
            handle_failed_payment(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status,
                action_code=action_code,
                summary=summary,
                data=transaction_data,
                cancelled=True,
            )
        elif status and status.upper() == "PENDING":
            logger.info("Pago en estado pendiente. Se omite actualización.")
        else:
            logger.warning("Estado desconocido de pago recibido: %s", status)

        return jsonify({"received": True})

    def _get_registration_from_purchase_number(self, purchase_number: str) -> Registration | None:
        if not purchase_number or "-" not in purchase_number:
            return None
        try:
            event_id_str, reg_id_str = purchase_number.split("-", 1)
            return Registration.query.filter_by(id=int(reg_id_str)).first()
        except Exception:
            logger.exception("No se pudo parsear purchaseNumber: %s", purchase_number)
            return None

    def _validate_authorization(self, event, plugin):
        expected = plugin._get_setting(event, "callback_authorization_token")
        if expected:
            auth_header = request.headers.get("Authorization")
            if auth_header != expected:
                logger.warning("Callback rechazado: token Authorization inválido")
                raise Forbidden("Invalid Authorization token")

    def _validate_signature(self, event, plugin):
        secret = plugin._get_setting(event, "callback_hmac_secret")
        if not secret:
            return

        received_sig = request.headers.get("NBZ-Signature")
        if not received_sig:
            logger.warning("Callback rechazado: NBZ-Signature faltante")
            raise Forbidden("Missing NBZ-Signature header")

        computed_sig = hmac.new(
            secret.encode("utf-8"),
            msg=request.data,
            digestmod=hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(computed_sig, received_sig):
            logger.warning("Callback rechazado: firma NBZ-Signature inválida")
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
                logger.warning("Entrada inválida en whitelist de IPs: %s", allowed)

        logger.warning("Callback desde IP no autorizada: %s", remote_ip)
        raise Forbidden("IP not allowed")


# ----------------------------------------------------------------------
# Registro del blueprint
# ----------------------------------------------------------------------
blueprint = Blueprint("payment_niubiz", __name__)
blueprint.add_url_rule(
    "/event/<int:event_id>/registrations/<int:reg_form_id>/payment/response/niubiz/notify",
    "callback",
    RHNiubizCallback,
    methods=("POST",),
)
