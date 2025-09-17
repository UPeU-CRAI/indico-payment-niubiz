import hashlib
import hmac
import ipaddress
import logging
from typing import TYPE_CHECKING

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import BadRequest, Forbidden

from indico.web.rh import RH

if TYPE_CHECKING:  # pragma: no cover - only for type checkers
    from indico_payment_niubiz.plugin import NiubizPaymentPlugin

logger = logging.getLogger(__name__)


def _get_plugin() -> "NiubizPaymentPlugin":
    from indico_payment_niubiz.plugin import NiubizPaymentPlugin

    return NiubizPaymentPlugin.instance


class RHNiubizCallback(RH):
    """Maneja los callbacks/webhooks enviados por Niubiz."""

    def _check_access(self):
        """Los callbacks no requieren autenticación de usuario, solo validación interna."""
        return True

    def _process(self):
        payload = request.get_json(force=True, silent=True)
        if not payload:
            raise BadRequest("No se recibió un JSON válido en el callback de Niubiz.")

        plugin = _get_plugin()
        event_id = request.view_args.get("event_id")
        event = self._locate_event(event_id)

        # -----------------------------
        # Validar seguridad del callback
        # -----------------------------
        self._validate_authorization(event, plugin)
        self._validate_signature(event, plugin, payload)
        self._validate_ip(event, plugin)

        # -----------------------------
        # Procesar payload
        # -----------------------------
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

        logger.info(
            "Callback Niubiz recibido: purchase=%s, transaction=%s, status=%s",
            purchase_number,
            transaction_id,
            status,
        )
        logger.debug("Payload completo: %s", payload)

        # TODO: mapear status/actionCode a estados de Indico
        # - Authorized -> success
        # - Not Authorized / Reject -> failed
        # - Voided -> cancelled
        # - Pending (PagoEfectivo CIP o Yape en espera) -> pending

        # Por ahora respondemos 200 para confirmar recepción
        return jsonify({"received": True})

    # -----------------------------
    # Validaciones de seguridad
    # -----------------------------
    def _validate_authorization(self, event, plugin):
        expected = plugin._get_setting(event, "callback_authorization_token")
        if expected:
            auth_header = request.headers.get("Authorization")
            if auth_header != expected:
                logger.warning("Callback rechazado por token Authorization inválido")
                raise Forbidden("Invalid Authorization token")

    def _validate_signature(self, event, plugin, payload):
        secret = plugin._get_setting(event, "callback_hmac_secret")
        if secret:
            received_sig = request.headers.get("NBZ-Signature")
            if not received_sig:
                raise Forbidden("Missing NBZ-Signature header")
            computed_sig = hmac.new(
                secret.encode("utf-8"),
                msg=request.data,
                digestmod=hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(computed_sig, received_sig):
                logger.warning("Firma NBZ-Signature inválida en callback")
                raise Forbidden("Invalid signature")

    def _validate_ip(self, event, plugin):
        whitelist = plugin._get_setting(event, "callback_ip_whitelist")
        if whitelist:
            ips = [ip.strip() for ip in whitelist.splitlines() if ip.strip()]
            remote_ip = ipaddress.ip_address(request.remote_addr)
            for allowed in ips:
                if remote_ip in ipaddress.ip_network(allowed, strict=False):
                    return
            logger.warning("Callback desde IP no autorizada: %s", remote_ip)
            raise Forbidden("IP not allowed")


blueprint = Blueprint("payment_niubiz", __name__)
blueprint.add_url_rule(
    "/event/<int:event_id>/registrations/<int:reg_form_id>/payment/response/niubiz/notify",
    "callback",
    RHNiubizCallback,
    methods=("POST",),
)
