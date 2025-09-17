import hashlib
import hmac
import ipaddress
import logging
from typing import TYPE_CHECKING

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import BadRequest, Forbidden

from indico.web.rh import RH

if TYPE_CHECKING:
    from indico_payment_niubiz.plugin import NiubizPaymentPlugin

logger = logging.getLogger(__name__)


def _get_plugin() -> "NiubizPaymentPlugin":
    from indico_payment_niubiz.plugin import NiubizPaymentPlugin
    return NiubizPaymentPlugin.instance


# ------------------------------------------------------------------------------
# Resource handler para los callbacks (webhooks) de Niubiz
# ------------------------------------------------------------------------------
class RHNiubizCallback(RH):
    """Maneja los callbacks/webhooks enviados por Niubiz a Indico."""

    def _check_access(self):
        """No se requiere autenticación de usuario para los callbacks."""
        return True

    def _process(self):
        # Parsear payload JSON
        payload = request.get_json(force=True, silent=True)
        if not payload:
            raise BadRequest("No se recibió un JSON válido en el callback de Niubiz.")

        plugin = _get_plugin()
        event_id = request.view_args.get("event_id")
        event = self._locate_event(event_id)

        # ----------------------------------------------------------------------
        # Validaciones de seguridad del callback
        # ----------------------------------------------------------------------
        self._validate_authorization(event, plugin)
        self._validate_signature(event, plugin, payload)
        self._validate_ip(event, plugin)

        # ----------------------------------------------------------------------
        # Extraer información clave del payload
        # ----------------------------------------------------------------------
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
            purchase_number, transaction_id, status
        )
        logger.debug("Payload completo del callback: %r", payload)

        # 🔧 TODO: Procesar el estado real de la transacción y actualizar en Indico
        #  - Authorized -> pago exitoso
        #  - Not Authorized / Rejected -> fallido
        #  - Voided -> cancelado
        #  - Pending (ej. Yape, PagoEfectivo) -> espera

        return jsonify({"received": True})

    # ----------------------------------------------------------------------
    # Seguridad: Authorization header
    # ----------------------------------------------------------------------
    def _validate_authorization(self, event, plugin):
        expected = plugin._get_setting(event, "callback_authorization_token")
        if expected:
            auth_header = request.headers.get("Authorization")
            if auth_header != expected:
                logger.warning("Callback rechazado: token Authorization inválido")
                raise Forbidden("Invalid Authorization token")

    # ----------------------------------------------------------------------
    # Seguridad: Validación HMAC NBZ-Signature
    # ----------------------------------------------------------------------
    def _validate_signature(self, event, plugin, payload):
        secret = plugin._get_setting(event, "callback_hmac_secret")
        if secret:
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

    # ----------------------------------------------------------------------
    # Seguridad: Validación de IP (whitelist)
    # ----------------------------------------------------------------------
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


# ------------------------------------------------------------------------------
# Registro de ruta para recibir callbacks desde Niubiz
# ------------------------------------------------------------------------------
blueprint = Blueprint("payment_niubiz", __name__)
blueprint.add_url_rule(
    "/event/<int:event_id>/registrations/<int:reg_form_id>/payment/response/niubiz/notify",
    "callback",
    RHNiubizCallback,
    methods=("POST",),
)
