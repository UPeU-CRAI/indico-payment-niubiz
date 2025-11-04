"""Niubiz payment plugin configuration and integration with Indico.

Este módulo define:
- Configuración global y por evento para la pasarela Niubiz.
- Métodos habilitados: tarjeta, Yape, PagoEfectivo, QR y tokenización.
- Integración con el flujo de pagos de Indico, incluyendo reembolsos.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, Optional

from werkzeug.exceptions import BadRequest

from indico.core.plugins import IndicoPlugin
from indico.modules.events.payment import PaymentPluginMixin
from indico.web.flask.util import url_for

from indico_payment_niubiz import _
from indico_payment_niubiz.client import NiubizClient
from indico_payment_niubiz.forms import EventSettingsForm, PluginSettingsForm
from indico_payment_niubiz.indico_integration import (
    build_transaction_data,
    handle_refund,
    parse_amount,
)
from indico_payment_niubiz.models import NiubizStoredToken
from indico_payment_niubiz.settings import (
    get_credentials_for_event,
    get_endpoint_for_event,
    get_merchant_id_for_event,
    get_scoped_setting,
)
from indico_payment_niubiz.views import blueprint

logger = logging.getLogger(__name__)


# --------------------- PLUGIN PRINCIPAL ---------------------
class NiubizPaymentPlugin(PaymentPluginMixin, IndicoPlugin):
    """Plugin de integración de Niubiz en Indico."""

    configurable = True
    settings_form = PluginSettingsForm
    event_settings_form = EventSettingsForm

    default_settings = {
        "method_name": "Niubiz",
        "merchant_id": "",
        "access_key": "",
        "secret_key": "",
        "merchant_logo_url": "",
        "button_color": "",
        "merchant_defined_data": "",
        "endpoint": "sandbox",
        "enable_card": True,
        "enable_yape": False,
        "enable_pagoefectivo": False,
        "enable_qr": False,
        "enable_tokenization": False,
        "callback_authorization_token": "",
        "callback_hmac_secret": "",
        "callback_ip_whitelist": "",
    }

    default_event_settings = {
        "enabled": False,
        "method_name": None,
        "merchant_id": None,
        "access_key": None,
        "secret_key": None,
        "merchant_logo_url": None,
        "button_color": None,
        "merchant_defined_data": None,
        "endpoint": None,
        "enable_card": None,
        "enable_yape": None,
        "enable_pagoefectivo": None,
        "enable_qr": None,
        "enable_tokenization": None,
        "callback_authorization_token": None,
        "callback_hmac_secret": None,
        "callback_ip_whitelist": None,
    }

    # ------------------ Registro ------------------
    def get_blueprints(self):
        return blueprint

    # ------------------ Helpers de settings ------------------
    def _get_bool(self, event, name: str) -> bool:
        """Obtiene un booleano considerando overrides por evento."""
        override = self.event_settings.get(event, name)
        if isinstance(override, str) and override in {"0", "1"}:
            return override == "1"
        if override not in (None, ""):
            return bool(override)

        value = get_scoped_setting(event, name, plugin=self)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off"}:
                return False
        return bool(value)

    def _get_setting(self, event, name: str) -> Optional[str]:
        """Obtiene un setting de evento o global."""
        return get_scoped_setting(event, name, plugin=self)

    # ------------------ Cliente ------------------
    def _build_client(self, event) -> NiubizClient:
        merchant_id = get_merchant_id_for_event(event, plugin=self)
        access_key, secret_key = get_credentials_for_event(event, plugin=self)
        endpoint = get_endpoint_for_event(event, plugin=self)
        return NiubizClient(
            merchant_id=merchant_id,
            access_key=access_key,
            secret_key=secret_key,
            endpoint=endpoint,
        )

    # ------------------ Métodos de pago ------------------
    def _collect_methods(self, event) -> Dict[str, bool]:
        return {
            "card": self._get_bool(event, "enable_card"),
            "yape": self._get_bool(event, "enable_yape"),
            "pagoefectivo": self._get_bool(event, "enable_pagoefectivo"),
            "qr": self._get_bool(event, "enable_qr"),
        }

    # ------------------ Checkout ------------------
    def adjust_payment_form_data(self, data):
        """Enriquece el contexto enviado al template de checkout."""
        registration = data["registration"]
        event = data["event"]
        amount = registration.price
        currency = registration.currency or "PEN"
        purchase_number = f"{registration.event_id}-{registration.id}"

        data.update({
            "merchant_id": self._get_setting(event, "merchant_id"),
            "amount": amount,
            "currency": currency,
            "purchase_number": purchase_number,
            "merchant_logo_url": self._get_setting(event, "merchant_logo_url"),
            "checkout_button_color": self._get_setting(event, "button_color"),
            "checkout_methods": self._collect_methods(event),
            "tokenization_enabled": self._get_bool(event, "enable_tokenization"),
            "start_url": url_for(
                "payment_niubiz.start",
                event_id=event.id,
                reg_form_id=registration.registration_form.id,
                reg_id=registration.id,
            ),
            "cancel_url": url_for(
                "payment_niubiz.cancel",
                event_id=event.id,
                reg_form_id=registration.registration_form.id,
                reg_id=registration.id,
            ),
        })

        # Tokens almacenados del usuario
        user = getattr(registration, "user", None)
        if user:
            data["stored_tokens"] = NiubizStoredToken.query.filter_by(user_id=user.id) \
                .order_by(NiubizStoredToken.created_at.desc()).all()

    def process_payment(self, registration, data):
        """Procesa un intento de pago y devuelve la acción a ejecutar."""
        method = (data or {}).get("method") or "card"
        event = registration.event
        methods = self._collect_methods(event)

        if method == "token":
            if not self._get_bool(event, "enable_tokenization"):
                raise BadRequest(_("La tokenización no está habilitada para este evento."))
            token_id = (data or {}).get("token_id")
            if not token_id:
                raise BadRequest(_("No se proporcionó el token almacenado."))
            return {
                "action": "redirect",
                "url": url_for(
                    "payment_niubiz.start",
                    event_id=event.id,
                    reg_form_id=registration.registration_form.id,
                    reg_id=registration.id,
                    method="token",
                    token_id=token_id,
                ),
            }

        if not methods.get(method):
            raise BadRequest(_("El método de pago seleccionado no está habilitado."))

        return {
            "action": "redirect",
            "url": url_for(
                "payment_niubiz.start",
                event_id=event.id,
                reg_form_id=registration.registration_form.id,
                reg_id=registration.id,
                method=method,
            ),
        }

    # ------------------ Reembolsos ------------------
    def refund(self, registration, transaction=None, amount=None, reason=None, **kwargs):
        """Inicia un reembolso en Niubiz y registra el resultado en Indico."""
        registration = registration or getattr(transaction, "registration", None)
        if not registration:
            return {"success": False, "error": _("No se pudo determinar la inscripción a reembolsar.")}

        event = getattr(registration, "event", None)
        txn = transaction or getattr(registration, "transaction", None)
        currency = getattr(txn, "currency", None) or getattr(registration, "currency", None) or "PEN"

        # Determinar monto
        amount_decimal = parse_amount(amount, None) or \
                         parse_amount(getattr(txn, "amount", None), None) or \
                         parse_amount(getattr(registration, "price", None), None)

        if event is None or amount_decimal is None:
            return {"success": False, "error": _("Datos insuficientes para procesar el reembolso.")}

        # Determinar transaction_id
        transaction_payload = getattr(txn, "data", {}) or {}
        transaction_id = (
            self._extract_transaction_id(transaction_payload)
            or getattr(txn, "transaction_id", None)
            or getattr(txn, "external_transaction_id", None)
        )
        transaction_id = str(transaction_id) if transaction_id else None
        if transaction_id is None:
            return {"success": False, "error": _("No se encontró el identificador de transacción en Niubiz.")}

        logger.info("Solicitando reembolso Niubiz: reg=%s, txn=%s", getattr(registration, "id", "?"), transaction_id)

        # Llamar al cliente
        try:
            client = self._build_client(event)
            result = client.refund_transaction(
                transaction_id=transaction_id,
                amount=amount_decimal,
                currency=currency,
                reason=reason,
            )
        except Exception:
            logger.exception("Error al solicitar el reembolso en Niubiz")
            return {"success": False, "error": _("Error al comunicarse con Niubiz.")}

        # Preparar payload
        payload_for_storage = result.data if isinstance(result.data, dict) else {"raw": result.data}

        status_value = result.status or ""
        status_key = status_value.upper()
        niubiz_transaction_id = result.transaction_id or transaction_id

        transaction_data = build_transaction_data(
            payload=payload_for_storage,
            source="refund",
            transaction_id=niubiz_transaction_id,
            status=status_value or None,
            reason=reason,
        )
        transaction_data["currency"] = currency
        transaction_data["amount"] = float(amount_decimal)

        success_statuses = {"REFUNDED", "VOIDED"}
        is_success = bool(result.success) and status_key in success_statuses

        if is_success:
            summary = _("Niubiz confirmó el reembolso correctamente.")
            logger.info("Reembolso Niubiz exitoso: reg=%s, txn=%s", registration.id, niubiz_transaction_id)
        else:
            summary = (
                result.data.get("error")
                if isinstance(result.data, dict) and result.data.get("error")
                else _("Niubiz no pudo completar el reembolso.")
            )
            logger.warning("Reembolso Niubiz fallido: reg=%s, txn=%s, error=%s", registration.id, niubiz_transaction_id, summary)
            transaction_data["error"] = summary

        handle_refund(
            registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=niubiz_transaction_id,
            status=status_value or ("REFUNDED" if is_success else "FAILED"),
            summary=summary,
            data=transaction_data,
            success=is_success,
        )

        return {"success": is_success, **({} if is_success else {"error": summary})}

    # ------------------ Tokens ------------------
    @staticmethod
    def _extract_transaction_id(payload: Dict[str, object]) -> Optional[str]:
        """Extrae transaction_id desde un payload flexible."""
        if not isinstance(payload, dict):
            return None
        for key in ("transaction_id", "transactionId", "TRANSACTION_ID", "operationNumber"):
            if payload.get(key):
                return str(payload[key])
        nested = payload.get("payload") or payload.get("data") or payload.get("order") or payload.get("ORDER")
        if isinstance(nested, dict):
            return NiubizPaymentPlugin._extract_transaction_id(nested)
        return None

    def get_stored_tokens(self, user) -> Iterable[NiubizStoredToken]:
        if user is None:
            return []
        return NiubizStoredToken.query.filter_by(user_id=user.id).order_by(NiubizStoredToken.created_at.desc())

    def store_token(self, user, token: str, payload: Dict[str, object]) -> NiubizStoredToken:
        stored = NiubizStoredToken(user_id=user.id, token=token)
        stored.update_from_token_response(payload)
        from indico.core.db import db
        db.session.add(stored)
        db.session.flush()
        return stored

    def delete_token(self, user, token_id: int) -> bool:
        if user is None:
            return False
        stored = NiubizStoredToken.query.filter_by(user_id=user.id, id=token_id).first()
        if not stored:
            return False
        from indico.core.db import db
        db.session.delete(stored)
        db.session.flush()
        return True
