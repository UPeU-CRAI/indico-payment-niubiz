"""Niubiz payment plugin configuration and integration with Indico."""

from __future__ import annotations

import logging
from typing import Dict, Iterable, Optional

from werkzeug.exceptions import BadRequest

from indico.core.plugins import IndicoPlugin
from indico.modules.events.payment import PaymentPluginMixin
from indico.web.flask.util import url_for

from indico_payment_niubiz import _
from indico_payment_niubiz.blueprint import blueprint
from indico_payment_niubiz.client import NiubizClient
from indico_payment_niubiz.forms import (
    NiubizEventSettingsForm,
    NiubizPluginSettingsForm,
)
from indico_payment_niubiz.indico_integration import (
    build_transaction_data,
    handle_refund,
    parse_amount,
)
from indico_payment_niubiz.models import NiubizStoredToken
from indico_payment_niubiz.settings import (
    get_branding,
    get_credentials_for_event,
    get_default_currency,
    get_environment_for_event,
    get_merchant_defined_data,
    get_scoped_bool,
    get_scoped_setting,
    is_mdd_required,
)
from indico_payment_niubiz.util import get_checkout_script_url

logger = logging.getLogger(__name__)


# --------------------- PLUGIN PRINCIPAL ---------------------
class NiubizPlugin(PaymentPluginMixin, IndicoPlugin):
    """Plugin de integración de Niubiz en Indico."""

    configurable = True
    settings_form = NiubizPluginSettingsForm
    event_settings_form = NiubizEventSettingsForm

    default_settings = {
        "method_name": "Niubiz",
        "merchant_id": "",
        "username": "",
        "password": "",
        "env": "sandbox",
        "authorization_token": "",
        "hmac_secret": "",
        "allowed_ips": "",
        "merchant_defined_data": "",
        "enable_refunds": True,
        "default_currency": "PEN",
        "enable_card": True,
        "enable_yape": False,
        "enable_pagoefectivo": False,
        "enable_qr": False,
        "enable_tokenization": False,
        "branding": "",
        "mdd_required": False,
    }

    default_event_settings = {
        "enabled": False,
        "method_name": None,
        "merchant_id": None,
        "username": None,
        "password": None,
        "env": None,
        "authorization_token": None,
        "hmac_secret": None,
        "allowed_ips": None,
        "merchant_defined_data": None,
        "enable_refunds": None,
        "default_currency": None,
        "enable_card": None,
        "enable_yape": None,
        "enable_pagoefectivo": None,
        "enable_qr": None,
        "enable_tokenization": None,
        "branding": None,
        "mdd_required": None,
    }

    # ------------------ Registro ------------------
    def get_blueprints(self):
        return blueprint

    # ------------------ Helpers de settings ------------------
    def _get_bool(self, event, name: str, *, default: bool = False) -> bool:
        return get_scoped_bool(event, name, plugin=self, default=default)

    def _get_setting(self, event, name: str) -> Optional[str]:
        return get_scoped_setting(event, name, plugin=self)

    # ------------------ Cliente ------------------
    def _build_client(self, event) -> NiubizClient:
        credentials = get_credentials_for_event(event, plugin=self)
        return NiubizClient(
            merchant_id=credentials.merchant_id,
            username=credentials.username,
            password=credentials.password,
            endpoint=credentials.endpoint,
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
        currency = registration.currency or get_default_currency(event, plugin=self)
        purchase_number = f"{registration.event_id}-{registration.id}"

        branding = get_branding(event, plugin=self)
        merchant_defined_data = get_merchant_defined_data(event, plugin=self)
        environment = get_environment_for_event(event, plugin=self)

        data.update({
            "merchant_id": self._get_setting(event, "merchant_id"),
            "amount": amount,
            "currency": currency,
            "purchase_number": purchase_number,
            "merchant_logo_url": branding.get("logo_url") or branding.get("logo"),
            "checkout_button_color": branding.get("button_color"),
            "checkout_methods": self._collect_methods(event),
            "tokenization_enabled": self._get_bool(event, "enable_tokenization"),
            "branding": branding,
            "mdd_required": is_mdd_required(event, plugin=self),
            "merchant_defined_data": merchant_defined_data,
            "checkout_js_url": get_checkout_script_url(environment.endpoint),
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

        currency = registration.currency or get_default_currency(event, plugin=self)
        if currency not in {"PEN", "USD"}:
            raise BadRequest(_("Niubiz solo soporta pagos en PEN o USD."))

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
        if event and not self._get_bool(event, "enable_refunds", default=True):
            return {"success": False, "error": _("Los reembolsos están deshabilitados para Niubiz en este evento.")}

        txn = transaction or getattr(registration, "transaction", None)
        if event:
            currency = (
                getattr(txn, "currency", None)
                or getattr(registration, "currency", None)
                or get_default_currency(event, plugin=self)
            )
        else:
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
        payload_for_storage = (
            result.get("data") if result.get("success") and isinstance(result.get("data"), dict)
            else result.get("payload") if isinstance(result.get("payload"), dict)
            else result
        )

        status_value = result.get("status") or ""
        status_key = status_value.upper()
        niubiz_transaction_id = result.get("transaction_id") or transaction_id

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
        is_success = bool(result.get("success")) and status_key in success_statuses

        if is_success:
            summary = _("Niubiz confirmó el reembolso correctamente.")
            logger.info("Reembolso Niubiz exitoso: reg=%s, txn=%s", registration.id, niubiz_transaction_id)
        else:
            summary = result.get("error") or _("Niubiz no pudo completar el reembolso.")
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
            return NiubizPlugin._extract_transaction_id(nested)
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
