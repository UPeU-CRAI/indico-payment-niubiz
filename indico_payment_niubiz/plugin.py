"""Niubiz payment plugin configuration and integration with Indico.

Este módulo define:
- Configuración global y por evento para la pasarela Niubiz.
- Métodos habilitados: tarjeta, Yape, PagoEfectivo, QR y tokenización.
- Integración con el flujo de pagos de Indico.
- Placeholder para refund() pendiente de implementar con APIs Niubiz.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, Optional

from wtforms.fields import BooleanField, SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, Optional as OptionalValidator

from werkzeug.exceptions import BadRequest

from indico.core.plugins import IndicoPlugin
from indico.modules.events.payment import (
    PaymentEventSettingsFormBase,
    PaymentPluginMixin,
    PaymentPluginSettingsFormBase,
)
from indico.web.forms.fields import IndicoPasswordField
from indico.web.flask.util import url_for

from indico_payment_niubiz import _
from indico_payment_niubiz.blueprint import blueprint
from indico_payment_niubiz.client import NiubizClient
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
)

logger = logging.getLogger(__name__)

# --------------------- CONFIGURACIÓN GLOBAL ---------------------
BOOL_INHERIT_CHOICES = (
    ("", _("Usar configuración global")),
    ("1", _("Activado")),
    ("0", _("Desactivado")),
)

class PluginSettingsForm(PaymentPluginSettingsFormBase):
    merchant_id = StringField(_("Merchant ID"), [DataRequired()])
    access_key = IndicoPasswordField(_("Access key"), [DataRequired()])
    secret_key = IndicoPasswordField(_("Secret key"), [DataRequired()])
    merchant_logo_url = StringField(_("Logo del comercio"), [OptionalValidator()])
    button_color = StringField(_("Color del botón"), [OptionalValidator()])
    merchant_defined_data = TextAreaField(_("Merchant Define Data (MDD)"), [OptionalValidator()])
    endpoint = SelectField(_("Entorno"), [DataRequired()], choices=[
        ("sandbox", _("Sandbox (pruebas)")),
        ("prod", _("Producción")),
    ])
    enable_card = BooleanField(_("Tarjeta"), default=True)
    enable_yape = BooleanField(_("Yape"), default=False)
    enable_pagoefectivo = BooleanField(_("PagoEfectivo"), default=False)
    enable_qr = BooleanField(_("QR"), default=False)
    enable_tokenization = BooleanField(_("Tokenización"), default=False)
    callback_authorization_token = IndicoPasswordField(_("Token de autorización de callback"), [OptionalValidator()])
    callback_hmac_secret = IndicoPasswordField(_("Secreto HMAC"), [OptionalValidator()])
    callback_ip_whitelist = TextAreaField(_("Whitelist de IPs"), [OptionalValidator()])


# --------------------- CONFIG POR EVENTO ---------------------
class EventSettingsForm(PaymentEventSettingsFormBase):
    merchant_id = StringField(_("Merchant ID"), [OptionalValidator()])
    access_key = IndicoPasswordField(_("Access key"), [OptionalValidator()])
    secret_key = IndicoPasswordField(_("Secret key"), [OptionalValidator()])
    merchant_logo_url = StringField(_("Logo"), [OptionalValidator()])
    button_color = StringField(_("Color del botón"), [OptionalValidator()])
    merchant_defined_data = TextAreaField(_("Merchant Define Data"), [OptionalValidator()])
    endpoint = SelectField(_("Entorno"), [OptionalValidator()], choices=[
        ("", _("Usar configuración global")),
        ("sandbox", _("Sandbox (pruebas)")),
        ("prod", _("Producción")),
    ])
    enable_card = SelectField(_("Tarjeta"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_yape = SelectField(_("Yape"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_pagoefectivo = SelectField(_("PagoEfectivo"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_qr = SelectField(_("QR"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_tokenization = SelectField(_("Tokenización"), choices=BOOL_INHERIT_CHOICES, default="")
    callback_authorization_token = IndicoPasswordField(_("Token de autorización"), [OptionalValidator()])
    callback_hmac_secret = IndicoPasswordField(_("Secreto HMAC"), [OptionalValidator()])
    callback_ip_whitelist = TextAreaField(_("Whitelist de IPs"), [OptionalValidator()])


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

    def get_blueprints(self):
        return blueprint

    def _get_bool(self, event, name: str) -> bool:
        override = self.event_settings.get(event, name)
        if isinstance(override, str) and override in {"0", "1"}:
            return override == "1"
        if override is not None and not isinstance(override, str):
            return bool(override)
        return bool(self.settings.get(name))

    def _get_setting(self, event, name: str) -> Optional[str]:
        value = self.event_settings.get(event, name)
        return self.settings.get(name) if value in (None, "") else value

    def _build_client(self, event) -> NiubizClient:
        merchant_id = get_merchant_id_for_event(event, plugin=self)
        access_key, secret_key = get_credentials_for_event(event, plugin=self)
        endpoint = get_endpoint_for_event(event, plugin=self)
        return NiubizClient(merchant_id, access_key, secret_key, endpoint)

    def _collect_methods(self, event) -> Dict[str, bool]:
        return {
            "card": self._get_bool(event, "enable_card"),
            "yape": self._get_bool(event, "enable_yape"),
            "pagoefectivo": self._get_bool(event, "enable_pagoefectivo"),
            "qr": self._get_bool(event, "enable_qr"),
        }

    def adjust_payment_form_data(self, data):
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
            "start_url": url_for("payment_niubiz.start", event_id=event.id,
                                 reg_form_id=registration.registration_form.id, reg_id=registration.id),
            "cancel_url": url_for("payment_niubiz.cancel", event_id=event.id,
                                  reg_form_id=registration.registration_form.id, reg_id=registration.id),
        })

        user = getattr(registration, "user", None)
        if user:
            data["stored_tokens"] = NiubizStoredToken.query.filter_by(user_id=user.id)\
                .order_by(NiubizStoredToken.created_at.desc()).all()

    def process_payment(self, registration, data):
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
                "url": url_for("payment_niubiz.start", event_id=event.id,
                               reg_form_id=registration.registration_form.id, reg_id=registration.id,
                               method="token", token_id=token_id),
            }

        if method not in methods or not methods[method]:
            raise BadRequest(_("El método de pago seleccionado no está habilitado."))

        return {
            "action": "redirect",
            "url": url_for("payment_niubiz.start", event_id=event.id,
                           reg_form_id=registration.registration_form.id,
                           reg_id=registration.id, method=method),
        }

    def refund(self, registration, transaction=None, amount=None, reason=None, **kwargs):
        registration = registration or getattr(transaction, "registration", None)
        if not registration:
            return {"success": False, "error": _("No se pudo determinar la inscripción a reembolsar.")}

        txn = transaction or getattr(registration, "transaction", None)
        currency = getattr(txn, "currency", None) or getattr(registration, "currency", None) or "PEN"
        amount_decimal = parse_amount(amount, None) if amount is not None else None

        if amount_decimal is None:
            amount_decimal = parse_amount(getattr(txn, "amount", None), None)
        if amount_decimal is None:
            amount_decimal = parse_amount(getattr(registration, "price", None), None)

        transaction_payload = getattr(txn, "data", {}) or {}
        transaction_id = self._extract_transaction_id(transaction_payload)

        summary = _("Refund requested — not yet implemented")
        logger.info("Refund requested for Niubiz transaction %s on registration %s",
                    transaction_id or "unknown", getattr(registration, "id", "?"))

        data = build_transaction_data(
            payload=transaction_payload,
            source="refund",
            transaction_id=str(transaction_id) if transaction_id else None,
            reason=reason,
            message=summary,
            status="NOT_IMPLEMENTED",
        )
        data["currency"] = currency
        if amount_decimal is not None:
            data["amount"] = float(amount_decimal)

        handle_refund(
            registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=str(transaction_id) if transaction_id else None,
            status="NOT_IMPLEMENTED",
            summary=summary,
            data=data,
            success=False,
        )

        return {"success": False, "error": summary}

    @staticmethod
    def _extract_transaction_id(payload: Dict[str, object]) -> Optional[str]:
        if not isinstance(payload, dict):
            return None
        for key in ("transaction_id", "transactionId", "TRANSACTION_ID", "operationNumber"):
            value = payload.get(key)
            if value:
                return str(value)
        nested = payload.get("payload") or payload.get("data") or payload.get("ORDER") or payload.get("order")
        if isinstance(nested, dict):
            return NiubizPaymentPlugin._extract_transaction_id(nested)
        return None

    def get_stored_tokens(self, user) -> Iterable[NiubizStoredToken]:
        if user is None:
            return []
        return NiubizStoredToken.query.filter_by(user_id=user.id)\
            .order_by(NiubizStoredToken.created_at.desc())

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
