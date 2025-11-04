"""WTForms definitions used by the Niubiz plugin configuration."""

from __future__ import annotations

from wtforms.fields import BooleanField, SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, Optional as OptionalValidator

from indico.modules.events.payment import (
    PaymentEventSettingsFormBase,
    PaymentPluginSettingsFormBase,
)
from indico.web.forms.fields import IndicoPasswordField

from indico_payment_niubiz import _

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
    endpoint = SelectField(
        _("Entorno"),
        [DataRequired()],
        choices=[("sandbox", _("Sandbox (pruebas)")), ("prod", _("Producción"))],
    )
    enable_card = BooleanField(_("Tarjeta"), default=True)
    enable_yape = BooleanField(_("Yape"), default=False)
    enable_pagoefectivo = BooleanField(_("PagoEfectivo"), default=False)
    enable_qr = BooleanField(_("QR"), default=False)
    enable_tokenization = BooleanField(_("Tokenización"), default=False)
    callback_authorization_token = IndicoPasswordField(
        _("Token de autorización de callback"),
        [OptionalValidator()],
    )
    callback_hmac_secret = IndicoPasswordField(_("Secreto HMAC"), [OptionalValidator()])
    callback_ip_whitelist = TextAreaField(_("Whitelist de IPs"), [OptionalValidator()])


class EventSettingsForm(PaymentEventSettingsFormBase):
    merchant_id = StringField(_("Merchant ID"), [OptionalValidator()])
    access_key = IndicoPasswordField(_("Access key"), [OptionalValidator()])
    secret_key = IndicoPasswordField(_("Secret key"), [OptionalValidator()])
    merchant_logo_url = StringField(_("Logo"), [OptionalValidator()])
    button_color = StringField(_("Color del botón"), [OptionalValidator()])
    merchant_defined_data = TextAreaField(_("Merchant Define Data"), [OptionalValidator()])
    endpoint = SelectField(
        _("Entorno"),
        [OptionalValidator()],
        choices=[
            ("", _("Usar configuración global")),
            ("sandbox", _("Sandbox (pruebas)")),
            ("prod", _("Producción")),
        ],
    )
    enable_card = SelectField(_("Tarjeta"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_yape = SelectField(_("Yape"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_pagoefectivo = SelectField(_("PagoEfectivo"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_qr = SelectField(_("QR"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_tokenization = SelectField(_("Tokenización"), choices=BOOL_INHERIT_CHOICES, default="")
    callback_authorization_token = IndicoPasswordField(
        _("Token de autorización"),
        [OptionalValidator()],
    )
    callback_hmac_secret = IndicoPasswordField(_("Secreto HMAC"), [OptionalValidator()])
    callback_ip_whitelist = TextAreaField(_("Whitelist de IPs"), [OptionalValidator()])
