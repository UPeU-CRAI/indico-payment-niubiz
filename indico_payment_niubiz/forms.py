"""Formulario de configuración para el plugin Niubiz.

Este módulo centraliza los formularios de configuración global y por evento,
incluyendo validaciones adicionales requeridas por los nuevos parámetros
introducidos en el plugin (credenciales NO-PCI, branding y restricciones de
seguridad).
"""

from __future__ import annotations

import json
import ipaddress
import re
from typing import Iterable, List

from wtforms import ValidationError
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


ENV_CHOICES = (
    ("sandbox", _("Sandbox (NO-PCI)")),
    ("prod", _("Producción (NO-PCI)")),
    ("sandbox-pci", _("Sandbox (PCI)")),
    ("prod-pci", _("Producción (PCI)")),
)


_PCI_WARNING = _(
    "Los endpoints PCI no son compatibles con este plugin. Asegúrate de usar "
    "credenciales y entornos NO-PCI."
)


def _split_ip_values(raw: str) -> Iterable[str]:
    for chunk in re.split(r"[\s,]+", raw.strip()):
        chunk = chunk.strip()
        if chunk:
            yield chunk


class _AllowedIPValidator:
    """Valida y normaliza la lista de IPs/CIDRs permitidos."""

    def __call__(self, form, field) -> None:  # type: ignore[override]
        value = field.data or ""
        cleaned: List[str] = []
        for item in _split_ip_values(value):
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValidationError(_("IP/CIDR inválido: %(cidr)s", cidr=item))
            cleaned.append(item)
        field.data = "\n".join(cleaned)


class _CurrencyValidator:
    """Fuerza códigos ISO de moneda (tres letras)."""

    def __call__(self, form, field) -> None:  # type: ignore[override]
        value = (field.data or "").strip()
        if not value:
            field.data = ""
            return
        if len(value) != 3 or not value.isalpha():
            raise ValidationError(_("La moneda debe ser un código ISO de 3 letras."))
        field.data = value.upper()


class _BrandingValidator:
    """Permite strings simples o JSON con claves conocidas."""

    _slug_re = re.compile(r"^[A-Za-z0-9._-]+$")
    _allowed_json_keys = {"logo", "logo_url", "button_color", "primary_color", "secondary_color"}

    def __call__(self, form, field) -> None:  # type: ignore[override]
        value = (field.data or "").strip()
        if not value:
            field.data = ""
            return

        if value.startswith("{"):
            try:
                payload = json.loads(value)
            except ValueError:
                raise ValidationError(_("El branding debe ser JSON válido o un identificador."))
            if not isinstance(payload, dict):
                raise ValidationError(_("El branding debe ser un objeto JSON."))
            cleaned = {}
            for key, raw in payload.items():
                if key not in self._allowed_json_keys:
                    raise ValidationError(
                        _("Llave de branding no soportada: %(key)s", key=key)
                    )
                cleaned[key] = str(raw).strip()
            field.data = json.dumps(cleaned, ensure_ascii=False)
            return

        if not self._slug_re.match(value):
            raise ValidationError(
                _("El identificador de branding solo puede contener letras, números, puntos, guiones y guiones bajos."))
        field.data = value


class _RealmCodeValidator:
    _pattern = re.compile(r"^[A-Za-z0-9._-]+$")

    def __call__(self, form, field) -> None:  # type: ignore[override]
        value = (field.data or "").strip()
        if not value:
            field.data = ""
            return
        if not self._pattern.match(value):
            raise ValidationError(
                _("El realm solo puede contener letras, números, puntos, guiones y guiones bajos."))
        field.data = value


class _PCIWarningMixin:
    def _emit_pci_warning(self, env_value: str | None) -> None:
        if not env_value:
            return
        if "pci" not in env_value.lower():
            return
        warnings = getattr(self, "warning_messages", None)
        if warnings is None:
            warnings = self.warning_messages = []  # type: ignore[attr-defined]
        if _PCI_WARNING not in warnings:
            warnings.append(_PCI_WARNING)


class NiubizPluginSettingsForm(_PCIWarningMixin, PaymentPluginSettingsFormBase):
    """Formulario global para la administración del plugin."""

    merchant_id = StringField(_("Merchant ID"), [DataRequired()])
    client_id = StringField(_("Client ID"), [DataRequired()])
    client_secret = IndicoPasswordField(_("Client secret"), [DataRequired()])
    username = StringField(_("Usuario NO-PCI"), [DataRequired()])
    password = IndicoPasswordField(_("Contraseña NO-PCI"), [DataRequired()])
    realm_code = StringField(_("Realm"), [DataRequired(), _RealmCodeValidator()])
    env = SelectField(_("Entorno"), [DataRequired()], choices=ENV_CHOICES, default="sandbox")

    authorization_token = IndicoPasswordField(_("Token de autorización"), [OptionalValidator()])
    hmac_secret = IndicoPasswordField(_("Secreto HMAC"), [OptionalValidator()])
    allowed_ips = TextAreaField(_("IPs permitidas"), [_AllowedIPValidator()])

    enable_refunds = BooleanField(_("Permitir reembolsos"), default=True)
    default_currency = StringField(_("Moneda por defecto"), [_CurrencyValidator()], default="PEN")

    enable_card = BooleanField(_("Tarjeta"), default=True)
    enable_yape = BooleanField(_("Yape"), default=False)
    enable_pagoefectivo = BooleanField(_("PagoEfectivo"), default=False)
    enable_qr = BooleanField(_("QR"), default=False)
    enable_tokenization = BooleanField(_("Tokenización"), default=False)

    branding = TextAreaField(_("Branding"), [_BrandingValidator()])
    mdd_required = BooleanField(_("Exigir Merchant Defined Data"), default=False)

    merchant_defined_data = TextAreaField(_("Merchant Defined Data (JSON)"), [OptionalValidator()])

    def validate(self) -> bool:  # type: ignore[override]
        is_valid = super().validate()
        if is_valid:
            self._emit_pci_warning(self.env.data)
        return is_valid


class NiubizEventSettingsForm(_PCIWarningMixin, PaymentEventSettingsFormBase):
    """Formulario de configuración por evento."""

    merchant_id = StringField(_("Merchant ID"), [OptionalValidator()])
    client_id = StringField(_("Client ID"), [OptionalValidator()])
    client_secret = IndicoPasswordField(_("Client secret"), [OptionalValidator()])
    username = StringField(_("Usuario NO-PCI"), [OptionalValidator()])
    password = IndicoPasswordField(_("Contraseña NO-PCI"), [OptionalValidator()])
    realm_code = StringField(_("Realm"), [OptionalValidator(), _RealmCodeValidator()])
    env = SelectField(
        _("Entorno"),
        [OptionalValidator()],
        choices=(("", _("Usar configuración global")),) + ENV_CHOICES,
        default="",
    )

    authorization_token = IndicoPasswordField(_("Token de autorización"), [OptionalValidator()])
    hmac_secret = IndicoPasswordField(_("Secreto HMAC"), [OptionalValidator()])
    allowed_ips = TextAreaField(_("IPs permitidas"), [_AllowedIPValidator()])

    enable_refunds = SelectField(_("Permitir reembolsos"), choices=BOOL_INHERIT_CHOICES, default="")
    default_currency = StringField(_("Moneda por defecto"), [_CurrencyValidator()])

    enable_card = SelectField(_("Tarjeta"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_yape = SelectField(_("Yape"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_pagoefectivo = SelectField(_("PagoEfectivo"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_qr = SelectField(_("QR"), choices=BOOL_INHERIT_CHOICES, default="")
    enable_tokenization = SelectField(_("Tokenización"), choices=BOOL_INHERIT_CHOICES, default="")

    branding = TextAreaField(_("Branding"), [_BrandingValidator()])
    mdd_required = SelectField(_("Exigir Merchant Defined Data"), choices=BOOL_INHERIT_CHOICES, default="")

    merchant_defined_data = TextAreaField(_("Merchant Defined Data (JSON)"), [OptionalValidator()])

    def validate(self) -> bool:  # type: ignore[override]
        is_valid = super().validate()
        env_value = self.env.data if isinstance(self.env.data, str) else None
        if is_valid:
            self._emit_pci_warning(env_value)
        return is_valid

