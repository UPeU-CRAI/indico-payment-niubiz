"""Helpers and accessors for plugin and event scoped settings."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from flask_pluginengine import current_plugin
from werkzeug.exceptions import BadRequest

from indico_payment_niubiz import _


TRUTHY = {"1", "true", "yes", "on", "si", "sí", "y", "t"}
FALSY = {"0", "false", "no", "off", "n", "f"}

ENVIRONMENT_ALIASES = {
    "sandbox": ("sandbox", True),
    "qa": ("sandbox", True),
    "qas": ("sandbox", True),
    "sandbox-pci": ("sandbox", False),
    "qa-pci": ("sandbox", False),
    "prod": ("prod", True),
    "production": ("prod", True),
    "live": ("prod", True),
    "prod-pci": ("prod", False),
    "production-pci": ("prod", False),
}

DEFAULT_ENVIRONMENT = "sandbox"

BRANDING_ALLOWED_KEYS = {"logo", "logo_url", "button_color", "primary_color", "secondary_color"}


@dataclass(frozen=True)
class EnvironmentInfo:
    raw: str
    normalized: str
    endpoint: str
    is_no_pci: bool


@dataclass(frozen=True)
class NiubizCredentials:
    merchant_id: str
    username: str
    password: str
    environment: EnvironmentInfo

    @property
    def endpoint(self) -> str:
        return self.environment.endpoint

    @property
    def is_no_pci(self) -> bool:
        return self.environment.is_no_pci


def _normalize_optional(value: Any) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return value


def _resolve_plugin(plugin=None):
    return plugin or current_plugin


def get_scoped_setting(event, name: str, plugin=None) -> Optional[str]:
    plugin = _resolve_plugin(plugin)
    event_value = _normalize_optional(plugin.event_settings.get(event, name))
    if event_value is not None:
        return event_value
    return _normalize_optional(plugin.settings.get(name))


def _normalize_env_value(raw: Optional[str]) -> EnvironmentInfo:
    raw_value = (raw or DEFAULT_ENVIRONMENT).strip() or DEFAULT_ENVIRONMENT
    normalized = raw_value.lower()
    normalized = normalized.replace(" ", "-")

    if normalized not in ENVIRONMENT_ALIASES:
        if "pci" in normalized:
            base = "prod" if "prod" in normalized or "live" in normalized else "sandbox"
            return EnvironmentInfo(raw=raw_value, normalized=normalized, endpoint=base, is_no_pci=False)
        raise BadRequest(_("Entorno Niubiz inválido: %(env)s", env=raw_value))

    endpoint, is_no_pci = ENVIRONMENT_ALIASES[normalized]
    return EnvironmentInfo(raw=raw_value, normalized=normalized, endpoint=endpoint, is_no_pci=is_no_pci)


def get_environment_for_event(event, plugin=None) -> EnvironmentInfo:
    raw = get_scoped_setting(event, "env", plugin)
    return _normalize_env_value(raw)


def get_endpoint_for_event(event, plugin=None) -> str:
    return get_environment_for_event(event, plugin).endpoint


def is_no_pci_environment(event, plugin=None) -> bool:
    return get_environment_for_event(event, plugin).is_no_pci


def _get_setting_with_fallback(event, names: Sequence[str], plugin=None) -> Optional[str]:
    for name in names:
        value = get_scoped_setting(event, name, plugin)
        if value:
            return value
    return None


def _collect_credentials(event, plugin=None) -> Dict[str, str]:
    plugin = _resolve_plugin(plugin)
    keys = ("merchant_id", "username", "password")
    values: Dict[str, str] = {}
    missing: List[str] = []

    for key in keys:
        value = _normalize_optional(plugin.event_settings.get(event, key))
        if value is None:
            value = _normalize_optional(plugin.settings.get(key))
        if not value:
            missing.append(key)
        else:
            values[key] = value

    if missing:
        raise BadRequest(
            _(
                "Faltan credenciales Niubiz: %(keys)s",
                keys=", ".join(sorted(missing)),
            )
        )

    return values


def get_credentials_for_event(event, plugin=None) -> NiubizCredentials:
    values = _collect_credentials(event, plugin)
    environment = get_environment_for_event(event, plugin)
    return NiubizCredentials(environment=environment, **values)


def get_scoped_bool(event, name: str, *, plugin=None, default: bool = False) -> bool:
    plugin = _resolve_plugin(plugin)

    def _convert(value) -> Optional[bool]:
        if value in (None, ""):
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if not normalized:
                return None
            if normalized in TRUTHY:
                return True
            if normalized in FALSY:
                return False
        return bool(value)

    override = _convert(plugin.event_settings.get(event, name))
    if override is not None:
        return override

    scoped = _convert(plugin.settings.get(name))
    if scoped is not None:
        return scoped

    return default


def _split_ip_values(raw: str) -> Tuple[str, ...]:
    cleaned: List[str] = []
    for token in re.split(r"[\s,]+", raw.strip()):
        token = token.strip()
        if not token:
            continue
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise BadRequest(_("IP/CIDR inválido: %(cidr)s", cidr=token)) from exc
        cleaned.append(token)
    return tuple(cleaned)


def get_allowed_ips(event, plugin=None) -> Tuple[str, ...]:
    raw = _get_setting_with_fallback(event, ("allowed_ips", "callback_ip_whitelist"), plugin) or ""
    if not raw:
        return tuple()
    return _split_ip_values(raw)


def get_hmac_secret(event, plugin=None) -> Optional[str]:
    return _get_setting_with_fallback(event, ("hmac_secret", "callback_hmac_secret"), plugin)


def get_authorization_token(event, plugin=None) -> Optional[str]:
    return _get_setting_with_fallback(event, ("authorization_token", "callback_authorization_token"), plugin)


def get_default_currency(event, plugin=None) -> str:
    value = get_scoped_setting(event, "default_currency", plugin)
    if not value:
        return "PEN"
    value = value.strip().upper()
    if len(value) != 3 or not value.isalpha():
        raise BadRequest(_("Código de moneda inválido: %(currency)s", currency=value))
    return value


def get_branding(event, plugin=None) -> Dict[str, str]:
    raw = get_scoped_setting(event, "branding", plugin)
    if not raw:
        return {}
    raw = raw.strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise BadRequest(_("El branding debe ser JSON válido.")) from exc
        if not isinstance(parsed, dict):
            raise BadRequest(_("El branding JSON debe ser un objeto."))
        cleaned: Dict[str, str] = {}
        for key, value in parsed.items():
            if key not in BRANDING_ALLOWED_KEYS:
                raise BadRequest(_("Llave de branding no soportada: %(key)s", key=key))
            cleaned[key] = str(value).strip()
        return cleaned
    return {"preset": raw}


def is_mdd_required(event, plugin=None) -> bool:
    return get_scoped_bool(event, "mdd_required", plugin=plugin, default=False)


def get_merchant_defined_data(event, plugin=None) -> Optional[str]:
    return get_scoped_setting(event, "merchant_defined_data", plugin)

