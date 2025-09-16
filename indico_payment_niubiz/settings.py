from __future__ import annotations

from typing import Any, Optional

from flask_pluginengine import current_plugin
from werkzeug.exceptions import BadRequest

from indico_payment_niubiz import _


def _normalize_optional(value: Any) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return value


def _resolve_plugin(plugin=None):
    return plugin or current_plugin


def get_scoped_setting(event, name: str, plugin=None):
    plugin = _resolve_plugin(plugin)
    event_value = _normalize_optional(plugin.event_settings.get(event, name))
    if event_value is not None:
        return event_value
    return _normalize_optional(plugin.settings.get(name))


def get_endpoint_for_event(event, plugin=None) -> str:
    endpoint = (get_scoped_setting(event, 'endpoint', plugin) or 'sandbox').lower()
    return 'sandbox' if endpoint == 'sandbox' else 'prod'


def get_credentials_for_event(event, plugin=None):
    plugin = _resolve_plugin(plugin)
    access_key = (plugin.event_settings.get(event, 'access_key') or
                  plugin.settings.get('access_key'))
    secret_key = (plugin.event_settings.get(event, 'secret_key') or
                  plugin.settings.get('secret_key'))
    if not access_key or not secret_key:
        raise BadRequest(_('Niubiz credentials are not configured.'))
    return access_key, secret_key


def get_merchant_id_for_event(event, plugin=None):
    plugin = _resolve_plugin(plugin)
    merchant_id = (plugin.event_settings.get(event, 'merchant_id') or
                   plugin.settings.get('merchant_id'))
    if not merchant_id:
        raise BadRequest(_('The Niubiz merchant ID is not configured.'))
    return merchant_id

