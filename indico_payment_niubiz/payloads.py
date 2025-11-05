"""Utilidades para construir payloads antifraude y MDD para Niubiz."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional
from uuid import uuid4

from werkzeug.exceptions import BadRequest


REQUIRED_MDD_KEYS = ("MDD4", "MDD5", "MDD32", "MDD75", "MDD77")


def _safe_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _dict_get(data: Dict[str, Any], key: str) -> Optional[Any]:
    if key in data and data[key] not in (None, ""):
        return data[key]
    lower = key.lower()
    if lower in data and data[lower] not in (None, ""):
        return data[lower]
    upper = key.upper()
    if upper in data and data[upper] not in (None, ""):
        return data[upper]
    return None


def _iter_registration_sources(registration) -> Iterable[Any]:
    yield registration
    user = getattr(registration, "user", None)
    if user is not None:
        yield user
    personal_data = getattr(registration, "personal_data", None)
    if isinstance(personal_data, dict):
        yield personal_data
    if hasattr(registration, "data"):
        data = getattr(registration, "data")
        if isinstance(data, dict):
            yield data
        elif isinstance(data, (list, tuple)):
            for item in data:
                if isinstance(item, dict):
                    yield item
                else:
                    for attr in ("data", "field_data"):
                        if hasattr(item, attr):
                            nested = getattr(item, attr)
                            if isinstance(nested, dict):
                                yield nested
    getter = getattr(registration, "get_personal_data", None)
    if callable(getter):
        try:
            result = getter()
        except TypeError:
            # Algunos métodos requieren argumentos; ignorar
            result = None
        if isinstance(result, dict):
            yield result


def _get_registration_value(registration, keys: Iterable[str]) -> Optional[Any]:
    normalized_keys = list(keys)
    for source in _iter_registration_sources(registration):
        if isinstance(source, dict):
            for key in normalized_keys:
                value = _dict_get(source, key)
                if value not in (None, ""):
                    return value
        else:
            for key in normalized_keys:
                if hasattr(source, key):
                    value = getattr(source, key)
                    if callable(value):
                        try:
                            value = value()
                        except TypeError:
                            continue
                    if value not in (None, ""):
                        return value
    return None


def _compute_days_since(date_obj) -> int:
    if date_obj is None:
        return 0
    if not hasattr(date_obj, "tzinfo") or date_obj.tzinfo is None:
        date_obj = date_obj.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    delta = now - date_obj
    try:
        return max(0, delta.days)
    except Exception:
        return 0


def collect_mdd_data(
    registration,
    *,
    extra: Optional[Dict[str, Any]] = None,
    require_all: bool = False,
) -> Dict[str, str]:
    """Construye los Merchant Defined Data obligatorios para Niubiz."""

    email = _safe_string(
        _get_registration_value(
            registration,
            ("email", "contact_email", "user_email", "mail"),
        )
    )
    if not email and getattr(registration, "user", None):
        email = _safe_string(getattr(registration.user, "email", ""))

    phone = _safe_string(
        _get_registration_value(
            registration,
            ("phone", "phone_number", "mobile", "tel", "telephone"),
        )
    )
    if not phone:
        phone = "000000000"

    unique_id = _safe_string(
        _get_registration_value(
            registration,
            ("identifier", "document", "document_number", "dni", "id", "code"),
        )
    )
    if not unique_id:
        user_id = getattr(registration, "user_id", None)
        if user_id:
            unique_id = str(user_id)
        elif email:
            unique_id = email
        else:
            unique_id = f"REG-{getattr(registration, 'id', '0')}"

    user = getattr(registration, "user", None)
    user_type = "Registrado" if user or getattr(registration, "user_id", None) else "Invitado"
    days_registered = 0
    if user is not None:
        created = getattr(user, "created_dt", None) or getattr(user, "created", None)
        days_registered = _compute_days_since(created)
    else:
        created = getattr(registration, "created_dt", None) or getattr(registration, "submitted_dt", None)
        days_registered = _compute_days_since(created)

    mdd: Dict[str, str] = {
        "MDD57": "PushPayments",
        "MDD4": email,
        "MDD5": phone,
        "MDD32": unique_id,
        "MDD75": user_type,
        "MDD77": str(days_registered),
    }

    if extra:
        for key, value in extra.items():
            if value is None:
                continue
            mdd[str(key)] = _safe_string(value)

    if require_all:
        missing = [key for key in REQUIRED_MDD_KEYS if not _safe_string(mdd.get(key))]
        if missing:
            raise BadRequest(
                "Faltan datos obligatorios para antifraude Niubiz: " + ", ".join(sorted(missing))
            )

    return mdd


def build_antifraud_payload(
    registration,
    mdd: Dict[str, str],
    *,
    client_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Construye el objeto antifraud recomendado por Niubiz."""

    first_name = _safe_string(
        _get_registration_value(registration, ("first_name", "firstname", "first"))
    )
    last_name = _safe_string(
        _get_registration_value(registration, ("last_name", "lastname", "last"))
    )
    country = _safe_string(
        _get_registration_value(registration, ("country", "country_code", "countryName"))
    )
    city = _safe_string(_get_registration_value(registration, ("city", "town")))
    address = _safe_string(
        _get_registration_value(registration, ("address", "address_line", "address1", "street"))
    )

    antifraud: Dict[str, Any] = {
        "merchantDefineData": mdd,
    }

    if client_ip:
        antifraud["clientIp"] = client_ip

    bill_to: Dict[str, Any] = {
        "firstName": first_name,
        "lastName": last_name,
        "email": mdd.get("MDD4", ""),
        "phoneNumber": mdd.get("MDD5", ""),
        "address": address,
        "city": city,
        "country": country,
    }

    if any(_safe_string(value) for value in bill_to.values()):
        antifraud["billTo"] = bill_to

    return antifraud


def generate_purchase_number(event_id: int, registration_id: int) -> str:
    """Genera un ``purchaseNumber`` numérico único para la sesión."""

    event_digits = f"{abs(int(event_id)) :06d}"[-6:]
    reg_digits = f"{abs(int(registration_id)) :06d}"[-6:]
    suffix = f"{uuid4().int % 1_000_000:06d}"
    purchase = f"{event_digits}{reg_digits}{suffix}"
    # Niubiz permite hasta 12 dígitos. Conservamos los últimos 12.
    return purchase[-12:]

