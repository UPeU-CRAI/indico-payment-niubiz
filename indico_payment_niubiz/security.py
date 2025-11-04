"""Funciones de seguridad y saneamiento para callbacks Niubiz."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import time
from collections import defaultdict, deque
from typing import Deque, Iterable, Mapping, MutableMapping, Optional, Sequence

logger = logging.getLogger(__name__)

DEFAULT_CALLBACK_IPS: tuple[str, ...] = (
    "200.48.119.0/24",
    "200.48.62.0/24",
    "200.48.63.0/24",
    "200.37.132.0/24",
    "200.37.133.0/24",
)

SENSITIVE_KEYS = {"card", "token", "transactionToken", "pan", "cvv", "securityCode"}

_rate_limit_buckets: MutableMapping[str, Deque[float]] = defaultdict(deque)


def extract_bearer_token(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None
    header_value = header_value.strip()
    if header_value.lower().startswith("bearer "):
        return header_value[7:].strip() or None
    return header_value or None


def parse_ip_list(entries: Iterable[str]) -> tuple[ipaddress._BaseNetwork, ...]:
    networks = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            logger.warning("Entrada de whitelist inválida: %s", entry)
            continue
        networks.append(network)
    return tuple(networks)


def ip_in_whitelist(ip: str, networks: Sequence[ipaddress._BaseNetwork]) -> bool:
    if not networks:
        return True
    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(ip_addr in network for network in networks)


def validate_nbz_signature(secret: Optional[str], body: bytes, signature: Optional[str]) -> bool:
    if not secret or not signature:
        return False
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature.strip().lower())


def redact_payload(payload: Mapping[str, object]) -> dict:
    result = {}
    for key, value in payload.items():
        if key in SENSITIVE_KEYS or key.lower() in {k.lower() for k in SENSITIVE_KEYS}:
            result[key] = "<redacted>"
        elif isinstance(value, Mapping):
            result[key] = redact_payload(value)
        else:
            result[key] = value
    return result


def check_rate_limit(bucket: str, *, limit: int = 30, window: int = 60) -> bool:
    """Devuelve ``True`` si la solicitud está permitida según el rate-limit."""

    now = time.monotonic()
    timestamps = _rate_limit_buckets[bucket]
    while timestamps and now - timestamps[0] > window:
        timestamps.popleft()
    if len(timestamps) >= limit:
        return False
    timestamps.append(now)
    return True


__all__ = [
    "DEFAULT_CALLBACK_IPS",
    "check_rate_limit",
    "extract_bearer_token",
    "ip_in_whitelist",
    "parse_ip_list",
    "redact_payload",
    "validate_nbz_signature",
]
