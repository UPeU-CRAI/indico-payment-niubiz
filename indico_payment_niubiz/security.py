"""Security helpers for validating Niubiz callbacks and webhooks."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
from dataclasses import dataclass
from typing import Iterable, Sequence

logger = logging.getLogger(__name__)


DEFAULT_CALLBACK_IPS = (
    "200.48.119.0/24",
    "200.48.62.0/24",
    "200.48.63.0/24",
    "200.37.132.0/24",
    "200.37.133.0/24",
)


def validate_nbz_signature(secret: str, body: bytes, signature: str) -> bool:
    """Validate the ``NBZ-Signature`` header using HMAC SHA-256."""

    if not secret or not signature:
        return False

    computed = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    provided = signature.strip().lower()
    return hmac.compare_digest(provided, computed.lower())


def parse_ip_list(values: Sequence[str]) -> Sequence[ipaddress._BaseNetwork]:  # type: ignore[name-defined]
    """Parse a list of IP/CIDR strings into :mod:`ipaddress` network objects."""

    networks = []
    for value in values:
        value = (value or "").strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid Niubiz callback IP range: %s", value)
    return tuple(networks)


def ip_in_whitelist(ip: str, networks: Iterable[ipaddress._BaseNetwork]) -> bool:  # type: ignore[name-defined]
    """Return ``True`` if ``ip`` is inside any of the given networks."""

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Received Niubiz callback from invalid IP address: %s", ip)
        return False
    return any(address in network for network in networks)


@dataclass(frozen=True)
class CallbackSecurityConfig:
    """Encapsulates the dynamic security configuration for callbacks."""

    hmac_secret: str | None = None
    authorization_token: str | None = None
    extra_whitelist: str | None = None

    def collect_networks(self) -> Sequence[ipaddress._BaseNetwork]:  # type: ignore[name-defined]
        extra = []
        if self.extra_whitelist:
            extra = [line.strip() for line in self.extra_whitelist.splitlines() if line.strip()]
        return parse_ip_list(DEFAULT_CALLBACK_IPS + tuple(extra))
