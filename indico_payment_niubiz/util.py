"""Utility helpers used by the Niubiz payment plugin."""

from __future__ import annotations

import ipaddress
import logging
from typing import Iterable, Sequence

from indico.modules.events.payment.models.transactions import TransactionStatus


logger = logging.getLogger(__name__)


CHECKOUT_JS_URLS = {
    "sandbox": "https://static-content-qas.vnforapps.com/env/sandbox/js/checkout.js",
    "prod": "https://static-content.vnforapps.com/v2/js/checkout.js",
}

# Official production IP ranges published by Niubiz for callbacks.
DEFAULT_CALLBACK_IPS = (
    "200.48.119.0/24",
    "200.48.62.0/24",
    "200.48.63.0/24",
    "200.37.132.0/24",
    "200.37.133.0/24",
)

# Additional codes documented as rejections or technical failures.
REJECTED_CODES = {"101", "102", "116", "129", "180", "191"}
FAILED_CODES = {"670", "678", "754", "666"}
CANCELLED_CODES = {"9997", "9905"}
TIMEOUT_CODES = {"909", "9999"}


def get_checkout_script_url(endpoint: str = "sandbox") -> str:
    endpoint_key = "sandbox" if (endpoint or "sandbox").lower() == "sandbox" else "prod"
    return CHECKOUT_JS_URLS[endpoint_key]


def map_action_code_to_status(action_code: str, status: str) -> TransactionStatus:
    """Map Niubiz action/status codes to the Indico :class:`TransactionStatus` enum."""

    normalized_code = (action_code or "").strip()
    normalized_status = (status or "").strip().lower()

    if normalized_code == "000" or normalized_status == "authorized":
        return TransactionStatus.successful

    if normalized_status in {"confirmed", "captured", "paid", "completed"}:
        return TransactionStatus.successful

    if normalized_status in {"cancelled", "canceled"} or normalized_code in CANCELLED_CODES:
        return TransactionStatus.cancelled

    if normalized_status in {"expired", "timeout"} or normalized_code in TIMEOUT_CODES:
        return TransactionStatus.expired

    if normalized_code in REJECTED_CODES or normalized_status in {"rejected", "denied"}:
        return TransactionStatus.rejected

    if normalized_code in FAILED_CODES or normalized_status in {"failed", "error"}:
        return TransactionStatus.failed

    return TransactionStatus.error


def parse_ip_list(values: Sequence[str]) -> Sequence[ipaddress._BaseNetwork]:  # type: ignore[name-defined]
    networks = []
    for value in values:
        value = (value or "").strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid Niubiz callback IP range: %%s", value)
    return tuple(networks)


def ip_in_whitelist(ip: str, networks: Iterable[ipaddress._BaseNetwork]) -> bool:  # type: ignore[name-defined]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Received Niubiz callback from invalid IP address: %%s", ip)
        return False
    return any(address in network for network in networks)
