"""Niubiz HTTP client abstraction used by the plugin."""

from __future__ import annotations

import base64
import logging
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Dict, Optional

import requests

from indico_payment_niubiz import _


logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT = 30
TOKEN_TTL_SECONDS = 55 * 60
TOKEN_REFRESH_THRESHOLD_SECONDS = 5 * 60


# -----------------------------
# Core endpoints
# -----------------------------
SECURITY_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.security/v1/security",
    "prod": "https://apiprod.vnforapps.com/api.security/v1/security",
}

SESSION_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.ecommerce/v2/ecommerce/token/session/{merchant_id}",
    "prod": "https://apiprod.vnforapps.com/api.ecommerce/v2/ecommerce/token/session/{merchant_id}",
}

AUTHORIZATION_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/ecommerce/{merchant_id}",
    "prod": "https://apiprod.vnforapps.com/api.authorization/v3/authorization/ecommerce/{merchant_id}",
}

CONFIRMATION_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.confirmation/v1/confirmation/ecommerce/{merchant_id}",
    "prod": "https://apiprod.vnforapps.com/api.confirmation/v1/confirmation/ecommerce/{merchant_id}",
}

REVERSAL_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.authorization/v3/reverse/ecommerce/{merchant_id}",
    "prod": "https://apiprod.vnforapps.com/api.authorization/v3/reverse/ecommerce/{merchant_id}",
}

REFUND_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.refund/v1/refund/{merchant_id}/{transaction_id}",
    "prod": "https://apiprod.vnforapps.com/api.refund/v1/refund/{merchant_id}/{transaction_id}",
}

QUERY_REFUND_ENDPOINTS = {
    "sandbox": "https://apitestenv.vnforapps.com/api.refund/v1/queryRefund/{merchant_id}",
    "prod": "https://apiprod.vnforapps.com/api.refund/v1/queryRefund/{merchant_id}",
}

# -----------------------------
# Order management (estado de órdenes)
# -----------------------------
ORDER_QUERY_ENDPOINTS = {
    "sandbox": "https://apitestenv.vnforapps.com/api.ordermgmt/api/v1/order/query/{merchant_id}/{order_id}",
    "prod": "https://apiprod.vnforapps.com/api.ordermgmt/api/v1/order/query/{merchant_id}/{order_id}",
}

ORDER_QUERY_EXTERNAL_ENDPOINTS = {
    "sandbox": "https://apitestenv.vnforapps.com/api.ordermgmt/api/v1/order/query/{merchant_id}/external/{external_id}",
    "prod": "https://apiprod.vnforapps.com/api.ordermgmt/api/v1/order/query/{merchant_id}/external/{external_id}",
}

ORDER_BATCH_QUERY_ENDPOINTS = {
    "sandbox": "https://apitestenv.vnforapps.com/api.ordermgmt/api/v1/batch/query/{merchant_id}/{batch_id}",
    "prod": "https://apiprod.vnforapps.com/api.ordermgmt/api/v1/batch/query/{merchant_id}/{batch_id}",
}

# -----------------------------
# Medios de pago adicionales
# -----------------------------
YAPE_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/yape/{merchant_id}",
    "prod": "https://apiprod.vnforapps.com/api.authorization/v3/authorization/yape/{merchant_id}",
}

PAGOEFECTIVO_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/pagoefectivo/{merchant_id}",
    "prod": "https://apiprod.vnforapps.com/api.authorization/v3/authorization/pagoefectivo/{merchant_id}",
}

# -----------------------------
# Utilidades
# -----------------------------
BIN_LOOKUP_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/bin/{merchant_id}/{bin_number}",
    "prod": "https://apiprod.vnforapps.com/api.authorization/v3/authorization/bin/{merchant_id}/{bin_number}",
}

ANTIFRAUD_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.antifraud/v1/antifraud/validate",
    "prod": "https://apiprod.vnforapps.com/api.antifraud/v1/antifraud/validate",
}

TOKENIZE_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.tokenization/v1/tokenize/{merchant_id}",
    "prod": "https://apiprod.vnforapps.com/api.tokenization/v1/tokenize/{merchant_id}",
}


# -----------------------------
# Sensibilidad
# -----------------------------
SENSITIVE_KEYWORDS = (
    "accesskey",
    "access_key",
    "secret",
    "secretkey",
    "token",
    "tokenid",
    "transactiontoken",
    "sessionkey",
    "cvv",
    "cvv2",
    "pan",
    "cardnumber",
    "card_number",
    "otp",
    "signature",
)


@dataclass
class _TokenEntry:
    token: str
    expires_at: datetime

    def is_valid(self) -> bool:
        now = datetime.now(timezone.utc)
        return self.expires_at > now + timedelta(seconds=TOKEN_REFRESH_THRESHOLD_SECONDS)


class _TokenCache:
    def __init__(self) -> None:
        self._tokens: Dict[tuple, _TokenEntry] = {}
        self._lock = RLock()

    def _key(self, merchant_id: str, access_key: str, secret_key: str, endpoint: str) -> tuple:
        return (endpoint, merchant_id, access_key, secret_key)

    def get(self, merchant_id: str, access_key: str, secret_key: str, endpoint: str) -> Optional[_TokenEntry]:
        key = self._key(merchant_id, access_key, secret_key, endpoint)
        with self._lock:
            entry = self._tokens.get(key)
            if entry and entry.is_valid():
                return entry
            if entry:
                self._tokens.pop(key, None)
        return None

    def store(self, merchant_id: str, access_key: str, secret_key: str, endpoint: str, token: str,
              expires_at: datetime) -> None:
        key = self._key(merchant_id, access_key, secret_key, endpoint)
        with self._lock:
            self._tokens[key] = _TokenEntry(token=token, expires_at=expires_at)

    def invalidate(self, merchant_id: str, access_key: str, secret_key: str, endpoint: str) -> None:
        key = self._key(merchant_id, access_key, secret_key, endpoint)
        with self._lock:
            self._tokens.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._tokens.clear()


_TOKEN_CACHE = _TokenCache()


def _normalize_endpoint(endpoint: Optional[str]) -> str:
    endpoint = (endpoint or "sandbox").lower()
    return "sandbox" if endpoint == "sandbox" else "prod"


def _mask_string(value: str) -> str:
    value = str(value)
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 10:
        return value[0] + "*" * (len(value) - 2) + value[-1]
    return f"{value[:6]}{'*' * (len(value) - 10)}{value[-4:]}"


def _is_sensitive_key(key: Optional[str]) -> bool:
    if not key:
        return False
    key_lower = key.lower()
    if "masked" in key_lower and "card" in key_lower:
        return False
    return any(keyword in key_lower for keyword in SENSITIVE_KEYWORDS)


def _sanitize_payload(payload: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return payload

    def _sanitize(value: Any, key: Optional[str] = None) -> Any:
        if isinstance(value, dict):
            return {k: _sanitize(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [_sanitize(item, key) for item in value]
        if _is_sensitive_key(key):
            if isinstance(value, str):
                return _mask_string(value)
            return "***"
        return value

    return _sanitize(payload)


def _safe_json(response: requests.Response) -> Dict[str, Any]:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _extract_error_message(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}

    if isinstance(payload, dict):
        for key in ("message", "errorMessage", "title", "error"):
            value = payload.get(key)
            if value:
                return str(value)
        data = payload.get("data")
        if isinstance(data, dict):
            for key in ("ACTION_DESCRIPTION", "ACTION_MESSAGE", "ACTION_CODE", "status"):
                value = data.get(key)
                if value:
                    return str(value)

    text = (response.text or "").strip()
    return text


class NiubizClient:
    """Convenience wrapper around the Niubiz REST APIs."""

    def __init__(
        self,
        *,
        merchant_id: str,
        access_key: str,
        secret_key: str,
        endpoint: str = "sandbox",
        timeout: int = DEFAULT_TIMEOUT,
        http: Optional[Any] = None,
    ) -> None:
        self.merchant_id = merchant_id
        self.access_key = access_key
        self.secret_key = secret_key
        self.endpoint = _normalize_endpoint(endpoint)
        self.timeout = timeout
        self._http = http or requests

    # ------------------------------------------------------------------
    # Token management helpers
    # ------------------------------------------------------------------
    def clear_cached_token(self) -> None:
        """Invalidate the cached security token for this client instance."""
        _TOKEN_CACHE.invalidate(self.merchant_id, self.access_key, self.secret_key, self.endpoint)

    def get_security_token(self, *, force_refresh: bool = False) -> Dict[str, Any]:
        """Retrieve a security token from Niubiz.

        Args:
            force_refresh: When ``True`` skips the cache and forces a network call.

        Returns:
            Dict[str, Any]: Information about the retrieval attempt. When ``success`` is ``True`` the
            dictionary contains the ``token`` string and the ``expires_at`` timestamp. On cached
            responses the ``cached`` flag is included.
        """
        if not force_refresh:
            cached = _TOKEN_CACHE.get(self.merchant_id, self.access_key, self.secret_key, self.endpoint)
        else:
            cached = None
        if cached:
            logger.info("Using cached Niubiz security token for merchant %s", self.merchant_id)
            return {
                "success": True,
                "token": cached.token,
                "cached": True,
                "expires_at": cached.expires_at.isoformat(),
            }

        url = SECURITY_ENDPOINTS[self.endpoint]
        credentials = f"{self.access_key}:{self.secret_key}".encode("utf-8")
        headers = {
            "Authorization": "Basic " + base64.b64encode(credentials).decode("utf-8"),
            "Accept": "application/json",
        }

        result = self._perform_request(
            "GET",
            url,
            headers=headers,
            error_message=_("Failed to obtain the Niubiz security token."),
            allow_token_refresh=False,
            include_token=False,
        )
        if not result["success"]:
            return result

        response = result["response"]
        payload = _safe_json(response)
        raw_text = (response.text or "").strip()
        token = payload.get("accessToken") or payload.get("access_token") or raw_text

        if token:
            expires_at = self._parse_expiration(payload) or (
                datetime.now(timezone.utc) + timedelta(seconds=TOKEN_TTL_SECONDS)
            )
            _TOKEN_CACHE.store(
                self.merchant_id, self.access_key, self.secret_key, self.endpoint, token, expires_at
            )
            logger.info("Obtained Niubiz security token for merchant %s", self.merchant_id)
            data: Dict[str, Any] = {
                "success": True,
                "token": token,
                "expires_at": expires_at.isoformat(),
            }
            if payload:
                data["payload"] = payload
            return data

        self.clear_cached_token()
        logger.error("Niubiz security token response was empty for merchant %s", self.merchant_id)
        return {
            "success": False,
            "error": _("Failed to obtain the Niubiz security token. The response was empty."),
            "payload": payload,
        }

    # ------------------------------------------------------------------
    # Transactional operations
    # ------------------------------------------------------------------
    def create_session_token(
        self,
        *,
        amount: Any,
        purchase_number: Optional[str],
        currency: str,
        antifraud_data: Optional[Dict[str, Any]] = None,
        customer_email: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a checkout session token in Niubiz.

        Args:
            amount: Monetary amount of the purchase.
            purchase_number: Optional merchant purchase identifier.
            currency: ISO currency code.
            antifraud_data: Additional antifraud payload to be sent to Niubiz.
            customer_email: Customer email address for antifraud.
            client_id: Identifier associated with the client on the merchant side.

        Returns:
            Dict[str, Any]: Response information that includes the ``session_key`` when
            successful. Niubiz may report states ``P`` (pending), ``E`` (error), ``S`` (success) or
            ``T`` (timeout) within the payload.
        """
        url = SESSION_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {"Content-Type": "application/json", "Authorization": token}

        antifraud = antifraud_data or {}
        data_map: Dict[str, Any] = {"clientId": client_id or "indico"}
        if customer_email:
            data_map["customerEmail"] = customer_email

        body: Dict[str, Any] = {
            "channel": "web",
            "amount": float(amount),
            "currency": currency,
            "antifraud": antifraud,
            "dataMap": data_map,
        }
        if purchase_number:
            body["order"] = {"purchaseNumber": purchase_number}

        result = self._perform_request(
            "POST", url, headers=headers, json=body, error_message=_("Failed to create the Niubiz checkout session."),
        )
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        session_key = payload.get("sessionKey")
        if not session_key:
            return {"success": False, "error": _("The Niubiz session response was invalid."), "payload": payload}

        return {
            "success": True,
            "session_key": session_key,
            "payload": payload,
            "access_token": token,
            "expiration_time": payload.get("expirationTime"),
        }

    def authorize_transaction(
        self,
        *,
        transaction_token: str,
        purchase_number: str,
        amount: Any,
        currency: str,
        client_ip: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Authorize a transaction against Niubiz.

        Args:
            transaction_token: Token returned by the checkout form.
            purchase_number: Merchant purchase identifier.
            amount: Monetary amount to authorise.
            currency: ISO currency code.
            client_ip: Customer IP used for antifraud evaluation.
            client_id: Optional merchant-side client identifier.

        Returns:
            Dict[str, Any]: Normalized transaction information with keys such as ``status``,
            ``action_code`` and ``transaction_id``. Niubiz reports states ``P`` (pending), ``E``
            (error), ``S`` (success) or ``T`` (timeout).
        """
        url = AUTHORIZATION_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {"Content-Type": "application/json", "Authorization": token}

        antifraud_ip = client_ip or "127.0.0.1"
        body: Dict[str, Any] = {
            "channel": "web",
            "captureType": "manual",
            "countable": True,
            "order": {
                "tokenId": transaction_token,
                "purchaseNumber": purchase_number,
                "amount": float(amount),
                "currency": currency,
            },
            "dataMap": {"clientIp": antifraud_ip},
        }
        if client_id:
            body["dataMap"]["clientId"] = client_id

        result = self._perform_request("POST", url, headers=headers, json=body,
                                       error_message=_("Failed to authorise the Niubiz transaction."))
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        return normalized

    def confirm_transaction(self, *, transaction_id: str) -> Dict[str, Any]:
        """Confirm a previously authorized Niubiz transaction.

        Args:
            transaction_id: Identifier returned by Niubiz when the transaction was authorized.

        Returns:
            Dict[str, Any]: Normalized transaction information that includes ``status``,
            ``action_code`` and ``transaction_id``. The ``status`` can be ``P`` (pending), ``E``
            (error), ``S`` (success) or ``T`` (timeout).

        Raises:
            ValueError: If ``transaction_id`` is empty.
        """
        if not transaction_id:
            raise ValueError(_("The Niubiz transaction ID cannot be empty."))

        url = CONFIRMATION_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {"Authorization": token, "Accept": "application/json", "Content-Type": "application/json"}
        body = {"transactionId": transaction_id}

        result = self._perform_request("POST", url, headers=headers, json=body,
                                       error_message=_("Failed to confirm the Niubiz transaction."))
        if not result["success"]:
            logger.error("Failed to confirm transaction %s: %s", transaction_id, result.get("error"))
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        logger.info("Confirmed transaction %s with status %s", transaction_id, normalized.get("status"))
        return normalized

    def reverse_transaction(self, *, transaction_id: str, amount: Any, currency: str) -> Dict[str, Any]:
        """Reverse (void) a transaction in Niubiz.

        Args:
            transaction_id: Identifier of the transaction to reverse.
            amount: Monetary amount to reverse.
            currency: ISO currency code.

        Returns:
            Dict[str, Any]: Normalized transaction data that includes ``status``, ``action_code``
            and ``transaction_id`` on success. Niubiz uses states ``P`` (pending), ``E`` (error),
            ``S`` (success) or ``T`` (timeout).

        Raises:
            ValueError: If ``transaction_id`` is empty.
        """
        if not transaction_id:
            raise ValueError(_("The Niubiz transaction ID cannot be empty."))

        url = REVERSAL_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {"Content-Type": "application/json", "Authorization": token}
        body = {"transactionId": transaction_id, "amount": float(amount), "currency": currency}

        result = self._perform_request("POST", url, headers=headers, json=body,
                                       error_message=_("Failed to reverse the Niubiz transaction."))
        if not result["success"]:
            logger.error("Failed to reverse transaction %s: %s", transaction_id, result.get("error"))
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        logger.info("Reversed transaction %s with status %s", transaction_id, normalized.get("status"))
        return normalized

    def refund_transaction(
        self, *, transaction_id: str, amount: Any, currency: str, reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Refund an existing Niubiz transaction.

        Args:
            transaction_id: Identifier of the transaction to refund.
            amount: Monetary amount to refund.
            currency: ISO currency code.
            reason: Optional description of the refund reason.

        Returns:
            Dict[str, Any]: Normalized transaction data including ``status``, ``action_code`` and
            ``transaction_id`` when the refund succeeds. Niubiz states may be ``P`` (pending), ``E``
            (error), ``S`` (success) or ``T`` (timeout).

        Raises:
            ValueError: If ``transaction_id`` is empty.
        """
        if not transaction_id:
            raise ValueError(_("The Niubiz transaction ID cannot be empty."))

        url = REFUND_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id, transaction_id=transaction_id)
        token = self._ensure_token()
        headers = {"Content-Type": "application/json", "Authorization": token}
        body: Dict[str, Any] = {"amount": float(amount), "currency": currency}
        if reason:
            body["reason"] = reason

        result = self._perform_request("POST", url, headers=headers, json=body,
                                       error_message=_("Failed to refund the Niubiz transaction."))
        if not result["success"]:
            logger.error("Failed to refund transaction %s: %s", transaction_id, result.get("error"))
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        logger.info("Refunded transaction %s with status %s", transaction_id, normalized.get("status"))
        return normalized

    def query_refund(self) -> Dict[str, Any]:
        """Query the status of refund operations associated with the merchant.

        Returns:
            Dict[str, Any]: Response payload including ``success`` and ``access_token`` when
            available. Refund statuses reported by Niubiz may be ``P`` (pending), ``E`` (error),
            ``S`` (success) or ``T`` (timeout).
        """
        url = QUERY_REFUND_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {"Authorization": token, "Accept": "application/json"}

        result = self._perform_request("GET", url, headers=headers,
                                       error_message=_("Failed to query Niubiz refund status."))
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        payload.setdefault("success", True)
        payload["access_token"] = token
        return payload

    # ------------------------------------------------------------------
    # Order management (query endpoints)
    # ------------------------------------------------------------------
    def query_order(self, order_id: str) -> Dict[str, Any]:
        """Retrieve the status of an order using its Niubiz identifier.

        Args:
            order_id: Identifier assigned by Niubiz to the order.

        Returns:
            Dict[str, Any]: Raw order payload augmented with ``success`` and ``access_token`` when
            successful. Niubiz reports order states such as ``PENDING``, ``COMPLETED``, ``CANCELED``
            and ``EXPIRED``.

        Raises:
            ValueError: If ``order_id`` is empty.
        """
        if not order_id:
            raise ValueError(_("The Niubiz order ID cannot be empty."))

        url = ORDER_QUERY_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id, order_id=order_id)
        token = self._ensure_token()
        headers = {"Authorization": token, "Accept": "application/json"}

        result = self._perform_request("GET", url, headers=headers,
                                       error_message=_("Failed to query Niubiz order by ID."))
        if not result["success"]:
            logger.error("Failed to query order %s: %s", order_id, result.get("error"))
            return result

        payload = _safe_json(result["response"])
        payload.setdefault("success", True)
        payload["access_token"] = token
        logger.info("Queried order %s with status %s", order_id, self._extract_status(payload))
        return payload

    def query_order_external(self, external_id: str) -> Dict[str, Any]:
        """Retrieve an order status using the merchant external identifier.

        Args:
            external_id: Merchant-side identifier registered in Niubiz.

        Returns:
            Dict[str, Any]: Raw order payload augmented with ``success`` and ``access_token`` when
            successful. Possible states include ``PENDING``, ``COMPLETED``, ``CANCELED`` and
            ``EXPIRED``.

        Raises:
            ValueError: If ``external_id`` is empty.
        """
        if not external_id:
            raise ValueError(_("The Niubiz external order ID cannot be empty."))

        url = ORDER_QUERY_EXTERNAL_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id, external_id=external_id)
        token = self._ensure_token()
        headers = {"Authorization": token, "Accept": "application/json"}

        result = self._perform_request("GET", url, headers=headers,
                                       error_message=_("Failed to query Niubiz order by external ID."))
        if not result["success"]:
            logger.error("Failed to query external order %s: %s", external_id, result.get("error"))
            return result

        payload = _safe_json(result["response"])
        payload.setdefault("success", True)
        payload["access_token"] = token
        logger.info("Queried external order %s with status %s", external_id, self._extract_status(payload))
        return payload

    def query_order_batch(self, batch_id: str) -> Dict[str, Any]:
        """Retrieve information about a batch of orders.

        Args:
            batch_id: Identifier of the batch registered in Niubiz.

        Returns:
            Dict[str, Any]: Raw batch payload augmented with ``success`` and ``access_token`` when
            successful. Order states within the batch may include ``PENDING``, ``COMPLETED``,
            ``CANCELED`` and ``EXPIRED``.

        Raises:
            ValueError: If ``batch_id`` is empty.
        """
        if not batch_id:
            raise ValueError(_("The Niubiz batch ID cannot be empty."))

        url = ORDER_BATCH_QUERY_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id, batch_id=batch_id)
        token = self._ensure_token()
        headers = {"Authorization": token, "Accept": "application/json"}

        result = self._perform_request("GET", url, headers=headers,
                                       error_message=_("Failed to query Niubiz order batch."))
        if not result["success"]:
            logger.error("Failed to query order batch %s: %s", batch_id, result.get("error"))
            return result

        payload = _safe_json(result["response"])
        payload.setdefault("success", True)
        payload["access_token"] = token
        logger.info("Queried order batch %s with status %s", batch_id, self._extract_status(payload))
        return payload

    # ------------------------------------------------------------------
    # Extras: Yape, PagoEfectivo, BIN, Antifraud, Tokenization
    # ------------------------------------------------------------------
    def yape_transaction(self, *, phone: str, otp: str, amount: Any, purchase_number: str, currency: str) -> Dict[str, Any]:
        """Process a Yape transaction via Niubiz.

        Args:
            phone: Customer phone number associated with Yape.
            otp: One-time password generated by Yape.
            amount: Monetary amount to charge.
            purchase_number: Merchant purchase identifier.
            currency: ISO currency code.

        Returns:
            Dict[str, Any]: Normalized transaction data with fields like ``status``, ``action_code``
            and ``transaction_id`` when successful. Yape transactions share the same Niubiz states
            ``P`` (pending), ``E`` (error), ``S`` (success) or ``T`` (timeout).
        """
        url = YAPE_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {"Content-Type": "application/json", "Authorization": token}
        body = {
            "channel": "yape",
            "order": {"purchaseNumber": purchase_number, "amount": float(amount), "currency": currency},
            "dataMap": {"phoneNumber": phone, "otp": otp},
        }

        result = self._perform_request("POST", url, headers=headers, json=body,
                                       error_message=_("Failed to process the Yape transaction."))
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        return normalized

    def pagoefectivo_transaction(
        self, *, amount: Any, purchase_number: str, currency: str,
        expiration_minutes: int = 1440, customer_email: Optional[str] = None, customer_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a PagoEfectivo voucher through Niubiz.

        Args:
            amount: Monetary amount to charge.
            purchase_number: Merchant purchase identifier.
            currency: ISO currency code.
            expiration_minutes: Validity of the voucher in minutes.
            customer_email: Optional email for the customer.
            customer_name: Optional name of the customer.

        Returns:
            Dict[str, Any]: Normalized transaction data with keys such as ``status``, ``action_code``
            and ``transaction_id`` when successful. The status follows Niubiz values ``P`` (pending),
            ``E`` (error), ``S`` (success) or ``T`` (timeout).
        """
        url = PAGOEFECTIVO_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {"Content-Type": "application/json", "Authorization": token}
        body: Dict[str, Any] = {
            "channel": "pagoefectivo",
            "order": {"purchaseNumber": purchase_number, "amount": float(amount), "currency": currency},
            "dataMap": {"timeLimitInMinutes": expiration_minutes},
        }
        if customer_email:
            body["dataMap"]["customerEmail"] = customer_email
        if customer_name:
            body["dataMap"]["customerName"] = customer_name

        result = self._perform_request("POST", url, headers=headers, json=body,
                                       error_message=_("Failed to create the PagoEfectivo transaction."))
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        return normalized

    def bin_lookup(self, *, bin_number: str) -> Dict[str, Any]:
        """Retrieve BIN information from Niubiz.

        Args:
            bin_number: Bank identification number to look up.

        Returns:
            Dict[str, Any]: Response payload containing card brand and additional metadata together
            with ``success`` and ``access_token`` when successful.
        """
        url = BIN_LOOKUP_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id, bin_number=bin_number)
        token = self._ensure_token()
        headers = {"Authorization": token, "Accept": "application/json"}

        result = self._perform_request("GET", url, headers=headers,
                                       error_message=_("Failed to perform the BIN lookup."))
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        payload.setdefault("success", True)
        payload["access_token"] = token
        return payload

    def antifraud_check(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the Niubiz antifraud validation service.

        Args:
            data: Antifraud payload expected by Niubiz.

        Returns:
            Dict[str, Any]: Response payload including ``success`` and ``access_token`` when
            successful, along with antifraud evaluation results.
        """
        url = ANTIFRAUD_ENDPOINTS[self.endpoint]
        token = self._ensure_token()
        headers = {"Content-Type": "application/json", "Authorization": token}

        result = self._perform_request("POST", url, headers=headers, json=data,
                                       error_message=_("Failed to execute the Niubiz antifraud check."))
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        payload.setdefault("success", True)
        payload["access_token"] = token
        return payload

    def tokenize_card(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Tokenize a card through Niubiz.

        Args:
            data: Card information payload as expected by Niubiz.

        Returns:
            Dict[str, Any]: Response payload including the generated token, ``success`` and
            ``access_token`` on success.
        """
        url = TOKENIZE_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {"Content-Type": "application/json", "Authorization": token}

        result = self._perform_request("POST", url, headers=headers, json=data,
                                       error_message=_("Failed to tokenize the card with Niubiz."))
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        payload.setdefault("success", True)
        payload["access_token"] = token
        return payload

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _ensure_token(self) -> str:
        cached = _TOKEN_CACHE.get(self.merchant_id, self.access_key, self.secret_key, self.endpoint)
        if cached:
            return cached.token

        result = self.get_security_token()
        if not result.get("success"):
            message = result.get("error") or "Niubiz security token not available"
            raise RuntimeError(message)
        return result["token"]

    def _perform_request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        error_message: str,
        allow_token_refresh: bool = True,
        include_token: bool = True,
    ) -> Dict[str, Any]:
        headers = headers or {}
        sanitized_headers = {k: ("***" if k.lower() == "authorization" else v) for k, v in headers.items()}
        sanitized_json = _sanitize_payload(deepcopy(json)) if isinstance(json, dict) else None
        logger.info("Calling Niubiz API %s %s headers=%s body=%s", method.upper(), url, sanitized_headers, sanitized_json)

        try:
            response = self._http.request(method.upper(), url, headers=headers, json=json, timeout=self.timeout)
            response.raise_for_status()
        except requests.Timeout:
            return {"success": False, "error": _("The Niubiz service did not respond in time. Please try again."), "timeout": True}
        except requests.HTTPError as exc:
            response = exc.response
            payload = _safe_json(response) if response is not None else {}
            status_code = response.status_code if response is not None else None
            if allow_token_refresh and include_token and status_code == 401:
                self.clear_cached_token()
                refreshed = self.get_security_token(force_refresh=True)
                if refreshed.get("success"):
                    headers = dict(headers)
                    headers["Authorization"] = refreshed["token"]
                    return self._perform_request(
                        method, url, headers=headers, json=json,
                        error_message=error_message, allow_token_refresh=False, include_token=include_token,
                    )
                payload.setdefault("token_expired", True)
            message = _extract_error_message(response) if response is not None else ""
            formatted = f"{error_message} [HTTP {status_code}] - {message}" if message else f"{error_message} [HTTP {status_code}]"
            return {"success": False, "error": formatted, "status_code": status_code, "payload": payload}
        except requests.RequestException:
            return {"success": False, "error": _("Could not communicate with Niubiz. Please try again later.")}

        return {"success": True, "response": response}

    @staticmethod
    def _parse_expiration(payload: Dict[str, Any]) -> Optional[datetime]:
        expires_in = payload.get("expiresIn") or payload.get("expires_in")
        if expires_in:
            try:
                return datetime.now(timezone.utc) + timedelta(seconds=float(expires_in))
            except (TypeError, ValueError):
                pass
        expires_at = payload.get("expiresAt") or payload.get("expirationDate")
        if isinstance(expires_at, (int, float)):
            try:
                return datetime.fromtimestamp(float(expires_at), tz=timezone.utc)
            except (TypeError, ValueError, OSError):
                return None
        if isinstance(expires_at, str):
            try:
                parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        return None

    @staticmethod
    def _extract_status(payload: Dict[str, Any]) -> Optional[str]:
        if not isinstance(payload, dict):
            return None
        for key in ("status", "statusOrder", "STATUS"):
            if payload.get(key):
                return str(payload[key])
        order = payload.get("order") if isinstance(payload.get("order"), dict) else {}
        if order:
            for key in ("status", "STATUS"):
                if order.get(key):
                    return str(order[key])
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        if data:
            for key in ("status", "STATUS"):
                if data.get(key):
                    return str(data[key])
        return None

    @staticmethod
    def _normalize_transaction_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        order = data.get("order") if isinstance(data.get("order"), dict) else {}
        card = data.get("card") or data.get("CARD") or {}
        if not isinstance(card, dict):
            card = {}
        antifraud = data.get("antifraud") or data.get("ANTIFRAUD") or {}
        if not isinstance(antifraud, dict):
            antifraud = {}

        def _get(*keys: str) -> Optional[str]:
            for key in keys:
                if key in data and data[key] is not None:
                    return str(data[key])
                if key in order and order[key] is not None:
                    return str(order[key])
            return None

        return {
            "success": True,
            "status": _get("STATUS", "status") or payload.get("status"),
            "action_code": _get("ACTION_CODE", "actionCode") or payload.get("actionCode"),
            "authorization_code": _get("AUTHORIZATION_CODE", "authorizationCode"),
            "trace_number": _get("TRACE_NUMBER", "traceNumber"),
            "transaction_id": _get("TRANSACTION_ID", "transactionId") or payload.get("transactionId"),
            "brand": card.get("BRAND") or card.get("brand") or data.get("brand"),
            "masked_card": card.get("PAN") or card.get("pan") or card.get("maskedCard"),
            "eci": data.get("ECI") or data.get("eci"),
            "antifraud": antifraud or None,
            "data": payload,
        }


def clear_token_cache() -> None:
    _TOKEN_CACHE.clear()
