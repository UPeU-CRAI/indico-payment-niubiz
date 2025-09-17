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

YAPE_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/yape/{merchant_id}",
    "prod": "https://apiprod.vnforapps.com/api.authorization/v3/authorization/yape/{merchant_id}",
}

PAGOEFECTIVO_ENDPOINTS = {
    "sandbox": "https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/pagoefectivo/{merchant_id}",
    "prod": "https://apiprod.vnforapps.com/api.authorization/v3/authorization/pagoefectivo/{merchant_id}",
}

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
        _TOKEN_CACHE.invalidate(self.merchant_id, self.access_key, self.secret_key, self.endpoint)

    def get_security_token(self, *, force_refresh: bool = False) -> Dict[str, Any]:
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
        url = SESSION_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": token,
        }
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
            "POST",
            url,
            headers=headers,
            json=body,
            error_message=_("Failed to create the Niubiz checkout session."),
        )
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        session_key = payload.get("sessionKey")
        if not session_key:
            logger.error("Niubiz session response did not include sessionKey")
            return {
                "success": False,
                "error": _("The Niubiz session response was invalid."),
                "payload": payload,
            }
        logger.info("Created Niubiz session for purchase %s", purchase_number or "-")
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
        url = AUTHORIZATION_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": token,
        }
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

        result = self._perform_request(
            "POST",
            url,
            headers=headers,
            json=body,
            error_message=_("Failed to authorise the Niubiz transaction."),
        )
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        return normalized

    def confirm_transaction(self, *, transaction_id: str) -> Dict[str, Any]:
        url = CONFIRMATION_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {
            "Authorization": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        body = {"transactionId": transaction_id}
        result = self._perform_request(
            "POST",
            url,
            headers=headers,
            json=body,
            error_message=_("Failed to confirm the Niubiz transaction."),
        )
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        return normalized

    def reverse_transaction(self, *, transaction_id: str, amount: Any, currency: str) -> Dict[str, Any]:
        url = REVERSAL_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": token,
        }
        body = {
            "transactionId": transaction_id,
            "amount": float(amount),
            "currency": currency,
        }
        result = self._perform_request(
            "POST",
            url,
            headers=headers,
            json=body,
            error_message=_("Failed to reverse the Niubiz transaction."),
        )
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        return normalized

    def refund_transaction(
        self,
        *,
        transaction_id: str,
        amount: Any,
        currency: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = REFUND_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id, transaction_id=transaction_id)
        token = self._ensure_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": token,
        }
        body: Dict[str, Any] = {"amount": float(amount), "currency": currency}
        if reason:
            body["reason"] = reason

        result = self._perform_request(
            "POST",
            url,
            headers=headers,
            json=body,
            error_message=_("Failed to refund the Niubiz transaction."),
        )
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        return normalized

    def yape_transaction(
        self,
        *,
        phone: str,
        otp: str,
        amount: Any,
        purchase_number: str,
        currency: str,
    ) -> Dict[str, Any]:
        url = YAPE_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": token,
        }
        body = {
            "channel": "yape",
            "order": {
                "purchaseNumber": purchase_number,
                "amount": float(amount),
                "currency": currency,
            },
            "dataMap": {
                "phoneNumber": phone,
                "otp": otp,
            },
        }
        result = self._perform_request(
            "POST",
            url,
            headers=headers,
            json=body,
            error_message=_("Failed to process the Yape transaction."),
        )
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        return normalized

    def pagoefectivo_transaction(
        self,
        *,
        amount: Any,
        purchase_number: str,
        currency: str,
        expiration_minutes: int = 1440,
        customer_email: Optional[str] = None,
        customer_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = PAGOEFECTIVO_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": token,
        }
        body: Dict[str, Any] = {
            "channel": "pagoefectivo",
            "order": {
                "purchaseNumber": purchase_number,
                "amount": float(amount),
                "currency": currency,
            },
            "dataMap": {
                "timeLimitInMinutes": expiration_minutes,
            },
        }
        if customer_email:
            body["dataMap"]["customerEmail"] = customer_email
        if customer_name:
            body["dataMap"]["customerName"] = customer_name

        result = self._perform_request(
            "POST",
            url,
            headers=headers,
            json=body,
            error_message=_("Failed to create the PagoEfectivo transaction."),
        )
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        normalized = self._normalize_transaction_payload(payload)
        normalized["access_token"] = token
        return normalized

    def bin_lookup(self, *, bin_number: str) -> Dict[str, Any]:
        url = BIN_LOOKUP_ENDPOINTS[self.endpoint].format(
            merchant_id=self.merchant_id, bin_number=bin_number
        )
        token = self._ensure_token()
        headers = {
            "Authorization": token,
            "Accept": "application/json",
        }
        result = self._perform_request(
            "GET",
            url,
            headers=headers,
            error_message=_("Failed to perform the BIN lookup."),
        )
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        payload.setdefault("success", True)
        payload["access_token"] = token
        return payload

    def antifraud_check(self, data: Dict[str, Any]) -> Dict[str, Any]:
        url = ANTIFRAUD_ENDPOINTS[self.endpoint]
        token = self._ensure_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": token,
        }
        result = self._perform_request(
            "POST",
            url,
            headers=headers,
            json=data,
            error_message=_("Failed to execute the Niubiz antifraud check."),
        )
        if not result["success"]:
            return result

        payload = _safe_json(result["response"])
        payload.setdefault("success", True)
        payload["access_token"] = token
        return payload

    def tokenize_card(self, data: Dict[str, Any]) -> Dict[str, Any]:
        url = TOKENIZE_ENDPOINTS[self.endpoint].format(merchant_id=self.merchant_id)
        token = self._ensure_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": token,
        }
        result = self._perform_request(
            "POST",
            url,
            headers=headers,
            json=data,
            error_message=_("Failed to tokenize the card with Niubiz."),
        )
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
        sanitized_headers = {
            key: ("***" if key.lower() == "authorization" else value)
            for key, value in headers.items()
        }
        sanitized_json = _sanitize_payload(deepcopy(json)) if isinstance(json, dict) else None
        logger.info(
            "Calling Niubiz API %s %s headers=%s body=%s",
            method.upper(),
            url,
            sanitized_headers,
            sanitized_json,
        )
        try:
            response = self._http.request(method.upper(), url, headers=headers, json=json, timeout=self.timeout)
            response.raise_for_status()
        except requests.Timeout:
            logger.exception("Timeout while calling Niubiz API at %s", url)
            return {
                "success": False,
                "error": _("The Niubiz service did not respond in time. Please try again."),
                "timeout": True,
            }
        except requests.HTTPError as exc:
            response = exc.response
            payload = _safe_json(response) if response is not None else {}
            status_code = response.status_code if response is not None else None
            if allow_token_refresh and include_token and status_code == 401:
                logger.warning("Niubiz security token expired (HTTP 401).")
                self.clear_cached_token()
                refreshed = self.get_security_token(force_refresh=True)
                if refreshed.get("success"):
                    headers = dict(headers)
                    headers["Authorization"] = refreshed["token"]
                    return self._perform_request(
                        method,
                        url,
                        headers=headers,
                        json=json,
                        error_message=error_message,
                        allow_token_refresh=False,
                        include_token=include_token,
                    )
                payload.setdefault("token_expired", True)
            message = _extract_error_message(response) if response is not None else ""
            if message:
                formatted = f"{error_message} [HTTP {status_code}] - {message}"
            else:
                formatted = f"{error_message} [HTTP {status_code}]"
            logger.exception("Niubiz API responded with an error: %s", formatted)
            return {
                "success": False,
                "error": formatted,
                "status_code": status_code,
                "payload": payload,
            }
        except requests.RequestException:
            logger.exception("Error while calling Niubiz API at %s", url)
            return {
                "success": False,
                "error": _("Could not communicate with Niubiz. Please try again later."),
            }

        logger.info("Niubiz API call to %s succeeded with status %s", url, response.status_code)
        return {"success": True, "response": response}

    @staticmethod
    def _parse_expiration(payload: Dict[str, Any]) -> Optional[datetime]:
        expires_in = payload.get("expiresIn") or payload.get("expires_in")
        if expires_in:
            try:
                seconds = float(expires_in)
                return datetime.now(timezone.utc) + timedelta(seconds=seconds)
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
                cleaned = expires_at.replace("Z", "+00:00")
                parsed = datetime.fromisoformat(cleaned)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                else:
                    parsed = parsed.astimezone(timezone.utc)
                return parsed
            except ValueError:
                return None
        return None

    @staticmethod
    def _extract_status(payload: Dict[str, Any]) -> Optional[str]:
        if not isinstance(payload, dict):
            return None
        for key in ("status", "statusOrder", "STATUS"):
            value = payload.get(key)
            if value:
                return str(value)
        order = payload.get("order") if isinstance(payload.get("order"), dict) else {}
        if order:
            for key in ("status", "STATUS"):
                value = order.get(key)
                if value:
                    return str(value)
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        if data:
            for key in ("status", "STATUS"):
                value = data.get(key)
                if value:
                    return str(value)
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

        action_code = (
            _get("ACTION_CODE", "actionCode")
            or payload.get("ACTION_CODE")
            or payload.get("actionCode")
        )
        status = (
            _get("STATUS", "status")
            or payload.get("STATUS")
            or payload.get("status")
        )
        authorization_code = _get("AUTHORIZATION_CODE", "authorizationCode")
        trace_number = _get("TRACE_NUMBER", "traceNumber")
        transaction_id = (
            _get("TRANSACTION_ID", "transactionId")
            or payload.get("transactionId")
            or payload.get("operationNumber")
        )
        brand = (
            card.get("BRAND")
            or card.get("brand")
            or data.get("BRAND")
            or data.get("brand")
        )
        masked_card = (
            card.get("PAN")
            or card.get("pan")
            or card.get("maskedCard")
            or data.get("PAN")
            or data.get("pan")
        )
        eci = data.get("ECI") or data.get("eci")

        normalized = {
            "success": True,
            "status": status,
            "action_code": action_code,
            "authorization_code": authorization_code,
            "trace_number": trace_number,
            "transaction_id": transaction_id,
            "brand": brand,
            "masked_card": masked_card,
            "eci": eci,
            "antifraud": antifraud or None,
            "data": payload,
        }
        return normalized


def clear_token_cache() -> None:
    _TOKEN_CACHE.clear()
