"""Cliente HTTP orientado al flujo NO-PCI de Niubiz."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional

import requests
from requests import Response

logger = logging.getLogger(__name__)


class NiubizClientError(Exception):
    """Excepción base del cliente Niubiz."""


class NiubizAuthError(NiubizClientError):
    """Error durante la autenticación contra Niubiz."""


class NiubizAPIError(NiubizClientError):
    """Error retornado por la API de Niubiz."""


@dataclass(frozen=True)
class RequestContext:
    """Información contextual sobre un request Niubiz."""

    purchase_number: Optional[str] = None
    external_transaction_id: Optional[str] = None

    @property
    def idempotency_key(self) -> Optional[str]:
        if self.purchase_number and self.external_transaction_id:
            return f"{self.purchase_number}:{self.external_transaction_id}"
        return self.purchase_number or self.external_transaction_id


class NiubizClient:
    """Cliente HTTP especializado para operaciones Niubiz."""

    BASE_URLS = {
        "sandbox": "https://apitestenv.vnforapps.com",
        "prod": "https://apiprod.vnforapps.com",
    }

    ACCESS_TOKEN_TTL = 300  # 5 minutos
    RETRIABLE_STATUS = {406, 429}

    def __init__(
        self,
        *,
        merchant_id: str,
        access_key: str,
        secret_key: str,
        endpoint: str = "sandbox",
        timeout: int = 30,
    ) -> None:
        try:
            self.base_url = self.BASE_URLS[endpoint]
        except KeyError as exc:
            raise ValueError(f"Endpoint desconocido: {endpoint}") from exc

        self.merchant_id = merchant_id
        self.access_key = access_key
        self.secret_key = secret_key
        self.timeout = timeout
        self.endpoint = endpoint

        self._access_token: Optional[str] = None
        self._token_expiry: float = 0.0

    # ------------------------------------------------------------------
    # Utilidades internas
    # ------------------------------------------------------------------
    def _sleep(self, seconds: float) -> None:
        """Wrapper para dormir (facilita el monkeypatch en tests)."""

        if seconds > 0:
            time.sleep(seconds)

    @staticmethod
    def _normalize_amount(value: Decimal | float | str | int) -> str:
        if isinstance(value, Decimal):
            quantized = value.quantize(Decimal("0.01"))
            return f"{quantized:.2f}"
        try:
            normalized = Decimal(str(value))
        except (InvalidOperation, ValueError, TypeError) as exc:
            raise NiubizClientError(f"Monto inválido: {value}") from exc
        return f"{normalized.quantize(Decimal('0.01')):.2f}"

    @staticmethod
    def _decode_token_response(response: Response) -> str:
        try:
            data = response.json()
        except ValueError:
            raw = response.text.strip().strip('"')
            if raw:
                return raw
            raise NiubizAuthError("Niubiz devolvió una respuesta vacía")

        if isinstance(data, dict):
            token = (
                data.get("accessToken")
                or data.get("token")
                or data.get("sessionKey")
                or data.get("session")
            )
            if token:
                return str(token)
        raise NiubizAuthError("Niubiz no devolvió token válido")

    @staticmethod
    def _parse_json(response: Response) -> Dict[str, Any]:
        if not response.content:
            return {}
        try:
            payload = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Respuesta no es JSON válido") from exc
        if not isinstance(payload, dict):
            raise NiubizAPIError("Respuesta JSON inesperada de Niubiz")
        return payload

    def _clear_token(self) -> None:
        self._access_token = None
        self._token_expiry = 0.0

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_payload: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        context: Optional[RequestContext] = None,
        max_attempts: int = 4,
    ) -> Response:
        url = f"{self.base_url}{path}"
        attempt = 0
        last_exc: Optional[Exception] = None
        context = context or RequestContext()
        backoff = 1.0

        while attempt < max_attempts:
            attempt += 1
            token = self.get_access_token()
            req_headers: Dict[str, str] = {
                "Authorization": token,
                "Accept": "application/json",
            }
            if json_payload is not None:
                req_headers.setdefault("Content-Type", "application/json")
            if headers:
                req_headers.update(headers)
            if context.idempotency_key:
                req_headers.setdefault("Idempotency-Key", context.idempotency_key)

            try:
                response = requests.request(
                    method,
                    url,
                    json=json_payload,
                    headers=req_headers,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                last_exc = exc
                logger.warning("Error de red al llamar Niubiz (%s %s): %s", method, path, exc)
                break

            status_code = response.status_code
            if status_code == 401:
                self._clear_token()
                if attempt < max_attempts:
                    logger.info("Token expirado, reintentando autenticación con Niubiz")
                    continue
            if status_code in self.RETRIABLE_STATUS and attempt < max_attempts:
                logger.info(
                    "Respuesta %s de Niubiz; reintentando en %.1fs (intento %s/%s)",
                    status_code,
                    backoff,
                    attempt,
                    max_attempts,
                )
                self._sleep(backoff)
                backoff *= 2
                continue

            try:
                response.raise_for_status()
                return response
            except requests.HTTPError as exc:
                last_exc = exc
                logger.error(
                    "Error HTTP %s en Niubiz para %s %s", status_code, method, path
                )
                break

        if isinstance(last_exc, requests.HTTPError):
            raise NiubizAPIError(str(last_exc)) from last_exc
        if last_exc:
            raise NiubizClientError(str(last_exc)) from last_exc
        raise NiubizClientError("No se pudo completar la petición a Niubiz")

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------
    def get_access_token(self, *, force_refresh: bool = False) -> str:
        now = time.time()
        if (
            not force_refresh
            and self._access_token
            and now < self._token_expiry
        ):
            return self._access_token

        url = f"{self.base_url}/api.security/v1/security"
        try:
            response = requests.post(
                url,
                auth=(self.access_key, self.secret_key),
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.error("No se pudo autenticar con Niubiz: %s", exc)
            raise NiubizAuthError("Error autenticando con Niubiz") from exc

        token = self._decode_token_response(response)
        self._access_token = token
        self._token_expiry = now + self.ACCESS_TOKEN_TTL
        return token

    def create_session(
        self,
        *,
        amount: Decimal | float | str | int,
        currency: str,
        purchase_number: str,
        channel: str = "web",
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "amount": self._normalize_amount(amount),
            "currency": currency.upper(),
            "purchaseNumber": purchase_number,
            "channel": channel,
        }
        if data:
            payload.update(data)
        path = f"/api.ecommerce/v2/ecommerce/token/session/{self.merchant_id}"
        response = self._request(
            "POST",
            path,
            json_payload=payload,
            context=RequestContext(purchase_number=purchase_number),
        )
        session_data = self._parse_json(response)
        logger.info(
            "Sesión Niubiz creada purchase=%s sessionKey=%s",
            purchase_number,
            session_data.get("sessionKey"),
        )
        return session_data

    def get_token_card(
        self,
        *,
        transaction_token: str,
        session_key: str,
        purchase_number: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload = {
            "transactionToken": transaction_token,
            "sessionKey": session_key,
        }
        path = f"/api.ecommerce/v2/ecommerce/token/card/{self.merchant_id}"
        response = self._request(
            "POST",
            path,
            json_payload=payload,
            context=RequestContext(purchase_number=purchase_number),
        )
        data = self._parse_json(response)
        logger.debug("Token de tarjeta Niubiz resuelto purchase=%s", purchase_number)
        return data

    def push_payment(
        self,
        *,
        amount: Decimal | float | str | int,
        currency: str,
        purchase_number: str,
        external_transaction_id: str,
        card_token: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "order": {
                "purchaseNumber": purchase_number,
                "amount": self._normalize_amount(amount),
                "currency": currency.upper(),
                "externalTransactionId": external_transaction_id,
            },
            "card": {"token": card_token},
        }
        if data:
            payload.update(data)
        path = f"/api.authorization/v3/authorization/{self.merchant_id}/push"
        response = self._request(
            "POST",
            path,
            json_payload=payload,
            context=RequestContext(
                purchase_number=purchase_number,
                external_transaction_id=external_transaction_id,
            ),
        )
        result = self._parse_json(response)
        logger.info(
            "PushPayment ejecutado purchase=%s external=%s result=%s",
            purchase_number,
            external_transaction_id,
            result.get("actionCode"),
        )
        return result

    # ------------------------------------------------------------------
    # Stubs de operaciones adicionales
    # ------------------------------------------------------------------
    def reverse_payment(self, *args, **kwargs) -> Dict[str, Any]:
        raise NotImplementedError("ReversePayment no está implementado todavía")

    def refund_payment(self, *args, **kwargs) -> Dict[str, Any]:
        raise NotImplementedError("RefundPayment no está implementado todavía")


__all__ = [
    "NiubizClient",
    "NiubizClientError",
    "NiubizAuthError",
    "NiubizAPIError",
    "RequestContext",
]
