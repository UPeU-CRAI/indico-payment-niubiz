"""Cliente HTTP para integrar con la API de Niubiz.

Encapsula autenticación, ejecución de requests y operaciones
de pago/reembolso para ser usado por el plugin Indico.
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal
from typing import Any, Dict, Optional

import requests
from requests import Response
from werkzeug.exceptions import BadRequest

from indico_payment_niubiz.schema import AmountCurrency, CheckoutSession, OrderStatus, RefundResponse

logger = logging.getLogger(__name__)


class NiubizClientError(Exception):
    """Excepción base para errores del cliente Niubiz."""


class NiubizAuthError(NiubizClientError):
    """Error en autenticación con Niubiz."""


class NiubizAPIError(NiubizClientError):
    """Error en respuesta de la API de Niubiz."""


class NiubizClient:
    """Cliente para la API de Niubiz."""

    BASE_URLS = {
        "sandbox": "https://apitestenv.vnforapps.com",
        "prod": "https://apiprod.vnforapps.com",
    }

    def __init__(self, merchant_id: str, access_key: str, secret_key: str, endpoint: str = "sandbox") -> None:
        if endpoint not in self.BASE_URLS:
            raise ValueError(f"Endpoint desconocido: {endpoint}")
        self.merchant_id = merchant_id
        self.access_key = access_key
        self.secret_key = secret_key
        self.endpoint = endpoint
        self.base_url = self.BASE_URLS[endpoint]
        self._session_token: Optional[str] = None
        self._session_expiry: Optional[float] = None

    # ------------------ Autenticación ------------------
    def _get_session_token(self) -> str:
        """Obtiene un session token válido desde Niubiz (con caching temporal)."""
        now = time.time()
        if self._session_token and self._session_expiry and now < self._session_expiry:
            return self._session_token

        url = f"{self.base_url}/api.security/v1/security"
        try:
            response = requests.post(url, auth=(self.access_key, self.secret_key), timeout=15)
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.error("Error de conexión al autenticarse con Niubiz: %s", exc)
            raise NiubizAuthError("No se pudo autenticar con Niubiz") from exc

        token = response.text.strip().strip('"')
        if not token:
            logger.error("Respuesta vacía al autenticar con Niubiz")
            raise NiubizAuthError("Niubiz no devolvió token válido")

        self._session_token = token
        self._session_expiry = now + 300  # tokens duran 5 min
        return token

    # ------------------ HTTP genérico ------------------
    def _request(self, method: str, path: str, *, json: Optional[Dict[str, Any]] = None) -> Response:
        """Ejecuta un request autenticado contra Niubiz con reintento ante 401."""
        url = f"{self.base_url}{path}"
        last_exc: Optional[Exception] = None

        for attempt in range(2):
            headers = {"Authorization": self._get_session_token()}
            try:
                response = requests.request(method, url, headers=headers, json=json, timeout=20)
                if response.status_code == 401 and attempt == 0:
                    # Token expirado: limpiar cache y reintentar una vez.
                    logger.info("Token Niubiz expirado; reintentando autenticación")
                    self._session_token = None
                    self._session_expiry = None
                    continue
                response.raise_for_status()
                return response
            except requests.HTTPError as exc:
                last_exc = exc
                logger.warning(
                    "Error HTTP %s en Niubiz: %s",
                    exc.response.status_code if exc.response else "?",
                    exc,
                )
                break
            except requests.RequestException as exc:
                last_exc = exc
                logger.error("Error de red en request Niubiz: %s", exc)
                break

        if isinstance(last_exc, requests.HTTPError):
            raise NiubizAPIError(f"Error de API Niubiz: {last_exc}") from last_exc
        if last_exc:
            raise NiubizClientError("Error de red al llamar Niubiz") from last_exc
        raise NiubizClientError("No se pudo completar la petición Niubiz")

    # ------------------ API pública ------------------
    def get_auth_token(self) -> str:
        """Expone públicamente la obtención del session token (para tests/usos externos)."""
        return self._get_session_token()

    # ------------------ Helpers ------------------
    @staticmethod
    def _normalize_amount(amount: Decimal | float | str) -> str:
        """Convierte el monto a string con 2 decimales para Niubiz."""
        if isinstance(amount, Decimal):
            return f"{amount:.2f}"
        try:
            return f"{Decimal(str(amount)):.2f}"
        except Exception as exc:
            raise BadRequest(f"Monto inválido: {amount}") from exc

    # ------------------ Órdenes ------------------
    def _validate_amount_currency(self, amount: Decimal, currency: str) -> AmountCurrency:
        return AmountCurrency(amount=amount, currency=currency)

    def create_order(
        self,
        amount: Decimal,
        currency: str,
        purchase_number: str,
        *,
        channel: str = "web",
        data: Optional[Dict[str, Any]] = None,
    ) -> CheckoutSession:
        """Crea una orden de pago en Niubiz."""
        validated = self._validate_amount_currency(amount, currency)
        path = f"/api.ecommerce/v2/ecommerce/token/session/{self.merchant_id}"
        payload = {
            "channel": channel,
            "amount": self._normalize_amount(validated.amount),
            "currency": validated.currency,
            "purchaseNumber": purchase_number,
        }
        if data:
            payload.update(data)

        logger.debug("Creando orden Niubiz: %r", payload)
        response = self._request("POST", path, json=payload)
        try:
            result = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Niubiz devolvió respuesta no JSON al crear orden") from exc

        session_key = result.get("sessionKey") or result.get("sessionkey")
        if not session_key:
            raise NiubizAPIError("Niubiz no devolvió sessionKey para la orden")

        logger.info("Orden Niubiz creada purchase=%s, txn=%s", purchase_number, session_key)
        return CheckoutSession(
            session_key=str(session_key),
            amount=validated.amount,
            currency=validated.currency,
            purchase_number=purchase_number,
            raw=result,
        )

    def get_order_status(self, order_id: str) -> OrderStatus:
        """Consulta el estado de una orden en Niubiz."""
        path = f"/api.ecommerce/v2/ecommerce/token/order/{self.merchant_id}/{order_id}"
        response = self._request("GET", path)
        try:
            result = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Respuesta inválida al consultar estado de orden Niubiz") from exc

        logger.info("Estado de orden Niubiz consultado order_id=%s, status=%s", order_id, result.get("status"))
        status_value = result.get("status")
        return OrderStatus(success=status_value is not None, status=status_value, data=result)

    # ------------------ Reembolsos ------------------
    def refund_transaction(
        self,
        transaction_id: str,
        amount: Decimal,
        currency: str,
        reason: Optional[str] = None,
    ) -> RefundResponse:
        """Solicita un reembolso en Niubiz."""
        validated = self._validate_amount_currency(amount, currency)
        path = f"/api.ecommerce/v2/ecommerce/token/{self.merchant_id}/refund"
        payload = {
            "orderId": transaction_id,
            "amount": self._normalize_amount(validated.amount),
            "currency": validated.currency,
        }
        if reason:
            payload["reason"] = reason

        logger.debug("Solicitando reembolso Niubiz: %r", payload)
        response = self._request("POST", path, json=payload)
        try:
            result = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Respuesta inválida al solicitar reembolso Niubiz") from exc

        status_value = result.get("status")
        success = str(status_value or "").upper() in {"REFUNDED", "VOIDED"}
        logger.info("Reembolso Niubiz %s para txn=%s", "OK" if success else "fallido", transaction_id)
        return RefundResponse(
            success=success,
            status=status_value,
            transaction_id=result.get("transactionId") or transaction_id,
            action="refund",
            data=result,
        )

    # ------------------ Captura ------------------
    def capture_payment(self, transaction_id: str, amount: Optional[Decimal] = None) -> RefundResponse:
        """Confirma/captura un pago previamente autorizado en Niubiz."""
        path = f"/api.authorization/v3/authorization/{self.merchant_id}/capture"
        payload: Dict[str, Any] = {"transactionId": transaction_id}
        if amount is not None:
            payload["amount"] = self._normalize_amount(amount)

        logger.debug("Capturando pago Niubiz: %r", payload)
        response = self._request("POST", path, json=payload)
        try:
            result = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Respuesta inválida al capturar pago Niubiz") from exc

        status_value = result.get("status")
        logger.info("Captura Niubiz txn=%s status=%s", transaction_id, status_value)
        return RefundResponse(
            success=str(status_value or "").upper() == "CAPTURED",
            status=status_value,
            transaction_id=result.get("transactionId") or transaction_id,
            action="capture",
            data=result,
        )

    # ------------------ Anulación ------------------
    def void_payment(self, transaction_id: str, reason: Optional[str] = None) -> RefundResponse:
        """Anula un pago autorizado en Niubiz."""
        path = f"/api.authorization/v3/authorization/{self.merchant_id}/void"
        payload: Dict[str, Any] = {"transactionId": transaction_id}
        if reason:
            payload["reason"] = reason

        logger.debug("Anulando pago Niubiz: %r", payload)
        response = self._request("POST", path, json=payload)
        try:
            result = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Respuesta inválida al anular pago Niubiz") from exc

        status_value = result.get("status")
        success = str(status_value or "").upper() == "VOIDED"
        logger.info("Anulación Niubiz %s txn=%s", "OK" if success else "fallida", transaction_id)
        return RefundResponse(
            success=success,
            status=status_value,
            transaction_id=result.get("transactionId") or transaction_id,
            action="void",
            data=result,
        )

    def reverse_payment(
        self,
        transaction_id: str,
        amount: Decimal,
        currency: str,
        reason: Optional[str] = None,
    ) -> RefundResponse:
        """Intenta reembolsar y, si falla, anula la transacción."""

        refund_result = self.refund_transaction(
            transaction_id=transaction_id,
            amount=amount,
            currency=currency,
            reason=reason,
        )
        if refund_result.success:
            return refund_result

        void_result = self.void_payment(transaction_id, reason=reason)
        combined_data = {
            "refund": refund_result.data,
            "void": void_result.data,
        }
        return RefundResponse(
            success=void_result.success,
            status=void_result.status or refund_result.status,
            transaction_id=void_result.transaction_id or refund_result.transaction_id,
            action="void" if void_result.success else refund_result.action,
            data=combined_data,
        )
