"""Cliente HTTP para integrar con la API de Niubiz (PushPayment NO-PCI).

Este módulo centraliza la lógica para autenticar con el flujo NO-PCI,
generar sesiones, verificar tokens de tarjeta, ejecutar cobros push y
gestionar operaciones complementarias como reembolsos. Todas las
interacciones siguen la guía oficial de Niubiz 2025.
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal
from typing import Any, Dict, Optional
from uuid import uuid4

import requests
from requests import Response
from werkzeug.exceptions import BadRequest

logger = logging.getLogger(__name__)


class NiubizClientError(Exception):
    """Excepción base para errores del cliente Niubiz."""


class NiubizAuthError(NiubizClientError):
    """Error en autenticación con Niubiz."""


class NiubizAPIError(NiubizClientError):
    """Error en respuesta de la API de Niubiz."""


class NiubizClient:
    """Cliente para la API de Niubiz siguiendo el flujo PushPayment NO-PCI."""

    BASE_URLS = {
        "sandbox": "https://apitestenv.vnforapps.com",
        "prod": "https://apiprod.vnforapps.com",
    }

    SECURITY_PATH = "/api.security/v1/security/push"

    def __init__(
        self,
        *,
        merchant_id: str,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        realm_code: str,
        endpoint: str = "sandbox",
    ) -> None:
        if endpoint not in self.BASE_URLS:
            raise ValueError(f"Endpoint desconocido: {endpoint}")

        self.merchant_id = merchant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.realm_code = realm_code
        self.endpoint = endpoint
        self.base_url = self.BASE_URLS[endpoint]

        self._access_token: Optional[str] = None
        self._access_expiry: Optional[float] = None

    # ------------------ Autenticación ------------------
    def _build_security_payload(self) -> Dict[str, Any]:
        return {
            "grant_type": "password",
            "scope": "*",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": self.password,
            "realm": self.realm_code,
        }

    def _get_access_token(self) -> str:
        """Obtiene un JWT válido desde el endpoint ``security/push``."""

        now = time.time()
        if self._access_token and self._access_expiry and now < self._access_expiry:
            return self._access_token

        url = f"{self.base_url}{self.SECURITY_PATH}"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "request-id": str(uuid4()),
            "org-code": "1",
            "client-code": "inpms",
        }

        try:
            response = requests.post(
                url,
                json=self._build_security_payload(),
                headers=headers,
                timeout=20,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.error("Error de conexión al autenticarse con Niubiz: %s", exc)
            raise NiubizAuthError("No se pudo autenticar con Niubiz") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            logger.error("Respuesta inválida al autenticarse con Niubiz: %s", response.text[:200])
            raise NiubizAuthError("Niubiz devolvió una respuesta no JSON al autenticarse") from exc

        token = (payload or {}).get("accessToken")
        if not token:
            logger.error("Niubiz no devolvió accessToken en security/push")
            raise NiubizAuthError("Niubiz no devolvió token válido")

        expires_in = 0
        try:
            expires_in = int(payload.get("expiresIn", 0))
        except (TypeError, ValueError):
            expires_in = 0
        # Los tokens suelen durar 5 minutos; restamos un margen de seguridad de 30 s.
        validity = max(30, expires_in - 30) if expires_in else 300
        self._access_token = str(token)
        self._access_expiry = now + validity
        return self._access_token

    # ------------------ HTTP genérico ------------------
    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Response:
        """Ejecuta un request autenticado contra Niubiz con reintento ante 401."""

        url = f"{self.base_url}{path}"
        last_exc: Optional[Exception] = None

        for attempt in range(2):
            headers = {
                "Authorization": f"Bearer {self._get_access_token()}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "request-id": str(uuid4()),
                "org-code": "1",
                "client-code": "inpms",
            }
            if extra_headers:
                headers.update(extra_headers)

            try:
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    json=json,
                    timeout=20,
                )
                if response.status_code == 401 and attempt == 0:
                    logger.info("Token Niubiz expirado; reintentando autenticación")
                    self._access_token = None
                    self._access_expiry = None
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
        """Expone públicamente la obtención del access token (usado en pruebas)."""

        return self._get_access_token()

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

    # ------------------ Sesiones ------------------
    def create_session(
        self,
        *,
        amount: Decimal,
        currency: str,
        purchase_number: str,
        channel: str = "web",
        payment_method: Optional[str] = None,
        data_map: Optional[Dict[str, Any]] = None,
        antifraud: Optional[Dict[str, Any]] = None,
        token_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Crea una sesión de checkout en Niubiz."""

        path = f"/api.ecommerce/v2/ecommerce/token/session/{self.merchant_id}"
        payload: Dict[str, Any] = {
            "channel": channel,
            "amount": self._normalize_amount(amount),
            "currency": currency,
            "purchaseNumber": purchase_number,
        }

        if payment_method:
            payload["paymentMethod"] = payment_method
        if data_map:
            payload["dataMap"] = data_map
        if antifraud:
            payload["antifraud"] = antifraud
        if token_id:
            payload["tokenId"] = token_id

        logger.debug("Creando sesión Niubiz: %r", payload)
        response = self._request("POST", path, json=payload)
        try:
            result = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Niubiz devolvió respuesta no JSON al crear sesión") from exc

        logger.info(
            "Sesión Niubiz creada purchase=%s, session=%s",
            purchase_number,
            result.get("sessionKey"),
        )
        return {"success": True, "data": result}

    # Mantener compatibilidad con código legado
    def create_order(self, *args, **kwargs):  # pragma: no cover - compatibilidad
        return self.create_session(*args, **kwargs)

    # ------------------ Tokenización ------------------
    def verify_transaction_token(self, transaction_token: str) -> Dict[str, Any]:
        """Obtiene información de la tarjeta tokenizada asociada al ``transactionToken``."""

        path = (
            f"/api.ecommerce/v2/ecommerce/token/card/{self.merchant_id}/{transaction_token}"
        )
        response = self._request("GET", path)
        try:
            result = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Respuesta inválida al verificar token de tarjeta") from exc

        return {"success": True, "data": result}

    # ------------------ Push Payment ------------------
    def push_payment(
        self,
        *,
        purchase_number: str,
        amount: Decimal,
        currency: str,
        external_transaction_id: str,
        token_id: str,
        payer_email: Optional[str] = None,
        payer_name: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Ejecuta un cobro PushPayment usando un token de tarjeta."""

        path = f"/api.instantpayments/pushpayment/{self.merchant_id}"
        payload: Dict[str, Any] = {
            "purchaseNumber": purchase_number,
            "externalTransactionId": external_transaction_id,
            "amount": self._normalize_amount(amount),
            "currency": currency,
            "recipient": {
                "tokenId": token_id,
            },
        }

        if payer_email:
            payload["recipient"]["email"] = payer_email
        if payer_name:
            payload["recipient"]["name"] = payer_name
        if additional_data:
            payload.update(additional_data)

        logger.debug("Ejecutando PushPayment Niubiz: %r", payload)
        response = self._request("POST", path, json=payload)
        try:
            result = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Respuesta inválida al ejecutar PushPayment") from exc

        success_codes = {"00", "000", "0"}
        action_code = str(result.get("actionCode") or result.get("ACTION_CODE") or "").zfill(2)
        success = action_code in success_codes
        logger.info(
            "PushPayment %s purchase=%s action=%s txn=%s",
            "OK" if success else "fallido",
            purchase_number,
            action_code,
            result.get("transactionId") or result.get("transactionIdentifier"),
        )
        return {
            "success": success,
            "data": result,
            "action_code": action_code,
            "transaction_id": result.get("transactionId")
            or result.get("transactionIdentifier")
            or result.get("operationNumber"),
        }

    # ------------------ Reembolsos ------------------
    def refund_transaction(
        self,
        transaction_id: str,
        amount: Decimal,
        currency: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Solicita un reembolso en Niubiz."""

        path = f"/api.ecommerce/v2/ecommerce/token/{self.merchant_id}/refund"
        payload = {
            "orderId": transaction_id,
            "amount": self._normalize_amount(amount),
            "currency": currency,
        }
        if reason:
            payload["reason"] = reason

        logger.debug("Solicitando reembolso Niubiz: %r", payload)
        response = self._request("POST", path, json=payload)
        try:
            result = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Respuesta inválida al solicitar reembolso Niubiz") from exc

        success = str(result.get("status", "")).upper() in {"REFUNDED", "VOIDED"}
        logger.info(
            "Reembolso Niubiz %s para txn=%s",
            "OK" if success else "fallido",
            transaction_id,
        )
        return {
            "success": success,
            "status": result.get("status"),
            "transaction_id": result.get("transactionId") or transaction_id,
            "data": result,
        }

    # ------------------ Captura ------------------
    def capture_payment(
        self,
        transaction_id: str,
        amount: Optional[Decimal] = None,
    ) -> Dict[str, Any]:
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

        logger.info("Captura Niubiz txn=%s status=%s", transaction_id, result.get("status"))
        return {
            "success": str(result.get("status", "")).upper() == "CAPTURED",
            "status": result.get("status"),
            "transaction_id": result.get("transactionId") or transaction_id,
            "data": result,
        }

    # ------------------ Anulación ------------------
    def void_payment(self, transaction_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
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

        success = str(result.get("status", "")).upper() == "VOIDED"
        logger.info(
            "Anulación Niubiz %s txn=%s",
            "OK" if success else "fallida",
            transaction_id,
        )
        return {
            "success": success,
            "status": result.get("status"),
            "transaction_id": result.get("transactionId") or transaction_id,
            "data": result,
        }
