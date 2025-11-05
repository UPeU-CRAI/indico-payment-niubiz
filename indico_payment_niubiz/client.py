"""Cliente HTTP para integrar con la API NO-PCI de Niubiz.

Este módulo centraliza la lógica para autenticar con el flujo NO-PCI,
generar sesiones, verificar tokens de tarjeta, autorizar cobros y
gestionar operaciones complementarias como reembolsos. Todas las
interacciones siguen la guía oficial de Niubiz 2025.
"""

from __future__ import annotations

import base64
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
    """Cliente para la API NO-PCI de Niubiz siguiendo el flujo documentado."""

    BASE_URLS = {
        "sandbox": "https://apitestenv.vnforapps.com",
        "prod": "https://apiprod.vnforapps.com",
    }

    SECURITY_PATH = "/api.security/v1/security"

    def __init__(
        self,
        *,
        merchant_id: str,
        username: str,
        password: str,
        endpoint: str = "sandbox",
    ) -> None:
        if endpoint not in self.BASE_URLS:
            raise ValueError(f"Endpoint desconocido: {endpoint}")

        self.merchant_id = merchant_id
        self.username = username
        self.password = password
        self.endpoint = endpoint
        self.base_url = self.BASE_URLS[endpoint]

        self._security_token: Optional[str] = None
        self._security_expiry: Optional[float] = None

    # ------------------ Autenticación ------------------
    def _get_security_token(self) -> str:
        """Obtiene el ``securityToken`` usando autenticación Basic."""

        now = time.time()
        if self._security_token and self._security_expiry and now < self._security_expiry:
            return self._security_token

        credentials = f"{self.username}:{self.password}".encode("utf-8")
        encoded = base64.b64encode(credentials).decode("ascii")
        url = f"{self.base_url}{self.SECURITY_PATH}"
        headers = {
            "Authorization": f"Basic {encoded}",
            "Accept": "text/plain",
        }

        try:
            response = requests.post(url, headers=headers, timeout=20)
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.error("Error de conexión al autenticarse con Niubiz: %s", exc)
            raise NiubizAuthError("No se pudo autenticar con Niubiz") from exc

        token = response.text.strip()
        if not token:
            logger.error("Niubiz no devolvió securityToken en security")
            raise NiubizAuthError("Niubiz no devolvió token válido")

        # La documentación no indica el tiempo exacto de vida; usamos 5 minutos
        # con un margen de seguridad para evitar expiraciones en medio de un flujo.
        validity = 300 - 30
        self._security_token = token
        self._security_expiry = now + max(validity, 30)
        return token

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
                "Authorization": self._get_security_token(),
                "Accept": "application/json",
                "request-id": str(uuid4()),
                "org-code": "1",
                "client-code": "inpms",
            }
            if json is not None:
                headers["Content-Type"] = "application/json"
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
                    logger.info("securityToken Niubiz expirado; reintentando autenticación")
                    self._security_token = None
                    self._security_expiry = None
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
        """Expone públicamente el ``securityToken`` (usado en pruebas)."""

        return self._get_security_token()

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
        channel: str = "paycard",
        payment_method: Optional[str] = None,
        data_map: Optional[Dict[str, Any]] = None,
        antifraud: Optional[Dict[str, Any]] = None,
        token_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Crea una sesión de checkout en Niubiz."""

        path = f"/api.ecommerce/v2/ecommerce/token/session/{self.merchant_id}"
        payload: Dict[str, Any] = {
            "channel": channel or "paycard",
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
    def authorize_payment(
        self,
        *,
        purchase_number: str,
        amount: Decimal,
        currency: str,
        token_id: str,
        channel: str = "web",
        capture_type: str = "manual",
        countable: bool = True,
        antifraud: Optional[Dict[str, Any]] = None,
        product_id: Optional[str] = None,
        card_holder: Optional[Dict[str, Any]] = None,
        additional_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Autoriza un pago utilizando el token de tarjeta proporcionado."""

        path = f"/api.authorization/v3/authorization/ecommerce/{self.merchant_id}"
        order: Dict[str, Any] = {
            "purchaseNumber": purchase_number,
            "amount": self._normalize_amount(amount),
            "currency": currency,
            "tokenId": token_id,
        }
        if product_id:
            order["productId"] = product_id

        payload: Dict[str, Any] = {
            "captureType": capture_type,
            "channel": channel,
            "countable": bool(countable),
            "order": order,
        }

        if antifraud:
            payload["antifraud"] = antifraud
        if card_holder:
            payload["cardHolder"] = card_holder
        if additional_fields:
            payload.update(additional_fields)

        logger.debug("Autorizando pago Niubiz: %r", payload)
        response = self._request("POST", path, json=payload)
        try:
            result = response.json()
        except ValueError as exc:
            raise NiubizAPIError("Respuesta inválida al autorizar pago Niubiz") from exc

        action_code_raw = result.get("actionCode") or result.get("ACTION_CODE") or ""
        action_code = str(action_code_raw).zfill(3) if str(action_code_raw).isdigit() else str(action_code_raw)
        success = action_code == "000"

        transaction_id = result.get("transactionId") or result.get("transactionIdentifier")
        if not transaction_id:
            order_info = result.get("order") if isinstance(result.get("order"), dict) else {}
            if isinstance(order_info, dict):
                transaction_id = (
                    order_info.get("transactionId")
                    or order_info.get("TRANSACTION_ID")
                    or order_info.get("operationNumber")
                )

        logger.info(
            "Autorización Niubiz %s purchase=%s action=%s txn=%s",
            "OK" if success else "fallida",
            purchase_number,
            action_code,
            transaction_id,
        )

        return {
            "success": success,
            "data": result,
            "action_code": action_code,
            "transaction_id": transaction_id,
        }

    def push_payment(
        self,
        *,
        purchase_number: str,
        amount: Decimal,
        currency: str,
        external_transaction_id: Optional[str] = None,
        token_id: str,
        payer_email: Optional[str] = None,
        payer_name: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:  # pragma: no cover - compatibilidad
        """Compatibilidad con el API histórico ``push_payment``."""

        additional_fields = dict(kwargs.pop("additional_fields", {}) or {})
        if additional_data:
            additional_fields.update(additional_data)
        if external_transaction_id:
            additional_fields.setdefault("externalTransactionId", external_transaction_id)

        card_holder = dict(kwargs.pop("card_holder", {}) or {})
        if payer_name and "name" not in card_holder:
            card_holder["name"] = payer_name
        if payer_email and "email" not in card_holder:
            card_holder["email"] = payer_email

        antifraud = kwargs.pop("antifraud", None)

        return self.authorize_payment(
            purchase_number=purchase_number,
            amount=amount,
            currency=currency,
            token_id=token_id,
            antifraud=antifraud,
            card_holder=card_holder or None,
            additional_fields=additional_fields or None,
            **kwargs,
        )

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
