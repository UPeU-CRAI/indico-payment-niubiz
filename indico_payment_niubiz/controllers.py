"""HTTP handlers for the Niubiz payment workflow."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any, Dict, Optional

from flask import flash, redirect, render_template, request
from flask_pluginengine import current_plugin
from werkzeug.exceptions import BadRequest, Forbidden

from indico.modules.events.payment.models.transactions import TransactionStatus
from indico.modules.events.registration.models.registrations import Registration
from indico.modules.logs.models.entries import LogKind
from indico.web.flask.util import url_for
from indico.web.rh import RH

from indico_payment_niubiz import _
from indico_payment_niubiz.client import NiubizClient
from indico_payment_niubiz.indico_integration import (
    build_transaction_data,
    handle_failed_payment,
    handle_successful_payment,
    log_registration_event,
    parse_amount,
)
from indico_payment_niubiz.settings import (
    get_credentials_for_event,
    get_endpoint_for_event,
    get_merchant_id_for_event,
    get_scoped_setting,
)
from indico_payment_niubiz.util import (
    DEFAULT_CALLBACK_IPS,
    get_checkout_script_url,
    ip_in_whitelist,
    map_action_code_to_status,
    parse_ip_list,
)


logger = logging.getLogger(__name__)

SUCCESS_CODES = {"000"}
CANCELLED_STATUS_VALUES = {"cancelled", "canceled", "cancelado", "cancelada"}
EXPIRED_STATUS_VALUES = {"expired", "expirada", "expirado"}


def _sanitize_log_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = {}
    for key, value in payload.items():
        if key.lower() in {"token", "accesstoken", "authorization"}:
            sanitized[key] = "***"
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_log_payload(value)
        else:
            sanitized[key] = value
    return sanitized


class RHNiubizBase(RH):
    CSRF_ENABLED = False

    def _process_args(self):
        self.event_id = request.view_args["event_id"]
        self.reg_form_id = request.view_args["reg_form_id"]

        token = request.args.get("token") or request.form.get("token")
        reg_id = (
            request.view_args.get("reg_id")
            or request.form.get("reg_id")
            or request.args.get("reg_id")
        )

        registration: Optional[Registration] = None
        if token:
            registration = Registration.query.filter_by(uuid=token).first()
        elif reg_id is not None:
            try:
                reg_id_int = int(reg_id)
            except (TypeError, ValueError):
                raise BadRequest
            registration = Registration.query.get(reg_id_int)

        if not registration or registration.event_id != self.event_id or registration.registration_form_id != self.reg_form_id:
            raise BadRequest

        self.registration = registration
        self.event = registration.event
        self._client: Optional[NiubizClient] = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _get_endpoint(self) -> str:
        return get_endpoint_for_event(self.event)

    def _get_scoped_setting(self, name: str):
        return get_scoped_setting(self.event, name)

    def _get_credentials(self):
        return get_credentials_for_event(self.event)

    def _get_merchant_id(self):
        return get_merchant_id_for_event(self.event)

    def _get_amount(self):
        return self.registration.price

    def _get_currency(self):
        return self.registration.currency or "PEN"

    def _get_purchase_number(self):
        return f"{self.registration.event_id}-{self.registration.id}"

    def _get_client_ip(self):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip() or (request.remote_addr or "127.0.0.1")
        return request.remote_addr or "127.0.0.1"

    def _get_client_id(self):
        email = getattr(self.registration, "email", None)
        if email:
            return str(email)
        return f"indico-registration-{self.registration.id}"

    def _get_customer_email(self):
        email = getattr(self.registration, "email", None)
        if email:
            return str(email)
        user = getattr(self.registration, "user", None)
        if user is not None:
            user_email = getattr(user, "email", None)
            if user_email:
                return str(user_email)
        return None

    def _build_client(self) -> NiubizClient:
        if self._client is None:
            access_key, secret_key = self._get_credentials()
            self._client = NiubizClient(
                merchant_id=self._get_merchant_id(),
                access_key=access_key,
                secret_key=secret_key,
                endpoint=self._get_endpoint(),
            )
        return self._client

    def _log_step(self, summary: str, *, payload: Optional[Dict[str, Any]] = None, kind: LogKind = LogKind.change) -> None:
        log_registration_event(
            self.registration,
            summary,
            kind=kind,
            data=_sanitize_log_payload(payload or {}),
        )

    def _get_checkout_button_color(self):
        return self._get_scoped_setting("button_color")

    def _get_merchant_logo_url(self):
        return self._get_scoped_setting("merchant_logo_url")

    def _get_checkout_script(self):
        endpoint = self._get_endpoint()
        return get_checkout_script_url(endpoint)

    def _is_tokenization_enabled(self) -> bool:
        value = self._get_scoped_setting("enable_tokenization")
        if isinstance(value, str):
            return value == "1"
        return bool(value)

    def _load_merchant_defined_data(self, raw_value):
        if not raw_value:
            return {}
        try:
            parsed = json.loads(raw_value)
        except (TypeError, ValueError):
            logger.warning("Invalid Niubiz merchant defined data configuration. Value=%s", raw_value)
            return {}
        if not isinstance(parsed, dict):
            logger.warning("Niubiz merchant defined data configuration must be a JSON object. Value=%s", raw_value)
            return {}

        registration = self.registration
        context: Dict[str, Any] = {
            "registration_id": getattr(registration, "id", ""),
            "registration_uuid": getattr(registration, "uuid", ""),
            "event_id": getattr(self.event, "id", ""),
            "amount": self._get_amount(),
            "currency": self._get_currency(),
        }
        for attr, key in (
            ("email", "registration_email"),
            ("phone", "registration_phone"),
            ("company", "registration_company"),
            ("full_name", "registration_name"),
        ):
            value = getattr(registration, attr, None)
            if value:
                context[key] = value

        class _SafeDict(dict):
            def __missing__(self, key):
                return ""

        result = {}
        for key, value in parsed.items():
            if value in (None, ""):
                continue
            key_str = str(key)
            try:
                formatted = str(value).format_map(_SafeDict(context))
            except Exception:
                logger.warning("Could not format Niubiz MDD value for key %s", key_str, exc_info=True)
                formatted = str(value)
            formatted = formatted.strip()
            if formatted:
                result[key_str] = formatted
        return result

    def _get_merchant_defined_data(self):
        raw_value = self._get_scoped_setting("merchant_defined_data")
        return self._load_merchant_defined_data(raw_value)


class RHNiubizStart(RHNiubizBase):
    def _process(self):
        redirect_url = url_for("event_registration.display_regform", self.registration.locator.registrant)
        client = self._build_client()

        token_result = client.get_security_token()
        if not token_result.get("success"):
            flash(token_result.get("error") or _("No se pudo obtener el token de seguridad de Niubiz."), "error")
            return redirect(redirect_url)

        self._log_step(
            _("Token de seguridad de Niubiz obtenido."),
            payload={"expires_at": token_result.get("expires_at"), "cached": token_result.get("cached")},
            kind=LogKind.positive,
        )

        merchant_defined_data = self._get_merchant_defined_data()
        client_id = self._get_client_id()

        session_result = client.create_session_token(
            amount=self._get_amount(),
            purchase_number=self._get_purchase_number(),
            currency=self._get_currency(),
            antifraud_data={"clientIp": self._get_client_ip(), "merchantDefineData": merchant_defined_data} if merchant_defined_data else {"clientIp": self._get_client_ip()},
            customer_email=self._get_customer_email(),
            client_id=client_id,
        )

        if not session_result.get("success"):
            flash(session_result.get("error") or _("No se pudo iniciar el checkout de Niubiz."), "error")
            return redirect(redirect_url)

        self._log_step(
            _("Sesión de checkout de Niubiz creada."),
            payload={"session_key": session_result.get("session_key"), "expiration": session_result.get("expiration_time")},
        )

        context = {
            "registration": self.registration,
            "event": self.event,
            "amount": self._get_amount(),
            "amount_value": float(self._get_amount()),
            "currency": self._get_currency(),
            "merchant_id": self._get_merchant_id(),
            "purchase_number": self._get_purchase_number(),
            "sessionKey": session_result.get("session_key"),
            "checkout_js_url": self._get_checkout_script(),
            "merchant_logo_url": self._get_merchant_logo_url(),
            "checkout_button_color": self._get_checkout_button_color(),
            "session_expiration": session_result.get("expiration_time"),
            "cancel_url": url_for(
                "payment_niubiz.cancel",
                event_id=self.event.id,
                reg_form_id=self.registration.registration_form.id,
                reg_id=self.registration.id,
            ),
        }
        return render_template("payment_niubiz/event_payment_form.html", **context)


class RHNiubizSuccess(RHNiubizBase):
    def _process(self):
        transaction_token = request.form.get("transactionToken") or request.args.get("transactionToken")
        if not transaction_token and request.is_json:
            transaction_token = (request.json or {}).get("transactionToken")
        if not transaction_token:
            raise BadRequest(_("Falta el token de transacción de Niubiz."))

        redirect_url = url_for("event_registration.display_regform", self.registration.locator.registrant)
        client = self._build_client()

        amount_decimal = parse_amount(self._get_amount(), None)
        currency = self._get_currency()

        authorization = client.authorize_transaction(
            transaction_token=transaction_token,
            purchase_number=self._get_purchase_number(),
            amount=self._get_amount(),
            currency=currency,
            client_ip=self._get_client_ip(),
            client_id=self._get_client_id(),
        )

        if not authorization.get("success"):
            flash(authorization.get("error") or _("Niubiz no pudo confirmar el pago. Inténtalo nuevamente."), "error")
            return redirect(redirect_url)

        self._log_step(
            _("Transacción Niubiz autorizada."),
            payload={
                "status": authorization.get("status"),
                "action_code": authorization.get("action_code"),
                "authorization_code": authorization.get("authorization_code"),
                "transaction_id": authorization.get("transaction_id"),
            },
        )

        transaction_id = authorization.get("transaction_id")
        confirmation = None
        confirmation_status = None
        if transaction_id:
            confirmation = client.confirm_transaction(transaction_id=transaction_id)
            if confirmation.get("success"):
                confirmation_status = confirmation.get("status")
                self._log_step(
                    _("Confirmación de Niubiz completada."),
                    payload={
                        "status": confirmation_status,
                        "action_code": confirmation.get("action_code"),
                        "authorization_code": confirmation.get("authorization_code"),
                    },
                    kind=LogKind.positive,
                )
            else:
                self._log_step(
                    _("La confirmación de Niubiz no se completó."),
                    payload={"error": confirmation.get("error"), "status": confirmation.get("status")},
                    kind=LogKind.negative,
                )

        status_label = confirmation_status or authorization.get("status") or ""
        action_code = authorization.get("action_code") or ""
        mapped_status = map_action_code_to_status(action_code, status_label)

        transaction_data = build_transaction_data(
            payload={
                "authorization": authorization.get("data"),
                "confirmation": confirmation.get("data") if isinstance(confirmation, dict) else None,
            },
            source="checkout",
            status=status_label or None,
            action_code=action_code or None,
            transaction_id=transaction_id,
            order_id=self._get_purchase_number(),
        )
        transaction_data.update(
            {
                "authorization_code": confirmation.get("authorization_code") if confirmation else authorization.get("authorization_code"),
                "trace_number": confirmation.get("trace_number") if confirmation else authorization.get("trace_number"),
                "brand": authorization.get("brand"),
                "masked_card": authorization.get("masked_card"),
                "eci": authorization.get("eci"),
                "antifraud": authorization.get("antifraud"),
                "currency": currency,
                "amount": float(amount_decimal) if amount_decimal is not None else float(self._get_amount()),
            }
        )

        if confirmation_status and confirmation_status.lower() != "confirmed":
            mapped_status = map_action_code_to_status(action_code, confirmation_status)

        if mapped_status == TransactionStatus.successful:
            handle_successful_payment(
                self.registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status_label,
                action_code=action_code,
                summary=_("Niubiz confirmó el pago."),
                data=transaction_data,
            )
            flash(_("¡Tu pago ha sido procesado con éxito!"), "success")
        else:
            kwargs = {}
            if mapped_status == TransactionStatus.cancelled:
                kwargs["cancelled"] = True
            elif mapped_status == TransactionStatus.expired:
                kwargs["expired"] = True
            handle_failed_payment(
                self.registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status_label,
                action_code=action_code,
                summary=_("Niubiz no pudo procesar el pago."),
                data=transaction_data,
                **kwargs,
            )
            code_value = action_code or _("desconocido")
            flash(
                _("Niubiz rechazó tu pago (código {code}).").format(code=code_value),
                "error",
            )

        store_token_flag = request.form.get("storeToken") or request.args.get("storeToken")
        if store_token_flag and self._is_tokenization_enabled() and transaction_id:
            token_result = client.tokenize_card({"transactionId": transaction_id})
            if token_result.get("success"):
                token_value = token_result.get("data", {}).get("token") or token_result.get("token")
                if token_value:
                    try:
                        current_plugin.store_token(self.registration.user, token_value, token_result.get("data", {}))  # type: ignore[attr-defined]
                        self._log_step(
                            _("Tarjeta tokenizada en Niubiz."),
                            payload={"token": token_value, "brand": token_result.get("data", {}).get("brand")},
                            kind=LogKind.positive,
                        )
                    except Exception:  # pragma: no cover - defensive
                        logger.exception("No se pudo almacenar el token de Niubiz")
            else:
                self._log_step(
                    _("La tokenización de la tarjeta falló."),
                    payload={"error": token_result.get("error")},
                    kind=LogKind.negative,
                )

        context = {
            "registration": self.registration,
            "event": self.event,
            "amount": self._get_amount(),
            "currency": currency,
            "merchant_id": self._get_merchant_id(),
            "purchase_number": self._get_purchase_number(),
            "authorization": authorization.get("data"),
            "confirmation": confirmation.get("data") if isinstance(confirmation, dict) else None,
            "action_code": action_code or None,
            "status_token": status_label,
            "authorization_code": transaction_data.get("authorization_code"),
            "transaction_id": transaction_id,
            "masked_card": authorization.get("masked_card"),
            "card_brand": authorization.get("brand"),
            "status_label": status_label,
            "success": mapped_status == TransactionStatus.successful,
            "standalone": True,
        }
        return render_template("payment_niubiz/transaction_details.html", **context)


class RHNiubizCancel(RHNiubizBase):
    def _process(self):
        amount_decimal = parse_amount(self._get_amount(), None)
        currency = self._get_currency()
        transaction_data = build_transaction_data(
            source="cancel",
            status="CANCELLED",
            message=_("Cancelado por el usuario en el flujo de checkout."),
        )
        transaction_data["purchase_number"] = self._get_purchase_number()
        transaction_data["currency"] = currency
        if amount_decimal is not None:
            transaction_data["amount"] = float(amount_decimal)
        else:
            transaction_data["amount"] = float(self._get_amount())
        handle_failed_payment(
            self.registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=None,
            status="CANCELLED",
            action_code=None,
            summary=_("El participante canceló el pago de Niubiz."),
            data=transaction_data,
            cancelled=True,
        )
        flash(_("Pago cancelado por el usuario."), "info")
        return redirect(url_for("event_registration.display_regform", self.registration.locator.registrant))


class RHNiubizCallback(RHNiubizBase):
    def _process(self):
        if request.scheme != "https" and not request.is_secure:
            logger.warning("Niubiz callback recibido sin HTTPS. URL=%s", request.url)
            raise Forbidden

        remote_addr = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        if "," in remote_addr:
            remote_addr = remote_addr.split(",")[0].strip()

        configured = self._get_scoped_setting("callback_ip_whitelist") or ""
        configured_ips = [line.strip() for line in configured.splitlines() if line.strip()]
        networks = parse_ip_list(DEFAULT_CALLBACK_IPS + tuple(configured_ips))
        if remote_addr and not ip_in_whitelist(remote_addr, networks):
            logger.warning("Niubiz callback rechazado por IP no autorizada: %s", remote_addr)
            raise Forbidden

        expected_token = self._get_scoped_setting("callback_authorization_token")
        if expected_token:
            provided = request.headers.get("Authorization", "").strip()
            if provided.lower().startswith("bearer "):
                provided = provided[7:].strip()
            if provided != expected_token:
                logger.warning("Niubiz callback con token inválido desde %s", remote_addr)
                raise Forbidden

        hmac_secret = self._get_scoped_setting("callback_hmac_secret")
        if hmac_secret:
            signature = request.headers.get("NBZ-Signature")
            if not signature:
                logger.warning("Niubiz callback sin firma HMAC")
                raise Forbidden
            body = request.get_data(cache=True) or b""
            computed = hmac.new(hmac_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            if signature.strip().lower() != computed.lower():
                logger.warning("Firma HMAC inválida en callback de Niubiz")
                raise Forbidden

        payload = request.get_json(silent=True) or {}
        order_info = payload.get("order") if isinstance(payload.get("order"), dict) else {}
        external_id = payload.get("externalId")
        order_id = payload.get("orderId")
        purchase_number = (
            order_id
            or payload.get("purchaseNumber")
            or order_info.get("purchaseNumber")
        )
        status_value = (payload.get("statusOrder") or "").upper()
        amount_value = payload.get("amount")
        currency_value = payload.get("currency")
        transaction_id = (
            payload.get("transactionId")
            or order_info.get("transactionId")
            or payload.get("operationNumber")
        )

        logger.info(
            "Recibido callback de Niubiz (purchase=%s, status=%s, transaction=%s)",
            purchase_number,
            status_value or "UNKNOWN",
            transaction_id,
        )
        logger.debug("Payload completo de Niubiz: %s", payload)

        registration = None
        if purchase_number:
            parts = str(purchase_number).split("-", 1)
            if len(parts) == 2:
                _, reg_part = parts
                try:
                    reg_id = int(reg_part)
                except (TypeError, ValueError):
                    reg_id = None
                if reg_id is not None:
                    registration = (
                        Registration.query
                        .filter_by(id=reg_id, event_id=self.event_id, registration_form_id=self.reg_form_id)
                        .first()
                    )

        if not registration:
            logger.warning("No se pudo asociar el callback de Niubiz a una inscripción. purchase=%s", purchase_number)
            return "", 200

        amount_decimal = parse_amount(amount_value, None)
        if amount_decimal is None:
            amount_decimal = parse_amount(getattr(registration, "price", None), None)
        currency = currency_value or getattr(registration, "currency", None) or "PEN"

        transaction_data = build_transaction_data(
            payload=payload,
            source="notify",
            status=status_value or None,
            transaction_id=transaction_id,
            order_id=order_id or purchase_number,
            external_id=external_id,
        )
        if amount_decimal is not None:
            transaction_data["amount"] = float(amount_decimal)
        transaction_data["currency"] = currency

        status_lower = status_value.lower()
        if status_lower:
            if status_lower == "confirmed" or status_lower == "completed":
                handle_successful_payment(
                    registration,
                    amount=amount_decimal,
                    currency=currency,
                    transaction_id=transaction_id,
                    status=status_value,
                    action_code=None,
                    summary=_("Niubiz confirmó el pago mediante notificación."),
                    data=transaction_data,
                )
            elif status_lower in CANCELLED_STATUS_VALUES:
                handle_failed_payment(
                    registration,
                    amount=amount_decimal,
                    currency=currency,
                    transaction_id=transaction_id,
                    status=status_value,
                    action_code=None,
                    summary=_("El pago reportado por Niubiz fue cancelado."),
                    data=transaction_data,
                    cancelled=True,
                )
            elif status_lower in EXPIRED_STATUS_VALUES:
                handle_failed_payment(
                    registration,
                    amount=amount_decimal,
                    currency=currency,
                    transaction_id=transaction_id,
                    status=status_value,
                    action_code=None,
                    summary=_("El pago reportado por Niubiz expiró."),
                    data=transaction_data,
                    expired=True,
                )
            else:
                mapped_status = map_action_code_to_status("", status_lower)
                if mapped_status == TransactionStatus.successful:
                    handle_successful_payment(
                        registration,
                        amount=amount_decimal,
                        currency=currency,
                        transaction_id=transaction_id,
                        status=status_value,
                        action_code=None,
                        summary=_("Niubiz confirmó el pago mediante notificación."),
                        data=transaction_data,
                    )
                else:
                    handle_failed_payment(
                        registration,
                        amount=amount_decimal,
                        currency=currency,
                        transaction_id=transaction_id,
                        status=status_value,
                        action_code=None,
                        summary=_("Niubiz reportó un estado no exitoso."),
                        data=transaction_data,
                    )

        return "", 200
