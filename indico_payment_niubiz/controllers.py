"""HTTP handlers for the Niubiz payment workflow."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, List

from flask import flash, redirect, render_template, request
from flask_pluginengine import current_plugin
from werkzeug.exceptions import BadRequest, Forbidden

from indico.core.db import db
from indico.modules.events.payment.models.transactions import TransactionAction, TransactionStatus
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
    record_payment_transaction,
)
from indico_payment_niubiz.settings import (
    get_credentials_for_event,
    get_endpoint_for_event,
    get_merchant_id_for_event,
    get_scoped_setting,
)
from indico_payment_niubiz.util import (
    DEFAULT_CALLBACK_IPS,
    extract_callback_details,
    get_checkout_script_url,
    ip_in_whitelist,
    map_niubiz_status,
    parse_ip_list,
    validate_nbz_signature,
)


logger = logging.getLogger(__name__)


def _sanitize_log_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize sensitive keys before logging (tokens, keys, etc)."""
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

    # ------------------------------------------------------------------
    # Argumentos iniciales
    # ------------------------------------------------------------------
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

        # 1. Autorizar la transacción
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

        # 2. Confirmar la transacción
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

        # 3. Mapear estado final
        status_label = confirmation_status or authorization.get("status") or ""
        action_code = authorization.get("action_code") or ""
        mapped_details = map_niubiz_status(status=status_label, action_code=action_code)
        mapped_status = mapped_details.status

        # 4. Preparar datos de transacción
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
        if mapped_details.manual_confirmation:
            transaction_data["manual_confirmation"] = True

        if confirmation_status and confirmation_status.lower() != "confirmed":
            mapped_status = map_niubiz_status(status=confirmation_status, action_code=action_code).status

        # 5. Actualizar estado en Indico
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
            elif mapped_status == TransactionStatus.pending:
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

        # 6. Tokenización opcional
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
                    except Exception:  # pragma: no cover - defensivo
                        logger.exception("No se pudo almacenar el token de Niubiz")
            else:
                self._log_step(
                    _("La tokenización de la tarjeta falló."),
                    payload={"error": token_result.get("error")},
                    kind=LogKind.negative,
                )

        # 7. Renderizar vista de confirmación
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
    ALLOW_ANONYMOUS = True

    def _process_args(self):
        self.event_id = request.view_args.get("event_id")
        self.reg_form_id = request.view_args.get("reg_form_id")
        self.registration = None
        self.event = None
        self._client = None

    def _resolve_registration(self, purchase_number: Optional[str]) -> Optional[Registration]:
        if not purchase_number:
            return None
        parts = str(purchase_number).split("-", 1)
        if len(parts) != 2:
            return None
        try:
            reg_id = int(parts[1])
        except (TypeError, ValueError):
            return None
        return Registration.query.filter_by(
            id=reg_id,
            event_id=self.event_id,
            registration_form_id=self.reg_form_id,
        ).first()

    @staticmethod
    def _detect_callback_type(details: Dict[str, Optional[Any]]) -> str:
        channel = (details.get("channel") or "").lower()
        method = (details.get("payment_method") or "").lower()
        if details.get("cip") or "pagoefectivo" in channel or "pagoefectivo" in method:
            return "pagoefectivo"
        return "pagolink"


    @staticmethod
    def _validate_required_fields(details: Dict[str, Optional[Any]], callback_type: str) -> List[str]:
        missing: List[str] = []    
        if callback_type == "pagoefectivo":
            if not details.get("cip"):
                missing.append("cip")
            if not details.get("operation_number"):
                missing.append("operationNumber")
            if not details.get("status"):
                missing.append("status")
        else:
            if not details.get("purchase_number"):
                missing.append("purchaseNumber")
            if not details.get("transaction_id"):
                missing.append("transactionId")
            if not details.get("status"):
                missing.append("status")
        return missing

    def _build_callback_log_data(
        self,
        *,
        details: Dict[str, Optional[Any]],
        mapped_status: str,
        amount: Optional[Any],
        currency: str,
        transaction_id: Optional[str],
        manual_confirmation: bool,
    ) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "amount": float(amount) if amount is not None else None,
            "currency": currency,
            "transactionId": transaction_id,
            "transactionDate": details.get("transaction_date"),
            "status": details.get("status") or details.get("status_order"),
            "statusOrder": details.get("status_order"),
            "actionCode": details.get("action_code"),
            "actionDescription": details.get("action_description"),
            "mappedStatus": mapped_status,
        }
        if manual_confirmation:
            data["manualConfirmation"] = True
        return {key: value for key, value in data.items() if value is not None}

    def _log_callback_event(self, summary: str, kind: LogKind, data: Dict[str, Any]) -> None:
        if not self.registration:
            return
        log_registration_event(self.registration, summary, kind=kind, data=data)

    def _get_callback_secret(self) -> Optional[str]:
        secret = self._get_scoped_setting("callback_hmac_secret")
        if secret:
            return secret
        try:
            _, secret_key = self._get_credentials()
        except Exception:
            return None
        return secret_key

    def _process(self):
        if request.scheme != "https" and not request.is_secure:
            logger.warning("Niubiz callback recibido sin HTTPS. URL=%s", request.url)
            raise Forbidden

        body = request.get_data(cache=True) or b""
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            logger.warning("Niubiz callback con JSON inválido.")
            return "", 400

        details = extract_callback_details(payload)
        purchase_number = details.get("purchase_number")
        registration = self._resolve_registration(purchase_number)
        if not registration:
            logger.warning(
                "No se pudo asociar el callback de Niubiz a una inscripción. purchase=%s",
                purchase_number,
            )
            return "", 200

        self.registration = registration
        self.event = registration.event

        amount_decimal = parse_amount(details.get("amount"), None)
        if amount_decimal is None:
            amount_decimal = parse_amount(getattr(registration, "price", None), None)
        currency = details.get("currency") or getattr(registration, "currency", None) or "PEN"
        transaction_id = details.get("transaction_id") or details.get("operation_number")

        # Validar whitelist de IPs
        remote_addr = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        if "," in remote_addr:
            remote_addr = remote_addr.split(",")[0].strip()
        configured = self._get_scoped_setting("callback_ip_whitelist") or ""
        configured_ips = [line.strip() for line in configured.splitlines() if line.strip()]
        networks = parse_ip_list(DEFAULT_CALLBACK_IPS + tuple(configured_ips))
        if remote_addr and not ip_in_whitelist(remote_addr, networks):
            logger.warning("Niubiz callback rechazado por IP no autorizada: %s", remote_addr)
            raise Forbidden

        # Validar token de autorización
        expected_token = self._get_scoped_setting("callback_authorization_token")
        if expected_token:
            provided = request.headers.get("Authorization", "").strip()
            if provided.lower().startswith("bearer "):
                provided = provided[7:].strip()
            if provided != expected_token:
                log_data = self._build_callback_log_data(
                    details=details,
                    mapped_status="unauthorized",
                    amount=amount_decimal,
                    currency=currency,
                    transaction_id=transaction_id,
                    manual_confirmation=False,
                )
                summary = _("Niubiz callback rechazado por token inválido.")
                self._log_callback_event(summary, LogKind.warning, log_data)
                logger.warning("Token inválido en callback de Niubiz desde %s", remote_addr)
                return "", 401

        # Validar firma HMAC
        signature = request.headers.get("NBZ-Signature")
        secret = self._get_callback_secret()
        if secret and not signature:
            log_data = self._build_callback_log_data(
                details=details,
                mapped_status="unauthorized",
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                manual_confirmation=False,
            )
            summary = _("Niubiz callback rechazado por falta de firma.")
            self._log_callback_event(summary, LogKind.warning, log_data)
            logger.warning("Niubiz callback sin firma HMAC esperada")
            return "", 401
        if signature:
            if not secret or not validate_nbz_signature(secret, body, signature):
                log_data = self._build_callback_log_data(
                    details=details,
                    mapped_status="unauthorized",
                    amount=amount_decimal,
                    currency=currency,
                    transaction_id=transaction_id,
                    manual_confirmation=False,
                )
                summary = _("Niubiz callback rechazado por firma inválida.")
                self._log_callback_event(summary, LogKind.negative, log_data)
                logger.warning("Firma HMAC inválida en callback de Niubiz")
                return "", 401

        # Validar campos requeridos
        callback_type = self._detect_callback_type(details)
        missing = self._validate_required_fields(details, callback_type)
        if missing:
            log_data = self._build_callback_log_data(
                details=details,
                mapped_status="invalid",
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                manual_confirmation=False,
            )
            summary = _("Callback de Niubiz con campos faltantes: {fields}").format(
                fields=", ".join(missing)
            )
            self._log_callback_event(summary, LogKind.warning, log_data)
            logger.warning("Niubiz callback con campos faltantes: %s", ", ".join(missing))
            return "", 400
        # Extraer valores de estado
        status_value = details.get("status") or details.get("status_order") or ""
        normalized_status = status_value.strip()
        status_lower = normalized_status.lower()
        if status_lower in {"authorized", "confirmed"}:
            registration.set_paid(True)
            db.session.commit()
        elif status_lower in {"voided", "cancelled", "refunded"}:
            registration.set_paid(False)
            db.session.commit()
        action_code = details.get("action_code")
        action_description = details.get("action_description")
        payment_hint = details.get("payment_method") or details.get("channel")
        status_order = details.get("status_order")

        mapped = map_niubiz_status(
            status=status_value,
            action_code=action_code,
            status_order=status_order,
            payment_method=payment_hint,
            action_description=action_description,
        )

        order_id = payload.get("orderId") or details.get("purchase_number")
        external_id = payload.get("externalId")

        # Construcción de datos de transacción
        transaction_data = build_transaction_data(
            payload=payload,
            source="notify",
            status=status_value or None,
            action_code=action_code or None,
            transaction_id=transaction_id,
            order_id=order_id,
            external_id=external_id,
        )
        if amount_decimal is not None:
            transaction_data["amount"] = float(amount_decimal)
        transaction_data["currency"] = currency
        if details.get("transaction_date"):
            transaction_data["transaction_date"] = details.get("transaction_date")
        if details.get("authorization_code"):
            transaction_data["authorization_code"] = details.get("authorization_code")
        if details.get("trace_number"):
            transaction_data["trace_number"] = details.get("trace_number")
        if details.get("brand"):
            transaction_data["brand"] = details.get("brand")
        if details.get("masked_card"):
            transaction_data["masked_card"] = details.get("masked_card")
        if details.get("eci"):
            transaction_data["eci"] = details.get("eci")
        if action_description:
            transaction_data["action_description"] = action_description
        if details.get("cip"):
            transaction_data["cip"] = details.get("cip")
        if details.get("operation_number"):
            transaction_data["operation_number"] = details.get("operation_number")
        if status_order:
            transaction_data["status_order"] = status_order
        if signature:
            transaction_data["signature"] = signature
        if mapped.manual_confirmation:
            transaction_data["manual_confirmation"] = True

        # Logging del callback
        summary = _("Niubiz callback recibido — mapeado a {status}.").format(
            status=mapped.status.name
        )
        log_kind = (
            LogKind.positive
            if mapped.status == TransactionStatus.successful
            else LogKind.warning
            if mapped.status == TransactionStatus.pending
            else LogKind.change
            if mapped.status == TransactionStatus.cancelled
            else LogKind.negative
        )
        log_data = self._build_callback_log_data(
            details=details,
            mapped_status=mapped.status.name,
            amount=amount_decimal,
            currency=currency,
            transaction_id=transaction_id,
            manual_confirmation=mapped.manual_confirmation,
        )
        self._log_callback_event(summary, log_kind, log_data)

        logger.info(
            "Procesado callback de Niubiz (purchase=%s, status=%s, mapped=%s)",
            purchase_number,
            status_value or "",
            mapped.status.name,
        )

        # Procesamiento final según estado mapeado
        if mapped.status == TransactionStatus.successful:
            success_summary = _("Niubiz confirmó el pago mediante notificación.")
            if mapped.manual_confirmation:
                success_summary = _("Niubiz confirmó manualmente el pago mediante notificación.")
            handle_successful_payment(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status_value,
                action_code=action_code,
                summary=success_summary,
                data=transaction_data,
            )
        elif mapped.status == TransactionStatus.cancelled:
            handle_failed_payment(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status_value,
                action_code=action_code,
                summary=_("El pago reportado por Niubiz fue cancelado."),
                data=transaction_data,
                cancelled=True,
            )
        elif mapped.status == TransactionStatus.pending:
            record_payment_transaction(
                registration=registration,
                amount=amount_decimal if amount_decimal is not None else getattr(registration, "price", 0),
                currency=currency,
                action=TransactionAction.pending,
                data=transaction_data,
            )
        else:
            handle_failed_payment(
                registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id,
                status=status_value,
                action_code=action_code,
                summary=_("Niubiz reportó un estado no exitoso."),
                data=transaction_data,
            )

        return "", 200
