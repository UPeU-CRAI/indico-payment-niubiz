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
        try:
            event_id_str, reg_id_str = purchase_number.split("-", 1)
            reg_id = int(reg_id_str)
        except (ValueError, TypeError):
            return None
        return Registration.query.filter_by(
            id=reg_id,
            event_id=self.event_id,
            registration_form_id=self.reg_form_id,
        ).first()

    @staticmethod
    def _detect_callback_type(details: Dict[str, Any]) -> str:
        channel = (details.get("channel") or "").lower()
        method = (details.get("payment_method") or "").lower()
        if details.get("cip") or "pagoefectivo" in channel or "pagoefectivo" in method:
            return "pagoefectivo"
        return "pagolink"

    @staticmethod
    def _validate_required_fields(details: Dict[str, Any], callback_type: str) -> List[str]:
        missing = []
        if callback_type == "pagoefectivo":
            for field in ["cip", "operation_number", "status"]:
                if not details.get(field):
                    missing.append(field)
        else:
            for field in ["purchase_number", "transaction_id", "status"]:
                if not details.get(field):
                    missing.append(field)
        return missing

    def _get_callback_secret(self) -> Optional[str]:
        secret = self._get_scoped_setting("callback_hmac_secret")
        if secret:
            return secret
        try:
            _, fallback_secret = self._get_credentials()
            return fallback_secret
        except Exception:
            return None

    def _process(self):
        # ---------- Validar HTTPS ----------
        if request.scheme != "https" and not request.is_secure:
            logger.warning("Niubiz callback recibido sin HTTPS. URL=%s", request.url)
            raise Forbidden("HTTPS requerido")

        # ---------- Leer y validar cuerpo ----------
        body = request.get_data(cache=True) or b""
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            logger.warning("Callback Niubiz con JSON inválido. Body=%s", body.decode(errors='ignore'))
            return "", 400

        # ---------- Extraer datos ----------
        details = extract_callback_details(payload)
        purchase_number = details.get("purchase_number")
        transaction_id = details.get("transaction_id") or details.get("operation_number")

        # ---------- Resolver inscripción ----------
        registration = self._resolve_registration(purchase_number)
        if not registration:
            logger.warning("No se encontró inscripción para purchaseNumber=%s", purchase_number)
            return "", 200  # No es error, se puede reenviar luego
        self.registration = registration
        self.event = registration.event

        # ---------- Validar monto/moneda ----------
        expected_amount = parse_amount(getattr(registration, "price", None), None)
        expected_currency = getattr(registration, "currency", None) or "PEN"
        received_amount = parse_amount(details.get("amount"), None)
        received_currency = details.get("currency") or "PEN"

        if received_amount is not None and expected_amount is not None:
            if float(received_amount) != float(expected_amount):
                logger.warning("Monto inconsistente en callback. Esperado=%.2f, Recibido=%.2f",
                               expected_amount, received_amount)
                return "", 400

        if received_currency != expected_currency:
            logger.warning("Moneda inconsistente en callback. Esperada=%s, Recibida=%s",
                           expected_currency, received_currency)
            return "", 400

        # ---------- Validar IP Whitelist ----------
        remote_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        if "," in remote_ip:
            remote_ip = remote_ip.split(",")[0].strip()
        allowed_ips = parse_ip_list(
            DEFAULT_CALLBACK_IPS + tuple(
                line.strip() for line in (self._get_scoped_setting("callback_ip_whitelist") or "").splitlines() if line.strip()
            )
        )
        if remote_ip and not ip_in_whitelist(remote_ip, allowed_ips):
            logger.warning("IP no autorizada para callback: %s", remote_ip)
            raise Forbidden("IP no permitida")

        # ---------- Validar token de autorización ----------
        expected_token = self._get_scoped_setting("callback_authorization_token")
        if expected_token:
            provided = request.headers.get("Authorization", "").strip()
            if provided.lower().startswith("bearer "):
                provided = provided[7:].strip()
            if provided != expected_token:
                logger.warning("Token inválido en callback. Desde IP: %s", remote_ip)
                return "", 401

        # ---------- Validar firma HMAC ----------
        signature = request.headers.get("NBZ-Signature")
        secret = self._get_callback_secret()
        if secret:
            if not signature:
                logger.warning("Callback sin firma HMAC. Rechazado.")
                return "", 401
            if not validate_nbz_signature(secret, body, signature):
                logger.warning("Firma HMAC inválida. Rechazado.")
                return "", 401

        # ---------- Validar campos requeridos ----------
        callback_type = self._detect_callback_type(details)
        missing_fields = self._validate_required_fields(details, callback_type)
        if missing_fields:
            logger.warning("Callback Niubiz con campos faltantes: %s", ", ".join(missing_fields))
            return "", 400

        # ---------- Estado de la transacción ----------
        status_value = (details.get("status") or details.get("status_order") or "").strip()
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

        # ---------- Construir datos de transacción ----------
        transaction_data = build_transaction_data(
            payload=payload,
            source="notify",
            status=status_value or None,
            action_code=action_code or None,
            transaction_id=transaction_id,
            order_id=order_id,
            external_id=external_id,
        )
        transaction_data.update({
            "currency": received_currency,
            "amount": float(received_amount) if received_amount is not None else None,
            "transaction_date": details.get("transaction_date"),
            "authorization_code": details.get("authorization_code"),
            "trace_number": details.get("trace_number"),
            "brand": details.get("brand"),
            "masked_card": details.get("masked_card"),
            "eci": details.get("eci"),
            "cip": details.get("cip"),
            "operation_number": details.get("operation_number"),
            "status_order": status_order,
            "signature": signature,
            "action_description": action_description,
            "manual_confirmation": mapped.manual_confirmation or False,
        })

        # ---------- Logging del callback ----------
        summary = _("Niubiz callback recibido — mapeado a {status}.").format(status=mapped.status.name)
        log_kind = {
            TransactionStatus.successful: LogKind.positive,
            TransactionStatus.pending: LogKind.warning,
            TransactionStatus.cancelled: LogKind.change
        }.get(mapped.status, LogKind.negative)

        log_data = {
            "amount": float(received_amount) if received_amount is not None else None,
            "currency": received_currency,
            "transactionId": transaction_id,
            "transactionDate": details.get("transaction_date"),
            "status": status_value,
            "statusOrder": status_order,
            "actionCode": action_code,
            "actionDescription": action_description,
            "mappedStatus": mapped.status.name,
            "manualConfirmation": mapped.manual_confirmation or False,
        }

        self._log_callback_event(summary, log_kind, {k: v for k, v in log_data.items() if v is not None})

        logger.info(
            "Procesado callback Niubiz — purchase=%s, estado=%s → %s",
            purchase_number,
            status_value,
            mapped.status.name,
        )

        # ---------- Prevenir duplicados ----------
        from indico.modules.events.payment.models.transactions import PaymentTransaction

        if mapped.status == TransactionStatus.successful:
            existing_tx = PaymentTransaction.query.filter_by(
                registration_id=registration.id,
                external_transaction_id=transaction_id
            ).first()

            if existing_tx:
                logger.info("Callback duplicado ignorado — transaction_id=%s", transaction_id)
                return "", 200

        # ---------- Procesamiento según estado ----------
        if mapped.status == TransactionStatus.successful:
            summary_msg = _("Niubiz confirmó el pago mediante notificación.")
            if mapped.manual_confirmation:
                summary_msg = _("Niubiz confirmó manualmente el pago mediante notificación.")

            handle_successful_payment(
                registration,
                amount=received_amount,
                currency=received_currency,
                transaction_id=transaction_id,
                status=status_value,
                action_code=action_code,
                summary=summary_msg,
                data=transaction_data,
            )

        elif mapped.status == TransactionStatus.cancelled:
            handle_failed_payment(
                registration,
                amount=received_amount,
                currency=received_currency,
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
                amount=received_amount if received_amount is not None else getattr(registration, "price", 0),
                currency=received_currency,
                action=TransactionAction.pending,
                data=transaction_data,
            )

        else:
            handle_failed_payment(
                registration,
                amount=received_amount,
                currency=received_currency,
                transaction_id=transaction_id,
                status=status_value,
                action_code=action_code,
                summary=_("Niubiz reportó un estado no exitoso."),
                data=transaction_data,
            )

        return "", 200

