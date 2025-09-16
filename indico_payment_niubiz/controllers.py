import json
import json
import logging
from typing import Any, Dict

from flask import flash, redirect, render_template, request
from werkzeug.exceptions import BadRequest

from indico.modules.events.registration.models.registrations import Registration
from indico.web.flask.util import url_for
from indico.web.rh import RH

from indico_payment_niubiz import _
from indico_payment_niubiz.indico_integration import (apply_registration_status, build_transaction_data,
                                                      handle_failed_payment, handle_successful_payment,
                                                      parse_amount)
from indico_payment_niubiz.settings import (get_credentials_for_event, get_endpoint_for_event,
                                            get_merchant_id_for_event, get_scoped_setting)
from indico_payment_niubiz.util import (authorize_transaction, create_session_token,
                                        get_checkout_script_url, get_security_token,
                                        query_order_status_by_external_id, query_order_status_by_order_id,
                                        query_transaction_status)
SUCCESS_ACTION_CODE = '000'
AUTHORIZED_STATUS_VALUES = {
    'authorized', 'authorised', 'autorizado', 'autorizada', 'approved', 'completed', 'complete', 'success', 'successful',
    'paid'
}
CANCELLED_STATUS_VALUES = {'cancelled', 'canceled', 'cancelado', 'cancelada'}
EXPIRED_STATUS_VALUES = {'expired', 'expirada', 'expirado'}
REJECTED_STATUS_VALUES = {'rejected', 'rechazado', 'rechazada', 'denied', 'not authorized', 'not_authorized',
                          'notauthorised', 'failed'}
PENDING_STATUS_VALUES = {'pending', 'pendiente', 'generated', 'generado', 'created', 'in process', 'processing',
                         'in_progress', 'en proceso'}

logger = logging.getLogger(__name__)


class RHNiubizBase(RH):
    CSRF_ENABLED = False

    def _process_args(self):
        self.event_id = request.view_args['event_id']
        self.reg_form_id = request.view_args['reg_form_id']

        token = request.args.get('token') or request.form.get('token')
        reg_id = (request.view_args.get('reg_id') or request.form.get('reg_id') or
                  request.args.get('reg_id'))

        registration = None
        if token:
            registration = Registration.query.filter_by(uuid=token).first()
        elif reg_id is not None:
            try:
                reg_id = int(reg_id)
            except (TypeError, ValueError):
                raise BadRequest
            registration = Registration.query.get(reg_id)

        if not registration or registration.event_id != self.event_id or \
                registration.registration_form_id != self.reg_form_id:
            raise BadRequest

        self.registration = registration
        self.event = registration.event

    def _get_endpoint(self):
        return get_endpoint_for_event(self.event)

    def _get_scoped_setting(self, name):
        return get_scoped_setting(self.event, name)

    def _get_credentials(self):
        return get_credentials_for_event(self.event)

    def _get_merchant_id(self):
        return get_merchant_id_for_event(self.event)

    def _get_amount(self):
        return self.registration.price

    def _get_currency(self):
        return self.registration.currency or 'PEN'

    def _get_purchase_number(self):
        return f'{self.registration.event_id}-{self.registration.id}'

    def _get_client_ip(self):
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[0].strip() or (request.remote_addr or '127.0.0.1')
        return request.remote_addr or '127.0.0.1'

    def _get_client_id(self):
        email = getattr(self.registration, 'email', None)
        if email:
            return str(email)
        return f'indico-registration-{self.registration.id}'

    def _get_customer_email(self):
        email = getattr(self.registration, 'email', None)
        if email:
            return str(email)
        user = getattr(self.registration, 'user', None)
        if user is not None:
            user_email = getattr(user, 'email', None)
            if user_email:
                return str(user_email)
        return None

    def _get_mdd_context(self) -> Dict[str, Any]:
        registration = self.registration
        context: Dict[str, Any] = {
            'registration_id': getattr(registration, 'id', ''),
            'registration_uuid': getattr(registration, 'uuid', ''),
            'event_id': getattr(self.event, 'id', ''),
            'amount': self._get_amount(),
            'currency': self._get_currency(),
        }

        for attr, key in (
            ('email', 'registration_email'),
            ('phone', 'registration_phone'),
            ('company', 'registration_company'),
            ('full_name', 'registration_name'),
        ):
            value = getattr(registration, attr, None)
            if value:
                context[key] = value

        return context

    def _load_merchant_defined_data(self, raw_value):
        if not raw_value:
            return {}
        try:
            parsed = json.loads(raw_value)
        except (TypeError, ValueError):
            logger.warning('Invalid Niubiz merchant defined data configuration. Value=%s', raw_value)
            return {}
        if not isinstance(parsed, dict):
            logger.warning('Niubiz merchant defined data configuration must be a JSON object. Value=%s', raw_value)
            return {}

        context = self._get_mdd_context()

        class _SafeDict(dict):
            def __missing__(self, key):
                return ''

        result = {}
        for key, value in parsed.items():
            if value in (None, ''):
                continue
            key_str = str(key)
            try:
                formatted = str(value).format_map(_SafeDict(context))
            except Exception:  # pragma: no cover - defensive formatting guard
                logger.warning('Could not format Niubiz MDD value for key %s', key_str, exc_info=True)
                formatted = str(value)
            formatted = formatted.strip()
            if formatted:
                result[key_str] = formatted

        return result

    def _get_merchant_defined_data(self):
        raw_value = self._get_scoped_setting('merchant_defined_data')
        return self._load_merchant_defined_data(raw_value)

    def _get_checkout_button_color(self):
        value = self._get_scoped_setting('button_color')
        return value

    def _get_merchant_logo_url(self):
        value = self._get_scoped_setting('merchant_logo_url')
        return value

    def _get_checkout_script(self):
        endpoint = self._get_endpoint()
        return get_checkout_script_url(endpoint)


def _apply_status_from_value(registration, status_value):
    if not registration or not status_value:
        return False
    status = str(status_value).strip().lower()
    currency = getattr(registration, 'currency', None) or 'PEN'
    amount_decimal = parse_amount(getattr(registration, 'price', None), None)
    transaction_data = build_transaction_data(source='status-sync', status=status_value)
    transaction_data['currency'] = currency
    if amount_decimal is not None:
        transaction_data['amount'] = float(amount_decimal)
    event_id = getattr(registration, 'event_id', None)
    reg_id = getattr(registration, 'id', None)
    if event_id is not None and reg_id is not None:
        transaction_data['purchase_number'] = f'{event_id}-{reg_id}'

    if status in AUTHORIZED_STATUS_VALUES:
        handle_successful_payment(
            registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=None,
            status=status_value,
            action_code=None,
            summary=_('Niubiz confirmó el pago durante la sincronización.'),
            data=transaction_data,
        )
        return True
    if status in CANCELLED_STATUS_VALUES:
        handle_failed_payment(
            registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=None,
            status=status_value,
            action_code=None,
            summary=_('Niubiz indicó que el pago fue cancelado durante la sincronización.'),
            data=transaction_data,
            cancelled=True,
        )
        return True
    if status in EXPIRED_STATUS_VALUES:
        handle_failed_payment(
            registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=None,
            status=status_value,
            action_code=None,
            summary=_('El pago de Niubiz aparece como expirado tras la sincronización.'),
            data=transaction_data,
            expired=True,
        )
        return True
    if status in REJECTED_STATUS_VALUES:
        handle_failed_payment(
            registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=None,
            status=status_value,
            action_code=None,
            summary=_('Niubiz rechazó el pago tras la sincronización.'),
            data=transaction_data,
        )
        return True
    return False


def _synchronise_registration_with_query(*, registration, event, order_id=None, external_id=None,
                                         transaction_id=None):
    if registration is None or event is None:
        return None

    try:
        merchant_id = get_merchant_id_for_event(event)
        access_key, secret_key = get_credentials_for_event(event)
    except BadRequest:
        logger.exception('Missing Niubiz credentials while synchronising registration %s',
                         getattr(registration, 'id', 'unknown'))
        return None

    endpoint = get_endpoint_for_event(event)
    token_result = get_security_token(access_key, secret_key, endpoint)
    if not token_result.get('success'):
        logger.warning('Could not obtain Niubiz security token to synchronise registration %s: %s',
                       getattr(registration, 'id', 'unknown'), token_result.get('error'))
        return token_result

    access_token = token_result['token']

    def refresh_token():
        logger.info('Refreshing Niubiz security token while querying order information for registration %s',
                    getattr(registration, 'id', 'unknown'))
        return get_security_token(access_key, secret_key, endpoint, force_refresh=True)

    query_result = None
    if order_id:
        query_result = query_order_status_by_order_id(merchant_id, str(order_id), access_token, endpoint,
                                                      token_refresher=refresh_token)
    elif external_id:
        query_result = query_order_status_by_external_id(merchant_id, str(external_id), access_token, endpoint,
                                                         token_refresher=refresh_token)

    if (not query_result or not query_result.get('success')) and transaction_id:
        query_result = query_transaction_status(merchant_id, str(transaction_id), access_token, endpoint,
                                                token_refresher=refresh_token)

    if query_result and query_result.get('success'):
        status_value = query_result.get('status')
        if status_value:
            logger.info('Synchronised Niubiz status %s for registration %s', status_value,
                        getattr(registration, 'id', 'unknown'))
            _apply_status_from_value(registration, status_value)
    else:
        logger.info('Niubiz status query did not succeed for registration %s: %s',
                    getattr(registration, 'id', 'unknown'), query_result)

    return query_result


class RHNiubizCallback(RH):
    CSRF_ENABLED = False

    def _process(self):
        payload = request.get_json(silent=True) or {}

        event_id = request.view_args['event_id']
        reg_form_id = request.view_args['reg_form_id']

        order_info = payload.get('order') if isinstance(payload.get('order'), dict) else {}
        external_id = payload.get('externalId')
        order_id = payload.get('orderId')
        purchase_number = (order_id or payload.get('purchaseNumber') or
                           order_info.get('purchaseNumber'))
        reference_number = purchase_number or external_id
        status_value = (payload.get('statusOrder') or '').upper()
        amount_value = payload.get('amount')
        currency_value = payload.get('currency')
        transaction_id = (payload.get('transactionId') or order_info.get('transactionId') or
                          payload.get('operationNumber'))

        logger.info('Received Niubiz callback (externalId=%s, orderId=%s, status=%s, amount=%s, currency=%s)',
                    external_id, purchase_number, status_value or 'UNKNOWN', amount_value, currency_value)
        logger.info('Full Niubiz notification payload: %s', payload)
        registration = None
        if reference_number:
            parts = str(reference_number).split('-', 1)
            if len(parts) == 2:
                _, reg_part = parts
                try:
                    reg_id = int(reg_part)
                except (TypeError, ValueError):
                    reg_id = None
                if reg_id is not None:
                    registration = (Registration.query
                                    .filter_by(id=reg_id,
                                               event_id=event_id,
                                               registration_form_id=reg_form_id)
                                    .first())

        status_value = (payload.get('statusOrder') or '').upper()
        status_lower = status_value.lower()
        amount_decimal = parse_amount(amount_value, None)
        if amount_decimal is None and registration is not None:
            amount_decimal = parse_amount(getattr(registration, 'price', None), None)
        currency = (currency_value or getattr(registration, 'currency', None) or 'PEN')
        transaction_data = build_transaction_data(
            payload=payload,
            source='notify',
            status=status_value or None,
            transaction_id=transaction_id,
            order_id=order_id or purchase_number,
            external_id=external_id,
        )
        if amount_decimal is not None:
            transaction_data['amount'] = float(amount_decimal)
        transaction_data['currency'] = currency

        status_applied = False
        if registration and status_value:
            if status_lower in AUTHORIZED_STATUS_VALUES:
                logger.info('Marking registration %s as paid from Niubiz notification.', registration.id)
                handle_successful_payment(
                    registration,
                    amount=amount_decimal,
                    currency=currency,
                    transaction_id=transaction_id,
                    status=status_value,
                    action_code=None,
                    summary=_('Niubiz confirmó el pago mediante notificación.'),
                    data=transaction_data,
                )
                status_applied = True
            elif status_lower in EXPIRED_STATUS_VALUES:
                logger.info('Marking registration %s as expired from Niubiz notification.', registration.id)
                handle_failed_payment(
                    registration,
                    amount=amount_decimal,
                    currency=currency,
                    transaction_id=transaction_id,
                    status=status_value,
                    action_code=None,
                    summary=_('El pago reportado por Niubiz expiró.'),
                    data=transaction_data,
                    expired=True,
                )
                status_applied = True
            elif status_lower in CANCELLED_STATUS_VALUES:
                logger.info('Marking registration %s as cancelled from Niubiz notification.', registration.id)
                handle_failed_payment(
                    registration,
                    amount=amount_decimal,
                    currency=currency,
                    transaction_id=transaction_id,
                    status=status_value,
                    action_code=None,
                    summary=_('El pago de Niubiz fue cancelado mediante notificación.'),
                    data=transaction_data,
                    cancelled=True,
                )
                status_applied = True
            elif status_lower in REJECTED_STATUS_VALUES:
                logger.info('Marking registration %s as rejected from Niubiz notification.', registration.id)
                handle_failed_payment(
                    registration,
                    amount=amount_decimal,
                    currency=currency,
                    transaction_id=transaction_id,
                    status=status_value,
                    action_code=None,
                    summary=_('Niubiz rechazó el pago mediante notificación.'),
                    data=transaction_data,
                )
                status_applied = True
            else:
                logger.info('Unhandled Niubiz notification status %s for registration %s.',
                            status_value, registration.id)
        should_query = registration and (not status_applied and (order_id or external_id or transaction_id))
        if registration and status_value and status_lower in PENDING_STATUS_VALUES:
            should_query = True

        if should_query:
            logger.info('Attempting to synchronise Niubiz status for registration %s (orderId=%s, externalId=%s).',
                        registration.id, order_id, external_id)
            _synchronise_registration_with_query(registration=registration,
                                                 event=registration.event,
                                                 order_id=order_id or purchase_number,
                                                 external_id=external_id,
                                                 transaction_id=transaction_id)
        elif reference_number:
            logger.info('Could not match Niubiz notification to a registration (purchaseNumber=%s).',
                        reference_number)
        else:
            logger.info('Niubiz notification missing reference number. Payload: %s', payload)

        return '', 200


class RHNiubizSuccess(RHNiubizBase):
    def _process(self):
        transaction_token = (request.form.get('transactionToken') or
                             request.args.get('transactionToken'))
        if not transaction_token and request.is_json:
            transaction_token = (request.json or {}).get('transactionToken')
        if not transaction_token:
            raise BadRequest(_('Missing Niubiz transaction token.'))

        redirect_url = url_for('event_registration.display_regform',
                               self.registration.locator.registrant)

        access_key, secret_key = self._get_credentials()
        endpoint = self._get_endpoint()

        token_result = get_security_token(access_key, secret_key, endpoint)
        if not token_result.get('success'):
            flash(token_result.get('error') or _('The Niubiz security token could not be obtained.'), 'error')
            return redirect(redirect_url)

        access_token = token_result['token']

        authorization = None

        def refresh_token():
            logger.info('Refreshing Niubiz security token during transaction authorisation.')
            return get_security_token(access_key, secret_key, endpoint, force_refresh=True)

        result = authorize_transaction(
            self._get_merchant_id(),
            transaction_token,
            self._get_purchase_number(),
            self._get_amount(),
            self._get_currency(),
            access_token,
            endpoint,
            client_ip=self._get_client_ip(),
            client_id=self._get_client_id(),
            token_refresher=refresh_token,
        )

        if not result.get('success'):
            flash(result.get('error') or _('The Niubiz payment could not be confirmed. Please try again.'), 'error')
            return redirect(redirect_url)

        authorization = result['data']

        if authorization is None:
            flash(_('The Niubiz payment could not be confirmed. Please try again.'), 'error')
            return redirect(redirect_url)

        payload = authorization if isinstance(authorization, dict) else {}
        if isinstance(payload.get('data'), dict):
            auth_data = payload['data']
        else:
            auth_data = payload

        action_code = (auth_data.get('ACTION_CODE') or auth_data.get('actionCode') or
                       payload.get('ACTION_CODE') or payload.get('actionCode'))
        action_code = str(action_code or '').strip()
        status_token_raw = (auth_data.get('STATUS') or auth_data.get('status') or
                             payload.get('STATUS') or payload.get('status') or '')
        status_token = str(status_token_raw).strip().lower()
        order_section = auth_data.get('ORDER') or auth_data.get('order') or {}
        order_id_value = (auth_data.get('ORDER_ID') or payload.get('orderId') or order_section.get('orderId'))
        external_id_value = (auth_data.get('EXTERNAL_ID') or payload.get('externalId') or
                             order_section.get('externalId'))
        transaction_id_value = (auth_data.get('TRANSACTION_ID') or auth_data.get('transactionId') or
                                payload.get('transactionId') or payload.get('operationNumber') or
                                order_section.get('transactionId'))

        query_status = None
        if (status_token in PENDING_STATUS_VALUES or not status_token) and (
                order_id_value or external_id_value or transaction_id_value):
            logger.info('Authorisation returned pending status for registration %s. Synchronising with Niubiz.',
                        self.registration.id)
            query_result = _synchronise_registration_with_query(
                registration=self.registration,
                event=self.event,
                order_id=order_id_value or self._get_purchase_number(),
                external_id=external_id_value,
                transaction_id=transaction_id_value,
            )
            if query_result and query_result.get('success'):
                query_status = query_result.get('status')
                if query_status:
                    status_token_raw = query_status
                    status_token = str(query_status).strip().lower()

        success = (action_code == SUCCESS_ACTION_CODE or status_token in AUTHORIZED_STATUS_VALUES)
        cancelled = status_token in CANCELLED_STATUS_VALUES
        expired = status_token in EXPIRED_STATUS_VALUES
        rejected = status_token in REJECTED_STATUS_VALUES and not success
        if cancelled or expired:
            success = False

        description = (auth_data.get('ACTION_DESCRIPTION') or auth_data.get('ACTION_MESSAGE') or
                        auth_data.get('actionDescription') or auth_data.get('actionMessage') or '')
        amount_decimal = parse_amount(self._get_amount(), None)
        currency = self._get_currency()
        transaction_data = build_transaction_data(
            payload=authorization,
            source='checkout',
            status=status_token_raw or None,
            action_code=action_code or None,
            transaction_id=transaction_id_value,
            order_id=order_id_value,
            external_id=external_id_value,
            message=description or None,
        )
        transaction_data['purchase_number'] = self._get_purchase_number()
        transaction_data['currency'] = currency
        if amount_decimal is not None:
            transaction_data['amount'] = float(amount_decimal)
        else:
            transaction_data['amount'] = float(self._get_amount())
        if query_status:
            transaction_data['query_status'] = query_status

        if cancelled:
            logger.info('Niubiz transaction for registration %s was cancelled by the user.', self.registration.id)
            handle_failed_payment(
                self.registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id_value,
                status=status_token_raw or None,
                action_code=action_code or None,
                summary=_('El pago de Niubiz fue cancelado por el usuario.'),
                data=transaction_data,
                cancelled=True,
            )
        elif expired:
            logger.info('Niubiz transaction for registration %s expired before completion.', self.registration.id)
            handle_failed_payment(
                self.registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id_value,
                status=status_token_raw or None,
                action_code=action_code or None,
                summary=_('El pago de Niubiz expiró antes de completarse.'),
                data=transaction_data,
                expired=True,
            )
        elif rejected:
            logger.info('Niubiz transaction for registration %s explicitly rejected by Niubiz.',
                        self.registration.id)
            handle_failed_payment(
                self.registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id_value,
                status=status_token_raw or None,
                action_code=action_code or None,
                summary=_('Niubiz rechazó el pago.'),
                data=transaction_data,
            )
        elif success:
            logger.info('Niubiz transaction for registration %s approved with action code %s.',
                        self.registration.id, action_code or 'unknown')
            handle_successful_payment(
                self.registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id_value,
                status=status_token_raw or None,
                action_code=action_code or None,
                summary=_('Niubiz confirmó el pago.'),
                data=transaction_data,
            )
        else:
            logger.info('Niubiz transaction for registration %s rejected with action code %s.',
                        self.registration.id, action_code or 'unknown')
            handle_failed_payment(
                self.registration,
                amount=amount_decimal,
                currency=currency,
                transaction_id=transaction_id_value,
                status=status_token_raw or None,
                action_code=action_code or None,
                summary=_('Niubiz rechazó el pago.'),
                data=transaction_data,
            )

        if success:
            flash(_('¡Tu pago ha sido procesado con éxito!'), 'success')
        else:
            code_value = action_code or _('desconocido')
            message = _('Niubiz rechazó tu pago (código {code}).').format(code=code_value)
            if description:
                message = f'{message} {description}'
            flash(message, 'error')

        card_info = auth_data.get('CARD') or auth_data.get('card')
        card_brand = None
        if isinstance(card_info, dict):
            masked_card = (card_info.get('PAN') or card_info.get('pan') or card_info.get('maskedCard'))
            card_brand = (card_info.get('BRAND') or card_info.get('brand') or card_info.get('cardBrand'))
        else:
            masked_card = card_info
        if not card_brand:
            card_brand = (auth_data.get('BRAND') or payload.get('brand') or
                          payload.get('cardBrand') or auth_data.get('cardBrand'))

        authorization_code = (auth_data.get('AUTHORIZATION_CODE') or auth_data.get('authorizationCode'))
        transaction_id = (auth_data.get('TRANSACTION_ID') or auth_data.get('transactionId') or
                          auth_data.get('operationNumber') or payload.get('transactionId'))
        transaction_date = (auth_data.get('TRANSACTION_DATE') or auth_data.get('transactionDate'))

        if cancelled:
            status_label = _('Cancelado')
        elif expired:
            status_label = _('Expirado')
        elif status_token in AUTHORIZED_STATUS_VALUES:
            status_label = _('Autorizado')
        elif success:
            status_label = _('Autorizado')
        elif status_token in REJECTED_STATUS_VALUES:
            status_label = _('Rechazado')
        else:
            status_label = _('Rechazado')

        context = {
            'registration': self.registration,
            'event': self.event,
            'amount': self._get_amount(),
            'currency': self._get_currency(),
            'merchant_id': self._get_merchant_id(),
            'purchase_number': self._get_purchase_number(),
            'authorization': auth_data,
            'raw_authorization': payload,
            'action_code': action_code or None,
            'status_token': status_token_raw,
            'authorization_code': authorization_code,
            'transaction_id': transaction_id,
            'transaction_date': transaction_date,
            'masked_card': masked_card,
            'card_brand': card_brand,
            'status_label': status_label,
            'success': success,
            'standalone': True,
        }

        return render_template('payment_niubiz/transaction_details.html', **context)


class RHNiubizCancel(RHNiubizBase):
    def _process(self):
        amount_decimal = parse_amount(self._get_amount(), None)
        currency = self._get_currency()
        transaction_data = build_transaction_data(
            source='cancel',
            status='CANCELLED',
            message=_('Cancelado por el usuario en el flujo de checkout.'),
        )
        transaction_data['purchase_number'] = self._get_purchase_number()
        transaction_data['currency'] = currency
        if amount_decimal is not None:
            transaction_data['amount'] = float(amount_decimal)
        else:
            transaction_data['amount'] = float(self._get_amount())
        logger.info('Niubiz checkout was cancelled by the user for registration %s.', self.registration.id)
        handle_failed_payment(
            self.registration,
            amount=amount_decimal,
            currency=currency,
            transaction_id=None,
            status='CANCELLED',
            action_code=None,
            summary=_('El participante canceló el pago de Niubiz.'),
            data=transaction_data,
            cancelled=True,
        )
        flash(_('Pago cancelado por el usuario.'), 'info')
        return redirect(url_for('event_registration.display_regform', self.registration.locator.registrant))


class RHNiubizStart(RHNiubizBase):
    def _process(self):
        redirect_url = url_for('event_registration.display_regform',
                               self.registration.locator.registrant)

        access_key, secret_key = self._get_credentials()
        endpoint = self._get_endpoint()

        token_result = get_security_token(access_key, secret_key, endpoint)
        if not token_result.get('success'):
            flash(token_result.get('error') or _('The Niubiz security token could not be obtained.'), 'error')
            return redirect(redirect_url)

        access_token = token_result['token']

        session_key = None
        session_expiration = None
        merchant_defined_data = self._get_merchant_defined_data()
        client_id = self._get_client_id()

        def refresh_token():
            logger.info('Refreshing Niubiz security token while starting checkout session.')
            return get_security_token(access_key, secret_key, endpoint, force_refresh=True)

        session_result = create_session_token(
            self._get_merchant_id(),
            self._get_amount(),
            self._get_currency(),
            access_token,
            endpoint,
            client_ip=self._get_client_ip(),
            client_id=client_id,
            purchase_number=self._get_purchase_number(),
            merchant_defined_data=merchant_defined_data,
            customer_email=self._get_customer_email(),
            token_refresher=refresh_token,
        )

        if not session_result.get('success'):
            flash(session_result.get('error') or _('The Niubiz checkout could not be started. Please try again.'),
                  'error')
            return redirect(redirect_url)

        session_key = session_result['session_key']
        session_expiration = session_result.get('expiration_time')

        if session_key is None:
            flash(_('The Niubiz checkout could not be started. Please try again.'), 'error')
            return redirect(redirect_url)

        context = {
            'registration': self.registration,
            'event': self.event,
            'amount': self._get_amount(),
            'amount_value': float(self._get_amount()),
            'currency': self._get_currency(),
            'merchant_id': self._get_merchant_id(),
            'purchase_number': self._get_purchase_number(),
            'sessionKey': session_key,
            'checkout_js_url': self._get_checkout_script(),
            'merchant_logo_url': self._get_merchant_logo_url(),
            'checkout_button_color': self._get_checkout_button_color(),
            'session_expiration': session_expiration,
            'cancel_url': url_for('payment_niubiz.cancel',
                                  event_id=self.event.id,
                                  reg_form_id=self.registration.registration_form.id,
                                  reg_id=self.registration.id),
        }

        return render_template('payment_niubiz/event_payment_form.html', **context)
