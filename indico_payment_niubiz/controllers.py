import logging

from flask import flash, redirect, render_template, request
from flask_pluginengine import current_plugin
from werkzeug.exceptions import BadRequest

from indico.core.db import db
from indico.modules.events.payment.models.transactions import TransactionAction
from indico.modules.events.payment.util import register_transaction
from indico.modules.events.registration.models.registrations import Registration
from indico.web.flask.util import url_for
from indico.web.rh import RH

from indico_payment_niubiz import _
from indico_payment_niubiz.util import authorize_transaction, create_session_token, get_security_token

CANCEL_ACTION = getattr(TransactionAction, 'cancel', TransactionAction.reject)
SUCCESS_ACTION_CODE = '000'

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
        endpoint = (current_plugin.event_settings.get(self.event, 'endpoint') or
                    current_plugin.settings.get('endpoint') or 'sandbox')
        endpoint = (endpoint or '').lower()
        return 'sandbox' if endpoint == 'sandbox' else 'prod'

    def _get_credentials(self):
        access_key = (current_plugin.event_settings.get(self.event, 'access_key') or
                      current_plugin.settings.get('access_key'))
        secret_key = (current_plugin.event_settings.get(self.event, 'secret_key') or
                      current_plugin.settings.get('secret_key'))
        if not access_key or not secret_key:
            raise BadRequest(_('Niubiz credentials are not configured.'))
        return access_key, secret_key

    def _get_merchant_id(self):
        merchant_id = (current_plugin.event_settings.get(self.event, 'merchant_id') or
                       current_plugin.settings.get('merchant_id'))
        if not merchant_id:
            raise BadRequest(_('The Niubiz merchant ID is not configured.'))
        return merchant_id

    def _get_amount(self):
        return self.registration.price

    def _get_currency(self):
        return self.registration.currency or 'PEN'

    def _get_purchase_number(self):
        return f'{self.registration.event_id}-{self.registration.id}'

    def _get_client_ip(self):
        return request.remote_addr or '127.0.0.1'

    def _get_checkout_script(self):
        endpoint = self._get_endpoint()
        return ('https://static-content-qas.vnforapps.com/v2/js/checkout.js'
                if endpoint == 'sandbox'
                else 'https://static-content.vnforapps.com/v2/js/checkout.js')


def _apply_registration_status(*, registration, paid=None, cancelled=False, expired=False):
    if registration is None:
        return

    changed = False

    if cancelled:
        registration.update_state(withdrawn=True, paid=False)
        changed = True
    elif expired:
        registration.update_state(paid=False)
        changed = True
    elif paid is True:
        registration.update_state(paid=True)
        changed = True
    elif paid is False:
        registration.update_state(paid=False)
        changed = True

    if changed:
        db.session.flush()


class RHNiubizCallback(RH):
    CSRF_ENABLED = False

    def _process(self):
        payload = request.get_json(silent=True) or {}
        logger.info('Received Niubiz callback notification: %s', payload)

        event_id = request.view_args['event_id']
        reg_form_id = request.view_args['reg_form_id']

        order_info = payload.get('order') if isinstance(payload.get('order'), dict) else {}
        purchase_number = (payload.get('orderId') or payload.get('purchaseNumber') or
                           order_info.get('purchaseNumber'))
        reference_number = purchase_number or payload.get('externalId')
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
        if registration and status_value:
            if status_value == 'COMPLETED':
                logger.info('Marking registration %s as paid from Niubiz notification.', registration.id)
                _apply_registration_status(registration=registration, paid=True)
            elif status_value == 'EXPIRED':
                logger.info('Marking registration %s as expired from Niubiz notification.', registration.id)
                _apply_registration_status(registration=registration, expired=True)
            elif status_value in {'CANCELLED', 'CANCELED'}:
                logger.info('Marking registration %s as cancelled from Niubiz notification.', registration.id)
                _apply_registration_status(registration=registration, cancelled=True)
            else:
                logger.info('Unhandled Niubiz notification status %s for registration %s.',
                            status_value, registration.id)
        elif reference_number:
            logger.info('Could not match Niubiz notification to a registration (purchaseNumber=%s).',
                        reference_number)

        return '', 204


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
            return get_security_token(access_key, secret_key, endpoint)

        result = authorize_transaction(
            self._get_merchant_id(),
            transaction_token,
            self._get_purchase_number(),
            self._get_amount(),
            self._get_currency(),
            access_token,
            endpoint,
            client_ip=self._get_client_ip(),
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
        action_code = action_code or ''
        action_code = str(action_code)
        success = action_code == SUCCESS_ACTION_CODE
        status_token = (auth_data.get('STATUS') or auth_data.get('status') or '').lower()

        status_token = (auth_data.get('STATUS') or auth_data.get('status') or '').lower()
        cancelled = status_token in {'cancelled', 'canceled'}
        expired = status_token in {'expired', 'expirada'}
        action = (TransactionAction.complete if success else
                  (CANCEL_ACTION if cancelled else TransactionAction.reject))

        register_transaction(registration=self.registration,
                             amount=self._get_amount(),
                             currency=self._get_currency(),
                             action=action,
                             provider='niubiz',
                             data=authorization)

        if cancelled:
            _apply_registration_status(registration=self.registration, cancelled=True)
        elif expired:
            _apply_registration_status(registration=self.registration, expired=True)
        elif success:
            _apply_registration_status(registration=self.registration, paid=True)
        else:
            _apply_registration_status(registration=self.registration, paid=False)

        description = (auth_data.get('ACTION_DESCRIPTION') or auth_data.get('ACTION_MESSAGE') or
                        auth_data.get('actionDescription') or auth_data.get('actionMessage') or '')

        if success:
            flash(_('Your payment was authorized successfully.'), 'success')
        else:
            message = _('Your payment could not be authorized (code {code}).').format(code=action_code)
            if description:
                message = f'{message} {description}'
            flash(message, 'error')

        card_info = auth_data.get('CARD') or auth_data.get('card')
        if isinstance(card_info, dict):
            masked_card = (card_info.get('PAN') or card_info.get('pan') or card_info.get('maskedCard'))
        else:
            masked_card = card_info

        authorization_code = (auth_data.get('AUTHORIZATION_CODE') or auth_data.get('authorizationCode'))
        transaction_id = (auth_data.get('TRANSACTION_ID') or auth_data.get('transactionId') or
                          auth_data.get('operationNumber') or payload.get('transactionId'))
        transaction_date = (auth_data.get('TRANSACTION_DATE') or auth_data.get('transactionDate'))

        if cancelled:
            status_label = _('Cancelado')
        elif expired:
            status_label = _('Expirado')
        elif success:
            status_label = _('Éxito')
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
            'authorization_code': authorization_code,
            'transaction_id': transaction_id,
            'transaction_date': transaction_date,
            'masked_card': masked_card,
            'status_label': status_label,
            'success': success,
            'standalone': True,
        }

        return render_template('payment_niubiz/transaction_details.html', **context)


class RHNiubizCancel(RHNiubizBase):
    def _process(self):
        register_transaction(registration=self.registration,
                             amount=self._get_amount(),
                             currency=self._get_currency(),
                             action=CANCEL_ACTION,
                             provider='niubiz',
                             data={'status': 'cancelled'})
        _apply_registration_status(registration=self.registration, cancelled=True)
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

        def refresh_token():
            logger.info('Refreshing Niubiz security token while starting checkout session.')
            return get_security_token(access_key, secret_key, endpoint)

        session_result = create_session_token(
            self._get_merchant_id(),
            self._get_amount(),
            self._get_currency(),
            access_token,
            endpoint,
            client_ip=self._get_client_ip(),
            client_id=f'indico-registration-{self.registration.id}',
            token_refresher=refresh_token,
        )

        if not session_result.get('success'):
            flash(session_result.get('error') or _('The Niubiz checkout could not be started. Please try again.'),
                  'error')
            return redirect(redirect_url)

        session_key = session_result['session_key']

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
            'cancel_url': url_for('payment_niubiz.cancel',
                                  event_id=self.event.id,
                                  reg_form_id=self.registration.registration_form.id,
                                  reg_id=self.registration.id),
        }

        return render_template('payment_niubiz/event_payment_form.html', **context)
