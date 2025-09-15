import logging

import requests
from flask import flash, redirect, render_template, request
from flask_pluginengine import current_plugin
from werkzeug.exceptions import BadRequest

from indico.modules.events.payment.models.transactions import TransactionAction
from indico.modules.events.payment.util import register_transaction
from indico.modules.events.registration.models.registrations import Registration
from indico.web.flask.util import url_for
from indico.web.rh import RH

from indico_payment_niubiz import _
from indico_payment_niubiz.util import (authorize_transaction, create_session_token,
                                        get_security_token)

status_map = {
    'COMPLETED': TransactionAction.complete,
    'PENDING': TransactionAction.pending,
}


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
        endpoint = current_plugin.settings.get('endpoint')
        if endpoint in {'sandbox', 'prod'}:
            return endpoint

        for url in (current_plugin.settings.get('security_url', ''),
                    current_plugin.settings.get('session_url', '')):
            if not url:
                continue
            url_lower = url.lower()
            if 'sandbox' in url_lower or 'qas' in url_lower:
                return 'sandbox'
        return 'prod'

    def _get_credentials(self):
        access_key = (current_plugin.settings.get('access_key') or
                      current_plugin.settings.get('api_username'))
        secret_key = (current_plugin.settings.get('secret_key') or
                      current_plugin.settings.get('api_password'))
        if not access_key or not secret_key:
            raise BadRequest(_('Niubiz credentials are not configured.'))
        return access_key, secret_key

    def _get_merchant_id(self):
        merchant_id = current_plugin.event_settings.get(self.event, 'merchant_id')
        if not merchant_id:
            raise BadRequest(_('The Niubiz merchant ID is not configured.'))
        return merchant_id

    def _get_amount(self):
        return self.registration.price

    def _get_currency(self):
        return self.registration.currency or 'PEN'

    def _get_purchase_number(self):
        return f'{self.registration.event_id}-{self.registration.id}'


class RHNiubizCallback(RHNiubizBase):
    def _process(self):
        data = request.json or request.form
        status = data.get('status') or data.get('statusOrder')
        action = status_map.get(status, TransactionAction.reject)
        register_transaction(registration=self.registration,
                             amount=float(data.get('amount', 0)),
                             currency=data.get('currency', self.registration.currency),
                             action=action,
                             provider='niubiz',
                             data=data)
        return '', 204


class RHNiubizSuccess(RHNiubizBase):
    def _process(self):
        transaction_token = (request.form.get('transactionToken') or
                             request.args.get('transactionToken'))
        if not transaction_token and request.is_json:
            transaction_token = (request.json or {}).get('transactionToken')
        if not transaction_token:
            raise BadRequest(_('Missing Niubiz transaction token.'))

        try:
            access_key, secret_key = self._get_credentials()
            endpoint = self._get_endpoint()
            access_token = get_security_token(access_key, secret_key, endpoint)
            authorization = authorize_transaction(
                self._get_merchant_id(),
                transaction_token,
                self._get_purchase_number(),
                self._get_amount(),
                self._get_currency(),
                access_token,
                endpoint,
            )
        except BadRequest:
            raise
        except requests.RequestException as exc:
            logging.getLogger(__name__).exception('Niubiz authorization failed')
            flash(_('There was a problem confirming your Niubiz payment.'), 'error')
            return redirect(url_for('event_registration.display_regform',
                                    self.registration.locator.registrant))

        auth_data = authorization.get('data', {}) if isinstance(authorization, dict) else {}
        action_code = auth_data.get('ACTION_CODE')
        action = TransactionAction.complete if action_code == '000' else TransactionAction.reject

        register_transaction(registration=self.registration,
                             amount=self._get_amount(),
                             currency=self._get_currency(),
                             action=action,
                             provider='niubiz',
                             data=authorization)

        if action is TransactionAction.complete:
            flash(_('Your payment was authorized successfully.'), 'success')
        else:
            flash(_('Your payment could not be authorized (code {code}).').format(code=action_code),
                  'error')

        context = {
            'registration': self.registration,
            'event': self.event,
            'amount': self._get_amount(),
            'currency': self._get_currency(),
            'merchant_id': self._get_merchant_id(),
            'purchase_number': self._get_purchase_number(),
            'authorization': auth_data,
            'action_code': action_code,
            'transaction_id': auth_data.get('TRANSACTION_ID'),
            'masked_card': auth_data.get('CARD'),
            'success': action is TransactionAction.complete,
        }

        return render_template('payment_niubiz/event_payment_form.html', **context)


class RHNiubizCancel(RHNiubizBase):
    def _process(self):
        flash(_('You cancelled the payment process.'), 'info')
        return redirect(url_for('event_registration.display_regform', self.registration.locator.registrant))


class RHNiubizStart(RHNiubizBase):
    def _process(self):
        try:
            access_key, secret_key = self._get_credentials()
            endpoint = self._get_endpoint()
            access_token = get_security_token(access_key, secret_key, endpoint)
            session_key = create_session_token(
                self._get_merchant_id(),
                self._get_amount(),
                self._get_currency(),
                access_token,
                endpoint,
            )
        except BadRequest:
            raise
        except requests.RequestException:
            logging.getLogger(__name__).exception('Could not create Niubiz session token')
            flash(_('There was a problem initiating your Niubiz payment.'), 'error')
            return redirect(url_for('event_registration.display_regform',
                                    self.registration.locator.registrant))

        context = {
            'registration': self.registration,
            'event': self.event,
            'amount': self._get_amount(),
            'currency': self._get_currency(),
            'merchant_id': self._get_merchant_id(),
            'purchase_number': self._get_purchase_number(),
            'sessionKey': session_key,
        }

        return render_template('payment_niubiz/event_payment_form.html', **context)
