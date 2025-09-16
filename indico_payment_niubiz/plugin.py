from wtforms.fields import SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, Optional

import logging

from werkzeug.exceptions import BadRequest

from indico.core.plugins import IndicoPlugin
from indico.modules.events.payment import (PaymentEventSettingsFormBase, PaymentPluginMixin,
                                           PaymentPluginSettingsFormBase)
from indico.web.forms.fields import IndicoPasswordField
from indico.web.flask.util import url_for

from indico_payment_niubiz import _
from indico_payment_niubiz.blueprint import blueprint
from indico_payment_niubiz.indico_integration import build_transaction_data, handle_refund, parse_amount
from indico_payment_niubiz.settings import (get_credentials_for_event, get_endpoint_for_event,
                                            get_merchant_id_for_event)
from indico_payment_niubiz.util import get_security_token, refund_transaction


logger = logging.getLogger(__name__)


class PluginSettingsForm(PaymentPluginSettingsFormBase):
    merchant_id = StringField(_('Merchant ID'), [DataRequired()],
                              description=_('Your Niubiz merchant identifier.'))
    access_key = IndicoPasswordField(_('Access key'), [DataRequired()],
                                     description=_('Access key provided by Niubiz.'))
    secret_key = IndicoPasswordField(_('Secret key'), [DataRequired()],
                                     description=_('Secret key provided by Niubiz.'))
    merchant_logo_url = StringField(
        _('Merchant logo URL'),
        [Optional()],
        description=_('HTTPS URL of the logo that Niubiz should display in the checkout form.'),
    )
    button_color = StringField(
        _('Checkout button color'),
        [Optional()],
        description=_('Hexadecimal color (e.g. #1a6ec2) used to customise the Niubiz checkout button.'),
    )
    merchant_defined_data = TextAreaField(
        _('Merchant Define Data (MDD)'),
        [Optional()],
        description=_('JSON map with the antifraud fields (MDDs) provided by Niubiz.'),
    )
    endpoint = SelectField(
        _('Environment'),
        [DataRequired()],
        choices=(
            ('sandbox', _('Sandbox (testing)')),
            ('prod', _('Production')),
        ),
        description=_('Choose the Niubiz environment that should be used when processing payments.'),
    )


class EventSettingsForm(PaymentEventSettingsFormBase):
    merchant_id = StringField(_('Merchant ID override'), [Optional()],
                              description=_('Override the default merchant identifier for this event.'))
    access_key = IndicoPasswordField(_('Access key override'), [Optional()],
                                     description=_('Override the default access key for this event.'))
    secret_key = IndicoPasswordField(_('Secret key override'), [Optional()],
                                     description=_('Override the default secret key for this event.'))
    merchant_logo_url = StringField(
        _('Merchant logo URL override'),
        [Optional()],
        description=_('Override the default logo used in the Niubiz checkout form.'),
    )
    button_color = StringField(
        _('Checkout button color override'),
        [Optional()],
        description=_('Override the Niubiz checkout button color.'),
    )
    merchant_defined_data = TextAreaField(
        _('Merchant Define Data override'),
        [Optional()],
        description=_('Override the JSON map of Niubiz MDD antifraud fields for this event.'),
    )
    endpoint = SelectField(
        _('Environment override'),
        [Optional()],
        choices=(
            ('', _('Use plugin default')),
            ('sandbox', _('Sandbox (testing)')),
            ('prod', _('Production')),
        ),
        default='',
        description=_('Use a different Niubiz environment for this event.'),
    )


class NiubizPaymentPlugin(PaymentPluginMixin, IndicoPlugin):
    """Niubiz

    Provides a payment method using the Niubiz web checkout API.
    """

    configurable = True
    settings_form = PluginSettingsForm
    event_settings_form = EventSettingsForm
    default_settings = {
        'method_name': 'Niubiz',
        'merchant_id': '',
        'access_key': '',
        'secret_key': '',
        'merchant_logo_url': '',
        'button_color': '',
        'merchant_defined_data': '',
        'endpoint': 'sandbox',
    }
    default_event_settings = {
        'enabled': False,
        'method_name': None,
        'merchant_id': None,
        'access_key': None,
        'secret_key': None,
        'merchant_logo_url': None,
        'button_color': None,
        'merchant_defined_data': None,
        'endpoint': None,
    }

    def get_blueprints(self):
        return blueprint

    def adjust_payment_form_data(self, data):
        registration = data['registration']
        event = data['event']
        amount = registration.price
        currency = registration.currency or 'PEN'
        purchase_number = f"{registration.event_id}-{registration.id}"
        merchant_id = (self.event_settings.get(event, 'merchant_id') or
                       self.settings.get('merchant_id'))
        merchant_logo = (self.event_settings.get(event, 'merchant_logo_url') or
                         self.settings.get('merchant_logo_url'))
        button_color = (self.event_settings.get(event, 'button_color') or
                        self.settings.get('button_color'))

        data.update({
            'merchant_id': merchant_id,
            'amount': amount,
            'currency': currency,
            'purchase_number': purchase_number,
            'merchant_logo_url': merchant_logo,
            'checkout_button_color': button_color,
            'start_url': url_for('payment_niubiz.start', event_id=event.id,
                                 reg_form_id=registration.registration_form.id, reg_id=registration.id),
            'cancel_url': url_for('payment_niubiz.cancel', event_id=event.id,
                                  reg_form_id=registration.registration_form.id, reg_id=registration.id),
        })

    def refund(self, registration, transaction=None, amount=None, reason=None, **kwargs):
        registration = registration or getattr(transaction, 'registration', None)
        if registration is None:
            return {'success': False, 'error': _('No se pudo identificar la inscripción a reembolsar.')}

        event = registration.event
        txn = transaction or getattr(registration, 'transaction', None)

        currency = getattr(txn, 'currency', None) or getattr(registration, 'currency', None) or 'PEN'
        amount_decimal = parse_amount(amount, None) if amount is not None else None
        if amount_decimal is None:
            amount_decimal = parse_amount(getattr(txn, 'amount', None), None)
        if amount_decimal is None:
            amount_decimal = parse_amount(getattr(registration, 'price', None), None)

        def _extract_transaction_id(payload):
            if not isinstance(payload, dict):
                return None
            for key in ('transaction_id', 'transactionId', 'TRANSACTION_ID', 'operationNumber'):
                value = payload.get(key)
                if value:
                    return value
            nested = payload.get('payload') or payload.get('data') or payload.get('ORDER') or payload.get('order')
            if isinstance(nested, dict):
                return _extract_transaction_id(nested)
            return None

        transaction_payload = getattr(txn, 'data', {}) or {}
        transaction_id = _extract_transaction_id(transaction_payload)

        if transaction_id is None:
            summary = _('No se pudo determinar el identificador de la transacción de Niubiz para emitir el reembolso.')
            data = build_transaction_data(source='refund', reason=reason, message=summary)
            data['currency'] = currency
            if amount_decimal is not None:
                data['amount'] = float(amount_decimal)
            handle_refund(registration,
                          amount=amount_decimal,
                          currency=currency,
                          transaction_id=None,
                          status=None,
                          summary=summary,
                          data=data,
                          success=False)
            return {'success': False, 'error': summary}

        try:
            endpoint = get_endpoint_for_event(event, plugin=self)
            access_key, secret_key = get_credentials_for_event(event, plugin=self)
            merchant_id = get_merchant_id_for_event(event, plugin=self)
        except BadRequest as exc:
            message = getattr(exc, 'description', str(exc))
            logger.warning('Cannot issue Niubiz refund for registration %s: %s', getattr(registration, 'id', 'unknown'),
                           message)
            data = build_transaction_data(source='refund', transaction_id=str(transaction_id), reason=reason,
                                          message=message)
            data['currency'] = currency
            if amount_decimal is not None:
                data['amount'] = float(amount_decimal)
            handle_refund(registration,
                          amount=amount_decimal,
                          currency=currency,
                          transaction_id=str(transaction_id),
                          status=None,
                          summary=_('El reembolso de Niubiz no se pudo iniciar por una configuración incompleta.'),
                          data=data,
                          success=False)
            return {'success': False, 'error': message}

        token_result = get_security_token(access_key, secret_key, endpoint)
        if not token_result.get('success'):
            message = token_result.get('error') or _('No se pudo obtener el token de seguridad de Niubiz.')
            logger.error('Niubiz refund failed while obtaining security token for registration %s: %s',
                         getattr(registration, 'id', 'unknown'), message)
            data = build_transaction_data(source='refund', transaction_id=str(transaction_id), reason=reason,
                                          message=message)
            data['currency'] = currency
            if amount_decimal is not None:
                data['amount'] = float(amount_decimal)
            handle_refund(registration,
                          amount=amount_decimal,
                          currency=currency,
                          transaction_id=str(transaction_id),
                          status=None,
                          summary=_('Niubiz no pudo iniciar el reembolso.'),
                          data=data,
                          success=False)
            return {'success': False, 'error': message}

        access_token = token_result['token']

        refund_data = build_transaction_data(source='refund', transaction_id=str(transaction_id), reason=reason)
        refund_data['currency'] = currency
        if amount_decimal is not None:
            refund_data['amount'] = float(amount_decimal)
        purchase_number = f"{getattr(registration, 'event_id', '')}-{getattr(registration, 'id', '')}"
        refund_data['purchase_number'] = purchase_number

        def refresh_token():
            logger.info('Refreshing Niubiz security token during refund for registration %s.',
                        getattr(registration, 'id', 'unknown'))
            return get_security_token(access_key, secret_key, endpoint, force_refresh=True)

        amount_value = float(amount_decimal) if amount_decimal is not None else float(getattr(txn, 'amount', 0) or
                                                                                      getattr(registration, 'price', 0) or
                                                                                      0)

        refund_result = refund_transaction(merchant_id=merchant_id,
                                           transaction_id=str(transaction_id),
                                           amount=amount_value,
                                           currency=currency,
                                           access_token=access_token,
                                           endpoint=endpoint,
                                           reason=reason,
                                           token_refresher=refresh_token)

        payload = refund_result.get('data') or refund_result.get('payload')
        status = refund_result.get('status')
        if payload is not None:
            refund_data['payload'] = payload
        if status:
            refund_data['status'] = status

        success = refund_result.get('success') is True
        summary = (_('Se registró un reembolso de Niubiz.') if success
                   else _('Niubiz no pudo procesar el reembolso solicitado.'))
        if not success and refund_result.get('error'):
            refund_data['error'] = refund_result['error']

        handle_refund(registration,
                      amount=amount_decimal,
                      currency=currency,
                      transaction_id=str(transaction_id),
                      status=status,
                      summary=summary,
                      data=refund_data,
                      success=success)

        return {
            'success': success,
            'status': status,
            'payload': payload,
            'error': refund_result.get('error'),
        }
