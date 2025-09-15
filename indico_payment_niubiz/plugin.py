from wtforms.fields import StringField, URLField
from wtforms.validators import DataRequired

from indico.core.plugins import IndicoPlugin
from indico.modules.events.payment import (PaymentEventSettingsFormBase, PaymentPluginMixin,
                                           PaymentPluginSettingsFormBase)

from indico_payment_niubiz import _
from indico_payment_niubiz.blueprint import blueprint


class PluginSettingsForm(PaymentPluginSettingsFormBase):
    security_url = URLField(_('Security token URL'), [DataRequired()],
                            description=_('Endpoint used to obtain a security token.'))
    session_url = URLField(_('Session token URL'), [DataRequired()],
                           description=_('Endpoint used to create a session token.'))
    api_username = StringField(_('API username'), [DataRequired()])
    api_password = StringField(_('API password'), [DataRequired()])


class EventSettingsForm(PaymentEventSettingsFormBase):
    merchant_id = StringField(_('Merchant ID'), [DataRequired()],
                              description=_('Niubiz merchant identifier.'))


class NiubizPaymentPlugin(PaymentPluginMixin, IndicoPlugin):
    """Niubiz

    Provides a payment method using the Niubiz web checkout API.
    """

    configurable = True
    settings_form = PluginSettingsForm
    event_settings_form = EventSettingsForm
    default_settings = {
        'method_name': 'Niubiz',
        'security_url': 'https://apisandbox.vnforapps.com/api.security/v1/security',
        'session_url': 'https://apisandbox.vnforapps.com/api.ecommerce/v2/ecommerce/token/session',
        'api_username': '',
        'api_password': '',
    }
    default_event_settings = {
        'enabled': False,
        'method_name': None,
        'merchant_id': None,
    }

    def get_blueprints(self):
        return blueprint

    def adjust_payment_form_data(self, data):
        registration = data['registration']
        event = data['event']
        amount = registration.price
        currency = registration.currency
        purchase_number = f"{registration.event_id}-{registration.id}"

        data.update({
            'merchant_id': self.event_settings.get(event, 'merchant_id'),
            'amount': amount,
            'currency': currency,
            'purchase_number': purchase_number,
        })
