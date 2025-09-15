from wtforms.fields import SelectField, StringField
from wtforms.validators import DataRequired, Optional

from indico.core.plugins import IndicoPlugin
from indico.modules.events.payment import (PaymentEventSettingsFormBase, PaymentPluginMixin,
                                           PaymentPluginSettingsFormBase)
from indico.web.forms.fields import IndicoPasswordField
from indico.web.flask.util import url_for

from indico_payment_niubiz import _
from indico_payment_niubiz.blueprint import blueprint


class PluginSettingsForm(PaymentPluginSettingsFormBase):
    merchant_id = StringField(_('Merchant ID'), [DataRequired()],
                              description=_('Your Niubiz merchant identifier.'))
    access_key = IndicoPasswordField(_('Access key'), [DataRequired()],
                                     description=_('Access key provided by Niubiz.'))
    secret_key = IndicoPasswordField(_('Secret key'), [DataRequired()],
                                     description=_('Secret key provided by Niubiz.'))
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
        'endpoint': 'sandbox',
    }
    default_event_settings = {
        'enabled': False,
        'method_name': None,
        'merchant_id': None,
        'access_key': None,
        'secret_key': None,
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

        data.update({
            'merchant_id': merchant_id,
            'amount': amount,
            'currency': currency,
            'purchase_number': purchase_number,
            'start_url': url_for('payment_niubiz.start', event_id=event.id,
                                 reg_form_id=registration.registration_form.id, reg_id=registration.id),
            'cancel_url': url_for('payment_niubiz.cancel', event_id=event.id,
                                  reg_form_id=registration.registration_form.id, reg_id=registration.id),
        })
