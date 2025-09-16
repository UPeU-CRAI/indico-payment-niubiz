from wtforms.fields import SelectField, StringField, TextAreaField
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
