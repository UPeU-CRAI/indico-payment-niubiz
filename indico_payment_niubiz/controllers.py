from flask import flash, redirect, request
from flask_pluginengine import current_plugin
from werkzeug.exceptions import BadRequest

from indico.modules.events.payment.models.transactions import TransactionAction
from indico.modules.events.payment.util import register_transaction
from indico.modules.events.registration.models.registrations import Registration
from indico.web.flask.util import url_for
from indico.web.rh import RH

from indico_payment_niubiz import _

status_map = {
    'COMPLETED': TransactionAction.complete,
    'PENDING': TransactionAction.pending,
}


class RHNiubizBase(RH):
    CSRF_ENABLED = False

    def _process_args(self):
        token = request.args['token']
        self.registration = Registration.query.filter_by(uuid=token).first()
        if not self.registration:
            raise BadRequest


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
        flash(_('Your payment request has been processed.'), 'success')
        return redirect(url_for('event_registration.display_regform', self.registration.locator.registrant))


class RHNiubizCancel(RHNiubizBase):
    def _process(self):
        flash(_('You cancelled the payment process.'), 'info')
        return redirect(url_for('event_registration.display_regform', self.registration.locator.registrant))
