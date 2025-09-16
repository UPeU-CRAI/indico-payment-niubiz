from indico.core.plugins import IndicoPluginBlueprint

from indico_payment_niubiz.controllers import (RHNiubizCancel, RHNiubizCallback, RHNiubizStart,
                                               RHNiubizSuccess)

blueprint = IndicoPluginBlueprint(
    'payment_niubiz', __name__,
    url_prefix='/event/<int:event_id>/registrations/<int:reg_form_id>/payment/response/niubiz'
)

blueprint.add_url_rule('/cancel/<int:reg_id>', 'cancel', RHNiubizCancel, methods=('GET', 'POST'))
blueprint.add_url_rule('/start/<int:reg_id>', 'start', RHNiubizStart, methods=('GET', 'POST'))
blueprint.add_url_rule('/success/<int:reg_id>', 'success', RHNiubizSuccess, methods=('GET', 'POST'))
blueprint.add_url_rule('/notify', 'notify', RHNiubizCallback, methods=('POST',))
