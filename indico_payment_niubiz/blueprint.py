"""Blueprint del plugin Niubiz."""

from __future__ import annotations

from indico.web.flask.wrappers import IndicoPluginBlueprint

from . import views

blueprint = IndicoPluginBlueprint("niubiz", __name__)

blueprint.add_url_rule(
    "/payment/niubiz/start",
    "start",
    views.start,
    methods=("POST",),
)
blueprint.add_url_rule(
    "/payment/niubiz/return",
    "return",
    views.return_payment,
    methods=("POST",),
)
blueprint.add_url_rule(
    "/payment/niubiz/notify",
    "notify",
    views.notify,
    methods=("POST",),
)
blueprint.add_url_rule(
    "/payment/niubiz/refund",
    "refund",
    views.refund,
    methods=("POST",),
)

__all__ = ["blueprint"]
