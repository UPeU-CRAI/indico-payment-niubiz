from __future__ import annotations

import hashlib
import json
from decimal import Decimal
import hmac
from types import SimpleNamespace
from typing import Dict

import pytest
from flask import Flask, request
from werkzeug.exceptions import Forbidden

from indico.modules.events.payment.models.transactions import TransactionAction, TransactionStatus

from indico_payment_niubiz.blueprint import RHNiubizCallback


def _make_registration():
    event_log_entries = []

    class DummyEvent:
        id = 123

        def __init__(self):
            self.log_entries = event_log_entries

        def log(self, realm, kind, module, summary, data=None, meta=None):
            self.log_entries.append(
                {
                    "realm": realm,
                    "kind": kind,
                    "module": module,
                    "summary": summary,
                    "data": data or {},
                }
            )

    registration = SimpleNamespace()
    registration.id = 10
    registration.event_id = 123
    registration.registration_form_id = 5
    registration.price = Decimal("50.00")
    registration.currency = "PEN"
    registration.event = DummyEvent()
    registration.update_state = lambda *a, **k: None
    registration.set_paid = lambda *a, **k: None
    registration.event.log = registration.event.log  # satisfy attribute lookup
    registration._log_entries = event_log_entries
    return registration


@pytest.fixture
def flask_app():
    app = Flask(__name__)
    app.secret_key = "testing-niubiz"
    return app


@pytest.fixture
def plugin_factory(monkeypatch):
    class DummyPlugin:
        def __init__(self, settings: Dict[str, str]):
            self._settings = settings

        def _get_setting(self, event, key: str) -> str:
            return self._settings.get(key, "")

    def _factory(settings):
        plugin = DummyPlugin(settings)
        monkeypatch.setattr("indico_payment_niubiz.blueprint._get_plugin", lambda: plugin)
        return plugin

    return _factory


@pytest.fixture
def register_transaction_calls(monkeypatch):
    calls = []

    def _fake_register_transaction(*, registration, amount, currency, action, provider=None, data=None):
        calls.append(
            {
                "registration": registration,
                "amount": amount,
                "currency": currency,
                "action": action,
                "provider": provider,
                "data": data,
            }
        )
        status_map = {
            TransactionAction.complete: TransactionStatus.successful,
            TransactionAction.cancel: TransactionStatus.cancelled,
            TransactionAction.pending: TransactionStatus.pending,
            TransactionAction.reject: TransactionStatus.rejected,
        }
        return SimpleNamespace(status=status_map.get(action))

    monkeypatch.setattr(
        "indico_payment_niubiz.indico_integration.register_transaction",
        _fake_register_transaction,
    )
    return calls


def _configure_request(monkeypatch, registration, *, plugin_settings, remote_ip="200.48.119.10"):
    def _locate_event(self, event_id):  # pragma: no cover - simple delegation
        return registration.event

    def _get_registration_from_id(self, reg_id):
        return registration if reg_id == registration.id else None

    monkeypatch.setattr(RHNiubizCallback, "_locate_event", _locate_event)
    monkeypatch.setattr(RHNiubizCallback, "_get_registration_from_id", _get_registration_from_id)
    return plugin_settings


def _build_headers(body: str, settings: Dict[str, str]) -> Dict[str, str]:
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    token = settings.get("callback_authorization_token")
    if token:
        headers["Authorization"] = token
    secret = settings.get("callback_hmac_secret")
    if secret:
        headers["NBZ-Signature"] = hmac.new(
            secret.encode("utf-8"),
            body.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    return headers


@pytest.mark.parametrize(
    "status, expected_action, expected_kind, summary",
    [
        ("AUTHORIZED", TransactionAction.complete, "positive", "Pago confirmado por Niubiz"),
        ("REJECTED", TransactionAction.reject, "negative", "Pago rechazado por Niubiz"),
        ("NOT AUTHORIZED", TransactionAction.reject, "negative", "Pago no autorizado por Niubiz"),
        ("VOIDED", TransactionAction.cancel, "change", "Pago anulado por Niubiz"),
        ("CANCELLED", TransactionAction.cancel, "change", "Pago cancelado por Niubiz"),
        ("PENDING", TransactionAction.pending, "warning", "Pago pendiente en Niubiz"),
        ("REFUNDED", TransactionAction.cancel, "change", "Reembolso confirmado por Niubiz"),
        ("EXPIRED", TransactionAction.reject, "negative", "Orden expirada en Niubiz"),
        ("REVIEW", TransactionAction.pending, "warning", "Pago en revisión antifraude Niubiz"),
    ],
)
def test_callback_status_flows(
    flask_app,
    monkeypatch,
    plugin_factory,
    register_transaction_calls,
    status,
    expected_action,
    expected_kind,
    summary,
):
    registration = _make_registration()
    plugin_settings = {
        "callback_authorization_token": "token",
        "callback_hmac_secret": "secret",
        "callback_ip_whitelist": "0.0.0.0/0",
    }
    plugin_factory(plugin_settings)
    _configure_request(monkeypatch, registration, plugin_settings=plugin_settings)

    payload = {
        "purchaseNumber": f"{registration.event_id}-{registration.id}",
        "transactionId": "TX-1",
        "amount": "50.00",
        "currency": registration.currency,
        "STATUS": status,
        "ACTION_CODE": "000",
    }
    if status == "REFUNDED":
        payload.pop("ACTION_CODE", None)

    body = json.dumps(payload)
    headers = _build_headers(body, plugin_settings)

    handler = RHNiubizCallback()
    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=body,
        headers=headers,
        environ_overrides={"REMOTE_ADDR": "200.48.119.10"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        response = handler._process()

    assert response.status_code == 200
    assert response.get_json() == {"received": True}
    assert len(register_transaction_calls) == 1
    transaction_call = register_transaction_calls[0]
    assert transaction_call["action"] == expected_action
    assert transaction_call["provider"] == "niubiz"
    assert transaction_call["data"]["status"].strip().upper() == status
    assert transaction_call["data"]["payload"] == payload

    log_entry = registration._log_entries[-1]
    kind = getattr(log_entry["kind"], "name", str(log_entry["kind"]))
    assert kind.lower() == expected_kind
    assert log_entry["summary"] == summary
    assert log_entry["data"]["status"].strip().upper() == status


def test_callback_invalid_token(flask_app, monkeypatch, plugin_factory):
    registration = _make_registration()
    plugin_settings = {
        "callback_authorization_token": "expected-token",
        "callback_hmac_secret": "",
        "callback_ip_whitelist": "",
    }
    plugin_factory(plugin_settings)
    _configure_request(monkeypatch, registration, plugin_settings=plugin_settings)

    payload = {
        "purchaseNumber": f"{registration.event_id}-{registration.id}",
        "transactionId": "TX-1",
        "STATUS": "AUTHORIZED",
    }

    handler = RHNiubizCallback()
    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        headers={"Authorization": "invalid", "Content-Type": "application/json"},
        environ_overrides={"REMOTE_ADDR": "200.48.119.10"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        with pytest.raises(Forbidden):
            handler._process()


def test_callback_invalid_signature(flask_app, monkeypatch, plugin_factory):
    registration = _make_registration()
    plugin_settings = {
        "callback_authorization_token": "token",
        "callback_hmac_secret": "secret",
        "callback_ip_whitelist": "",
    }
    plugin_factory(plugin_settings)
    _configure_request(monkeypatch, registration, plugin_settings=plugin_settings)

    payload = {
        "purchaseNumber": f"{registration.event_id}-{registration.id}",
        "transactionId": "TX-1",
        "STATUS": "AUTHORIZED",
    }

    handler = RHNiubizCallback()
    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        headers={
            "Authorization": plugin_settings["callback_authorization_token"],
            "NBZ-Signature": "invalid",
            "Content-Type": "application/json",
        },
        environ_overrides={"REMOTE_ADDR": "200.48.119.10"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        with pytest.raises(Forbidden):
            handler._process()


def test_callback_ip_not_allowed(flask_app, monkeypatch, plugin_factory):
    registration = _make_registration()
    plugin_settings = {
        "callback_authorization_token": "token",
        "callback_hmac_secret": "",
        "callback_ip_whitelist": "10.0.0.0/24",
    }
    plugin_factory(plugin_settings)
    _configure_request(monkeypatch, registration, plugin_settings=plugin_settings)

    payload = {
        "purchaseNumber": f"{registration.event_id}-{registration.id}",
        "transactionId": "TX-1",
        "STATUS": "AUTHORIZED",
    }

    handler = RHNiubizCallback()
    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        headers={"Authorization": "token", "Content-Type": "application/json"},
        environ_overrides={"REMOTE_ADDR": "200.48.119.10"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        with pytest.raises(Forbidden):
            handler._process()
