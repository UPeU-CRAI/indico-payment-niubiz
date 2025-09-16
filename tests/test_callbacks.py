import hashlib
import json
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Flask, request

from indico_payment_niubiz.controllers import RHNiubizCallback


def _make_registration():
    registration = Mock()
    registration.id = 10
    registration.price = Decimal("50")
    registration.currency = "PEN"
    registration.event_id = 1
    registration.registration_form_id = 2
    registration.event = SimpleNamespace(id=1)
    registration.user = SimpleNamespace(id=5)
    return registration


@pytest.fixture
def flask_app():
    app = Flask(__name__)
    app.secret_key = "testing-niubiz"
    return app


def _mock_registration_lookup(monkeypatch, registration):
    def _filter_by(**kwargs):
        matches = (
            kwargs.get("id") == registration.id
            and kwargs.get("event_id") == registration.event_id
            and kwargs.get("registration_form_id") == registration.registration_form_id
        )
        return SimpleNamespace(first=lambda: registration if matches else None)

    monkeypatch.setattr(
        "indico_payment_niubiz.controllers.Registration",
        SimpleNamespace(query=SimpleNamespace(filter_by=_filter_by)),
    )


def _build_handler(monkeypatch, registration, settings=None):
    handler = RHNiubizCallback()
    _mock_registration_lookup(monkeypatch, registration)
    values = settings or {}

    def _fake_setting(self, name):
        return values.get(name, "")

    monkeypatch.setattr(RHNiubizCallback, "_get_scoped_setting", _fake_setting)
    monkeypatch.setattr(RHNiubizCallback, "_get_credentials", lambda self: ("ACCESS", values.get("__secret__", "secret")))
    return handler


def test_callback_successful_payment(flask_app, monkeypatch):
    registration = _make_registration()
    handler = _build_handler(monkeypatch, registration)

    success_calls = {}
    log_entries = []

    def fake_success(registration, **kwargs):
        success_calls.update(kwargs)

    def fake_log(registration, summary, *, kind, data, meta=None):
        log_entries.append({"summary": summary, "data": data, "kind": kind})

    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_successful_payment", fake_success)
    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_failed_payment", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.record_payment_transaction", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.log_registration_event", fake_log)

    payload = {
        "purchaseNumber": "1-10",
        "transactionId": "T-1",
        "STATUS": "Authorized",
        "ACTION_CODE": "000",
        "amount": "50.00",
        "currency": "PEN",
        "transactionDate": "2024-01-01T10:00:00",
        "actionDescription": "Autorizado automáticamente",
    }

    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        content_type="application/json",
        environ_overrides={"REMOTE_ADDR": "200.48.119.10", "wsgi.url_scheme": "https"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        handler._process()

    assert success_calls["transaction_id"] == "T-1"
    assert success_calls["status"] == "Authorized"
    assert success_calls["data"]["action_description"] == "Autorizado automáticamente"
    assert any(entry["data"].get("mappedStatus") == "successful" for entry in log_entries)


def test_callback_failed_payment(flask_app, monkeypatch):
    registration = _make_registration()
    handler = _build_handler(monkeypatch, registration)

    failure_calls = {}

    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_successful_payment", lambda *a, **k: None)

    def fake_failed(registration, **kwargs):
        failure_calls.update(kwargs)

    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_failed_payment", fake_failed)
    monkeypatch.setattr("indico_payment_niubiz.controllers.record_payment_transaction", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.log_registration_event", lambda *a, **k: None)

    payload = {
        "purchaseNumber": "1-10",
        "transactionId": "T-2",
        "STATUS": "Not Authorized",
        "ACTION_CODE": "101",
        "amount": "50",
        "currency": "PEN",
    }

    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        content_type="application/json",
        environ_overrides={"REMOTE_ADDR": "200.48.119.10", "wsgi.url_scheme": "https"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        handler._process()

    assert failure_calls["status"] == "Not Authorized"
    assert failure_calls["transaction_id"] == "T-2"


def test_callback_pagoefectivo_pending(flask_app, monkeypatch):
    registration = _make_registration()
    handler = _build_handler(monkeypatch, registration)

    pending_calls = {}

    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_successful_payment", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_failed_payment", lambda *a, **k: None)

    def fake_record(**kwargs):
        pending_calls.update(kwargs)

    monkeypatch.setattr("indico_payment_niubiz.controllers.record_payment_transaction", fake_record)
    monkeypatch.setattr("indico_payment_niubiz.controllers.log_registration_event", lambda *a, **k: None)

    payload = {
        "purchaseNumber": "1-10",
        "transactionId": "PE-1",
        "status": "PENDING",
        "channel": "pagoefectivo",
        "cip": "12345678",
        "operationNumber": "OP-1",
        "currency": "PEN",
    }

    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        content_type="application/json",
        environ_overrides={"REMOTE_ADDR": "200.48.119.10", "wsgi.url_scheme": "https"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        handler._process()

    assert pending_calls["action"].name == "pending"
    assert pending_calls["data"]["cip"] == "12345678"


def test_callback_pagoefectivo_expired(flask_app, monkeypatch):
    registration = _make_registration()
    handler = _build_handler(monkeypatch, registration)

    failure_calls = {}

    def fake_failed(registration, **kwargs):
        failure_calls.update(kwargs)

    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_failed_payment", fake_failed)
    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_successful_payment", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.record_payment_transaction", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.log_registration_event", lambda *a, **k: None)

    payload = {
        "purchaseNumber": "1-10",
        "transactionId": "PE-2",
        "status": "EXPIRED",
        "channel": "pagoefectivo",
        "operationNumber": "OP-2",
    }

    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        content_type="application/json",
        environ_overrides={"REMOTE_ADDR": "200.48.119.10", "wsgi.url_scheme": "https"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        handler._process()

    assert failure_calls["cancelled"] is True


def test_callback_missing_transaction_id_returns_400(flask_app, monkeypatch):
    registration = _make_registration()
    handler = _build_handler(monkeypatch, registration)

    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_successful_payment", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_failed_payment", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.record_payment_transaction", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.log_registration_event", lambda *a, **k: None)

    payload = {"purchaseNumber": "1-10", "STATUS": "AUTHORIZED", "ACTION_CODE": "000"}

    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        content_type="application/json",
        environ_overrides={"REMOTE_ADDR": "200.48.119.10", "wsgi.url_scheme": "https"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        result = handler._process()

    assert result == ("", 400)


def test_callback_invalid_signature_returns_401(flask_app, monkeypatch):
    registration = _make_registration()
    settings = {"callback_hmac_secret": "secret"}
    handler = _build_handler(monkeypatch, registration, settings=settings)

    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_successful_payment", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_failed_payment", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.record_payment_transaction", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.log_registration_event", lambda *a, **k: None)

    payload = {"purchaseNumber": "1-10", "transactionId": "T-1", "STATUS": "AUTHORIZED"}
    body = json.dumps(payload)
    signature = hashlib.sha256(b"invalid").hexdigest()

    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=body,
        content_type="application/json",
        headers={"NBZ-Signature": signature},
        environ_overrides={"REMOTE_ADDR": "200.48.119.10", "wsgi.url_scheme": "https"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        result = handler._process()

    assert result == ("", 401)
