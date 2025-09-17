import json
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Flask, request

from indico.modules.events.payment.models.transactions import TransactionStatus

from indico_payment_niubiz.controllers import RHNiubizCallback


def _make_registration():
    registration = Mock()
    registration.id = 10
    registration.event_id = 1
    registration.registration_form_id = 2
    registration.price = Decimal("50")
    registration.currency = "PEN"
    registration.event = SimpleNamespace(id=1)
    registration.user = SimpleNamespace(id=5)
    registration.set_paid = Mock()
    return registration


def _patch_registration_lookup(monkeypatch, registration):
    def _filter_by(**kwargs):
        matches = (
            kwargs.get("id") == registration.id
            and kwargs.get("event_id") == registration.event_id
            and kwargs.get("registration_form_id") == registration.registration_form_id
        )
        return SimpleNamespace(first=lambda: registration if matches else None)

    fake_registration = SimpleNamespace(
        query=SimpleNamespace(filter_by=_filter_by),
        get=lambda reg_id: registration if reg_id == registration.id else None,
    )
    monkeypatch.setattr("indico_payment_niubiz.controllers.Registration", fake_registration)


def _patch_db(monkeypatch):
    commits = []

    def _commit():
        commits.append(True)

    fake_db = SimpleNamespace(session=SimpleNamespace(commit=_commit))
    monkeypatch.setattr("indico_payment_niubiz.controllers.db", fake_db)
    return commits


def _build_handler(monkeypatch, registration, mapped_status):
    handler = RHNiubizCallback()
    _patch_registration_lookup(monkeypatch, registration)

    settings = {
        "callback_ip_whitelist": "",
        "callback_authorization_token": "",
        "callback_hmac_secret": "secret",
    }

    def _get_setting(self, name):
        return settings.get(name)

    monkeypatch.setattr(RHNiubizCallback, "_get_scoped_setting", _get_setting)
    monkeypatch.setattr(RHNiubizCallback, "_get_credentials", lambda self: ("ACCESS", "secret"))
    monkeypatch.setattr(
        "indico_payment_niubiz.controllers.map_niubiz_status",
        lambda **kwargs: SimpleNamespace(status=mapped_status, manual_confirmation=False),
    )
    monkeypatch.setattr("indico_payment_niubiz.controllers.build_transaction_data", lambda **kwargs: {})
    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_successful_payment", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_failed_payment", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.record_payment_transaction", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.log_registration_event", lambda *a, **k: None)
    return handler


@pytest.fixture
def flask_app():
    app = Flask(__name__)
    app.secret_key = "testing-niubiz"
    return app


def test_callback_marks_registration_paid(flask_app, monkeypatch):
    registration = _make_registration()
    handler = _build_handler(monkeypatch, registration, TransactionStatus.successful)
    commits = _patch_db(monkeypatch)
    monkeypatch.setattr(
        "indico_payment_niubiz.controllers.validate_nbz_signature",
        lambda secret, body, signature: True,
    )

    payload = {
        "purchaseNumber": "1-10",
        "transactionId": "T-1",
        "status": "Authorized",
        "ACTION_CODE": "000",
        "amount": "50.00",
        "currency": "PEN",
    }

    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"NBZ-Signature": "valid"},
        environ_overrides={"REMOTE_ADDR": "200.48.119.10", "wsgi.url_scheme": "https"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        result = handler._process()

    assert result == ("", 200)
    registration.set_paid.assert_called_once_with(True)
    assert len(commits) == 1


def test_callback_marks_registration_unpaid_on_refund(flask_app, monkeypatch):
    registration = _make_registration()
    handler = _build_handler(monkeypatch, registration, TransactionStatus.cancelled)
    commits = _patch_db(monkeypatch)
    monkeypatch.setattr(
        "indico_payment_niubiz.controllers.validate_nbz_signature",
        lambda secret, body, signature: True,
    )

    payload = {
        "purchaseNumber": "1-10",
        "transactionId": "T-2",
        "status": "Refunded",
        "amount": "50.00",
        "currency": "PEN",
    }

    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"NBZ-Signature": "valid"},
        environ_overrides={"REMOTE_ADDR": "200.48.119.10", "wsgi.url_scheme": "https"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        result = handler._process()

    assert result == ("", 200)
    registration.set_paid.assert_called_once_with(False)
    assert len(commits) == 1


def test_callback_invalid_signature_rejected(flask_app, monkeypatch):
    registration = _make_registration()
    handler = _build_handler(monkeypatch, registration, TransactionStatus.successful)
    commits = _patch_db(monkeypatch)
    monkeypatch.setattr(
        "indico_payment_niubiz.controllers.validate_nbz_signature",
        lambda secret, body, signature: False,
    )

    payload = {
        "purchaseNumber": "1-10",
        "transactionId": "T-3",
        "status": "Authorized",
        "amount": "50.00",
        "currency": "PEN",
    }

    with flask_app.test_request_context(
        "/notify",
        method="POST",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"NBZ-Signature": "invalid"},
        environ_overrides={"REMOTE_ADDR": "200.48.119.10", "wsgi.url_scheme": "https"},
    ):
        request.view_args = {"event_id": registration.event_id, "reg_form_id": registration.registration_form_id}
        handler._process_args()
        result = handler._process()

    assert result == ("", 401)
    assert not registration.set_paid.called
    assert len(commits) == 0
