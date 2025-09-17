from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Flask

import requests

from indico.modules.events.registration.models.registrations import RegistrationState

from indico_payment_niubiz.client import NiubizClient, _sanitize_payload
from indico_payment_niubiz.controllers import RHNiubizSuccess
from indico_payment_niubiz.plugin import NiubizPaymentPlugin


def _build_response(*, text="", json_payload=None, status_code=200):
    response = Mock()
    response.status_code = status_code
    response.text = text
    response.json = Mock(return_value=json_payload if json_payload is not None else {})
    response.raise_for_status = Mock()
    return response


@pytest.fixture
def flask_app():
    app = Flask(__name__)
    app.secret_key = "testing-niubiz"
    return app


def _make_registration():
    registration = Mock()
    registration.price = 50
    registration.currency = "PEN"
    registration.event_id = 1
    registration.id = 10
    registration.registration_form_id = 2
    registration.registration_form = SimpleNamespace(id=2)
    event_log = Mock()
    registration.event = SimpleNamespace(id=1, log=event_log)
    registration.locator = SimpleNamespace(registrant="locator-token")
    registration.set_state = Mock()
    registration.update_state = Mock()
    registration.event.log = event_log
    registration.user = SimpleNamespace(id=5)
    return registration


def _make_plugin(settings=None, event_settings=None):
    class DummyPlugin(NiubizPaymentPlugin):
        name = "payment_niubiz_test"

    class _Settings:
        def __init__(self, data):
            self._data = data

        def get(self, name):
            return self._data.get(name)

        def get_all(self, event=None):
            return dict(self._data)

    class _EventSettings:
        def __init__(self, data):
            self._data = data

        def get(self, event, name):
            return self._data.get(name)

        def get_all(self, event):
            return dict(self._data)

    settings_proxy = _Settings(settings or {
        "merchant_id": "MERCHANT",
        "access_key": "ACCESS",
        "secret_key": "SECRET",
        "endpoint": "sandbox",
        "enable_card": True,
    })
    event_settings_proxy = _EventSettings(event_settings or {})
    DummyPlugin.settings = settings_proxy
    DummyPlugin.event_settings = event_settings_proxy
    return object.__new__(DummyPlugin)


def test_plugin_refund_logs_placeholder(monkeypatch):
    plugin = _make_plugin()
    registration = _make_registration()
    transaction = Mock()
    transaction.data = {"transaction_id": "TX-1", "status": "CONFIRMED"}
    transaction.amount = 50
    transaction.currency = "PEN"

    captured = {}

    def fake_handle_refund(registration, *, amount, currency, transaction_id, status, summary, data, success):
        captured.update(
            {
                "registration": registration,
                "amount": amount,
                "currency": currency,
                "transaction_id": transaction_id,
                "status": status,
                "summary": summary,
                "data": data,
                "success": success,
            }
        )

    monkeypatch.setattr("indico_payment_niubiz.plugin.handle_refund", fake_handle_refund)

    result = plugin.refund(registration, transaction=transaction, amount=20, reason="Test")

    assert result["success"] is False
    assert "not yet implemented" in result["error"].lower()
    assert captured["success"] is False
    assert captured["status"] == "NOT_IMPLEMENTED"
    assert captured["transaction_id"] == "TX-1"
    assert captured["amount"].quantize(Decimal("1")) == Decimal("20")


def test_client_get_security_token_caches(monkeypatch):
    response = _build_response(text="  cached-token  ")

    calls = []

    def fake_request(method, url, headers=None, json=None, timeout=None):
        calls.append((method, url, headers))
        return response

    monkeypatch.setattr(requests, "request", fake_request)
    client = NiubizClient(merchant_id="MID", access_key="AK", secret_key="SK", endpoint="sandbox")

    result1 = client.get_security_token()
    result2 = client.get_security_token()

    assert result1["success"] is True
    assert result1["token"] == "cached-token"
    assert result2["cached"] is True
    assert len(calls) == 1


def test_client_get_security_token_from_json(monkeypatch):
    payload = {"accessToken": "json-token", "expiresIn": 600}
    response = _build_response(text="ignored", json_payload=payload)

    def fake_request(method, url, headers=None, json=None, timeout=None):
        return response

    monkeypatch.setattr(requests, "request", fake_request)
    client = NiubizClient(merchant_id="MID", access_key="AK", secret_key="SK", endpoint="sandbox")

    result = client.get_security_token()

    assert result["success"] is True
    assert result["token"] == "json-token"
    assert result["payload"] == payload


def test_sanitize_payload_masks_nested_sensitive_fields():
    payload = {
        "outer": {
            "accessToken": "abcdef123456",
            "nested": [
                {"tokenId": "token-1", "maskedCard": "411111******1111"},
                {"cvv": "123", "pan": "4111111111111111"},
            ],
            "details": {"secretKey": "shhhh", "sessionKey": "SESSION-123"},
        }
    }

    sanitized = _sanitize_payload(payload)

    assert sanitized["outer"]["accessToken"] == "abcdef**3456"
    assert sanitized["outer"]["nested"][0]["tokenId"].startswith("t")
    assert sanitized["outer"]["nested"][0]["tokenId"].endswith("1")
    assert sanitized["outer"]["nested"][0]["tokenId"] != "token-1"
    assert sanitized["outer"]["nested"][0]["maskedCard"] == "411111******1111"
    assert sanitized["outer"]["nested"][1]["pan"] == "411111******1111"
    assert sanitized["outer"]["nested"][1]["cvv"] == "***"
    assert sanitized["outer"]["details"]["secretKey"].startswith("s")
    assert sanitized["outer"]["details"]["secretKey"] != "shhhh"
    assert sanitized["outer"]["details"]["sessionKey"].startswith("S")
    assert sanitized["outer"]["details"]["sessionKey"] != "SESSION-123"
    assert payload["outer"]["accessToken"] == "abcdef123456"
    assert payload["outer"]["nested"][0]["tokenId"] == "token-1"
    assert payload["outer"]["details"]["secretKey"] == "shhhh"


def test_client_create_session_token_uses_authorization(monkeypatch):
    security_response = _build_response(text="token-value")
    session_payload = {"sessionKey": "session-123", "expirationTime": "2024-05-01T12:00:00"}
    session_response = _build_response(json_payload=session_payload)

    calls = []

    def fake_request(method, url, headers=None, json=None, timeout=None):
        if "security" in url:
            return security_response
        calls.append(headers.get("Authorization"))
        return session_response

    monkeypatch.setattr(requests, "request", fake_request)
    client = NiubizClient(merchant_id="MID", access_key="AK", secret_key="SK", endpoint="sandbox")

    result = client.create_session_token(amount=10, purchase_number="1-10", currency="PEN")

    assert result["success"] is True
    assert result["session_key"] == "session-123"
    assert calls == ["token-value"]


def test_query_order_status_uses_order_mgmt(monkeypatch):
    security_response = _build_response(text="token-value")
    order_payload = {"statusOrder": "PAID"}
    order_response = _build_response(json_payload=order_payload)

    calls = []

    def fake_request(method, url, headers=None, json=None, timeout=None):
        if "api.security" in url:
            return security_response
        calls.append((method, url, headers, json))
        return order_response

    monkeypatch.setattr(requests, "request", fake_request)
    client = NiubizClient(merchant_id="MID", access_key="AK", secret_key="SK", endpoint="sandbox")

    result = client.query_order_status_by_order_id(order_id="ORDER-1")

    assert result["status"] == "PAID"
    method, url, headers, body = calls[0]
    assert method == "GET"
    assert "api.ordermgmt/api/v1/order/query" in url
    assert url.endswith("/ORDER-1")
    assert headers["Authorization"] == "token-value"
    assert body is None


def test_query_transaction_status_uses_post(monkeypatch):
    security_response = _build_response(text="token-value")
    transaction_payload = {"data": {"STATUS": "CONFIRMED"}}
    transaction_response = _build_response(json_payload=transaction_payload)

    calls = []

    def fake_request(method, url, headers=None, json=None, timeout=None):
        if "api.security" in url:
            return security_response
        calls.append((method, url, headers, json))
        return transaction_response

    monkeypatch.setattr(requests, "request", fake_request)
    client = NiubizClient(merchant_id="MID", access_key="AK", secret_key="SK", endpoint="sandbox")

    result = client.query_transaction_status(transaction_id="T-999")

    assert result["status"] == "CONFIRMED"
    method, url, headers, body = calls[0]
    assert method == "POST"
    assert url.endswith("/transactions/T-999")
    assert headers["Authorization"] == "token-value"
    assert headers["Content-Type"] == "application/json"
    assert body == {"merchantId": "MID"}


def test_authorization_and_confirmation_success(flask_app, monkeypatch):
    registration = _make_registration()
    handler = RHNiubizSuccess()
    handler.registration = registration
    handler.event = registration.event

    class FakeClient:
        def authorize_transaction(self, **kwargs):
            return {
                "success": True,
                "status": "AUTHORIZED",
                "action_code": "000",
                "authorization_code": "123456",
                "transaction_id": "T-100",
                "brand": "VISA",
                "masked_card": "411111******1111",
                "data": {"sample": True},
            }

        def confirm_transaction(self, **kwargs):
            return {
                "success": True,
                "status": "CONFIRMED",
                "action_code": "000",
                "authorization_code": "654321",
                "trace_number": "TRACE",
                "data": {"confirmation": True},
            }

        def tokenize_card(self, data):
            return {"success": False}

    monkeypatch.setattr(RHNiubizSuccess, "_build_client", lambda self: FakeClient())
    monkeypatch.setattr(RHNiubizSuccess, "_get_purchase_number", lambda self: "1-10")
    monkeypatch.setattr(RHNiubizSuccess, "_get_amount", lambda self: 50)
    monkeypatch.setattr(RHNiubizSuccess, "_get_currency", lambda self: "PEN")
    monkeypatch.setattr(RHNiubizSuccess, "_get_client_ip", lambda self: "198.51.100.10")
    monkeypatch.setattr(RHNiubizSuccess, "_get_client_id", lambda self: "client-1")
    monkeypatch.setattr(RHNiubizSuccess, "_get_merchant_id", lambda self: "MERCHANT")
    monkeypatch.setattr(RHNiubizSuccess, "_get_credentials", lambda self: ("ACCESS", "SECRET"))
    monkeypatch.setattr(RHNiubizSuccess, "_get_endpoint", lambda self: "sandbox")
    monkeypatch.setattr("indico_payment_niubiz.controllers.url_for", lambda *a, **k: "redirect-url")
    monkeypatch.setattr("indico_payment_niubiz.controllers.render_template", lambda *a, **k: k)

    monkeypatch.setattr("indico_payment_niubiz.controllers.log_registration_event", lambda *a, **k: None)
    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_successful_payment", lambda *a, **k: registration.set_state(RegistrationState.complete))
    monkeypatch.setattr("indico_payment_niubiz.controllers.handle_failed_payment", lambda *a, **k: None)

    with flask_app.test_request_context(
        "/success/10",
        method="POST",
        data={"transactionToken": "checkout-token"},
        environ_overrides={"REMOTE_ADDR": "198.51.100.10"},
    ):
        result = handler._process()

    registration.set_state.assert_called_once_with(RegistrationState.complete)
    assert result["status_label"] == "CONFIRMED"
    assert result["success"] is True


def test_authorization_failure_redirects(flask_app, monkeypatch):
    registration = _make_registration()
    handler = RHNiubizSuccess()
    handler.registration = registration
    handler.event = registration.event

    class FakeClient:
        def authorize_transaction(self, **kwargs):
            return {"success": False, "error": "denied"}

    monkeypatch.setattr(RHNiubizSuccess, "_build_client", lambda self: FakeClient())
    monkeypatch.setattr(RHNiubizSuccess, "_get_purchase_number", lambda self: "1-10")
    monkeypatch.setattr(RHNiubizSuccess, "_get_amount", lambda self: 50)
    monkeypatch.setattr(RHNiubizSuccess, "_get_currency", lambda self: "PEN")
    monkeypatch.setattr(RHNiubizSuccess, "_get_client_ip", lambda self: "198.51.100.10")
    monkeypatch.setattr(RHNiubizSuccess, "_get_client_id", lambda self: "client-1")
    monkeypatch.setattr(RHNiubizSuccess, "_get_merchant_id", lambda self: "MERCHANT")
    monkeypatch.setattr(RHNiubizSuccess, "_get_credentials", lambda self: ("ACCESS", "SECRET"))
    monkeypatch.setattr(RHNiubizSuccess, "_get_endpoint", lambda self: "sandbox")
    monkeypatch.setattr("indico_payment_niubiz.controllers.url_for", lambda *a, **k: "redirect-url")
    monkeypatch.setattr("indico_payment_niubiz.controllers.render_template", lambda *a, **k: k)

    with flask_app.test_request_context(
        "/success/10",
        method="POST",
        data={"transactionToken": "checkout-token"},
        environ_overrides={"REMOTE_ADDR": "198.51.100.10"},
    ):
        result = handler._process()

    assert result.status_code == 302
def test_client_yape_transaction(monkeypatch):
    security_response = _build_response(text="token")
    payload = {
        "data": {
            "ACTION_CODE": "000",
            "STATUS": "AUTHORIZED",
            "TRANSACTION_ID": "T-200",
            "BRAND": "YAPE",
        }
    }
    yape_response = _build_response(json_payload=payload)

    def fake_request(method, url, headers=None, json=None, timeout=None):
        if "security" in url:
            return security_response
        return yape_response

    monkeypatch.setattr(requests, "request", fake_request)
    client = NiubizClient(merchant_id="MID", access_key="AK", secret_key="SK", endpoint="sandbox")

    result = client.yape_transaction(phone="999999999", otp="123456", amount=10, purchase_number="1-10", currency="PEN")

    assert result["transaction_id"] == "T-200"
    assert result["status"] == "AUTHORIZED"


def test_client_pagoefectivo_transaction(monkeypatch):
    security_response = _build_response(text="token")
    payload = {
        "data": {
            "ACTION_CODE": "000",
            "STATUS": "PENDING",
            "TRANSACTION_ID": "T-300",
            "order": {"cip": "12345678"},
        }
    }
    pago_response = _build_response(json_payload=payload)

    def fake_request(method, url, headers=None, json=None, timeout=None):
        if "security" in url:
            return security_response
        return pago_response

    monkeypatch.setattr(requests, "request", fake_request)
    client = NiubizClient(merchant_id="MID", access_key="AK", secret_key="SK", endpoint="sandbox")

    result = client.pagoefectivo_transaction(amount=20, purchase_number="1-10", currency="PEN")

    assert result["transaction_id"] == "T-300"
    assert result["status"] == "PENDING"
