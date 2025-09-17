from types import SimpleNamespace

import requests

from indico_payment_niubiz.client import NiubizClient


class DummyResponse:
    def __init__(self, *, json_payload=None, text="", status_code=200):
        self._json_payload = json_payload
        self.text = text
        self.status_code = status_code

    def json(self):
        if self._json_payload is None:
            raise ValueError
        return self._json_payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


def test_authorize_transaction_success(monkeypatch):
    security_response = DummyResponse(json_payload={"accessToken": "sec-token", "expiresIn": 600})
    authorization_payload = {
        "data": {
            "order": {
                "STATUS": "Authorized",
                "ACTION_CODE": "000",
                "TRANSACTION_ID": "T-123",
                "AUTHORIZATION_CODE": "654321",
            },
            "card": {"BRAND": "VISA", "PAN": "411111******1111"},
            "traceNumber": "TRACE-1",
        }
    }
    authorization_response = DummyResponse(json_payload=authorization_payload)

    calls = []

    def fake_request(method, url, headers=None, json=None, timeout=None):
        if "api.security" in url:
            return security_response
        calls.append(SimpleNamespace(method=method, url=url, headers=headers, json=json))
        return authorization_response

    monkeypatch.setattr(requests, "request", fake_request)
    client = NiubizClient(merchant_id="MERCHANT", access_key="ACCESS", secret_key="SECRET", endpoint="sandbox")

    result = client.authorize_transaction(
        transaction_token="TOKEN-123",
        purchase_number="ORDER-1",
        amount=10.5,
        currency="PEN",
        client_ip="203.0.113.20",
        client_id="client-abc",
    )

    assert result["success"] is True
    assert result["status"] == "Authorized"
    assert result["transaction_id"] == "T-123"
    assert result["trace_number"] == "TRACE-1"
    assert result["brand"] == "VISA"
    assert result["access_token"] == "sec-token"

    assert len(calls) == 1
    call = calls[0]
    assert call.method == "POST"
    assert call.url.endswith("/api.authorization/v3/authorization/ecommerce/MERCHANT")
    assert call.headers["Authorization"] == "sec-token"
    assert call.json["order"]["purchaseNumber"] == "ORDER-1"
    assert call.json["order"]["tokenId"] == "TOKEN-123"
    assert call.json["order"]["amount"] == 10.5
    assert call.json["order"]["currency"] == "PEN"
    assert call.json["dataMap"]["clientIp"] == "203.0.113.20"
    assert call.json["dataMap"]["clientId"] == "client-abc"


def test_refund_transaction_success(monkeypatch):
    security_response = DummyResponse(json_payload={"accessToken": "sec-token", "expiresIn": 600})
    refund_payload = {"data": {"STATUS": "Refunded", "transactionId": "T-1"}}
    refund_response = DummyResponse(json_payload=refund_payload)

    calls = []

    def fake_request(method, url, headers=None, json=None, timeout=None):
        if "api.security" in url:
            return security_response
        calls.append(SimpleNamespace(method=method, url=url, headers=headers, json=json))
        return refund_response

    monkeypatch.setattr(requests, "request", fake_request)
    client = NiubizClient(merchant_id="MERCHANT", access_key="ACCESS", secret_key="SECRET", endpoint="sandbox")

    result = client.refund_transaction(
        transaction_id="T-1",
        amount=25,
        currency="PEN",
        reason="Customer request",
    )

    assert result["success"] is True
    assert result["status"] == "Refunded"
    assert result["transaction_id"] == "T-1"
    assert result["access_token"] == "sec-token"

    assert len(calls) == 1
    call = calls[0]
    assert call.method == "POST"
    assert call.url.endswith("/api.refund/v1/refund/MERCHANT/T-1")
    assert call.headers["Authorization"] == "sec-token"
    assert call.json == {"amount": 25.0, "currency": "PEN", "reason": "Customer request"}


def test_reverse_transaction_success(monkeypatch):
    security_response = DummyResponse(json_payload={"accessToken": "sec-token", "expiresIn": 600})
    reversal_payload = {"data": {"STATUS": "Voided", "transactionId": "T-2"}}
    reversal_response = DummyResponse(json_payload=reversal_payload)

    calls = []

    def fake_request(method, url, headers=None, json=None, timeout=None):
        if "api.security" in url:
            return security_response
        calls.append(SimpleNamespace(method=method, url=url, headers=headers, json=json))
        return reversal_response

    monkeypatch.setattr(requests, "request", fake_request)
    client = NiubizClient(merchant_id="MERCHANT", access_key="ACCESS", secret_key="SECRET", endpoint="sandbox")

    result = client.reverse_transaction(transaction_id="T-2", amount=30, currency="PEN")

    assert result["success"] is True
    assert result["status"] == "Voided"
    assert result["transaction_id"] == "T-2"
    assert result["access_token"] == "sec-token"

    assert len(calls) == 1
    call = calls[0]
    assert call.method == "POST"
    assert call.url.endswith("/api.authorization/v3/reverse/ecommerce/MERCHANT")
    assert call.headers["Authorization"] == "sec-token"
    assert call.json == {"transactionId": "T-2", "amount": 30.0, "currency": "PEN"}
