import json

import json
from decimal import Decimal

import pytest
import responses

from indico_payment_niubiz.client import NiubizAuthError, NiubizClient


@pytest.fixture
def client():
    return NiubizClient(
        merchant_id="123456789",
        client_id="fake-client",
        client_secret="fake-secret",
        username="fake-user",
        password="fake-pass",
        realm_code="test-realm",
        endpoint="sandbox"
    )


# ----------------------
# Helper para stub
# ----------------------
def add_response(method, url, status=200, body=None, json_data=None):
    if json_data is not None:
        body = json.dumps(json_data)
    responses.add(method, url, body=body, status=status, content_type="application/json")


# ----------------------
# Auth / sesión
# ----------------------
@responses.activate
def test_get_auth_token_ok(client):
    url = f"{client.base_url}{client.SECURITY_PATH}"
    add_response("POST", url, json_data={"accessToken": "abc123"})

    token = client.get_auth_token()
    assert token == "abc123"
    # Cached en segunda llamada
    token2 = client.get_auth_token()
    assert token2 == "abc123"
    security_calls = [call for call in responses.calls if call.request.url == url]
    assert len(security_calls) == 1

    protected_url = f"{client.base_url}/dummy"
    add_response("GET", protected_url, json_data={"ok": True})
    client._request("GET", "/dummy")
    auth_header = responses.calls[-1].request.headers["Authorization"]
    assert auth_header.startswith("Bearer ")
    assert auth_header.endswith("abc123")


@responses.activate
def test_get_auth_token_fail(client):
    url = f"{client.base_url}{client.SECURITY_PATH}"
    responses.add("POST", url, status=500)

    with pytest.raises(NiubizAuthError):
        client.get_auth_token()


@responses.activate
def test_get_auth_token_plain_text(client):
    url = f"{client.base_url}{client.SECURITY_PATH}"
    responses.add("POST", url, body="abc123", status=200, content_type="text/plain")

    with pytest.raises(NiubizAuthError):
        client.get_auth_token()


# ----------------------
# Órdenes
# ----------------------
@responses.activate
def test_create_session_ok(client):
    url = f"{client.base_url}/api.ecommerce/v2/ecommerce/token/session/{client.merchant_id}"
    add_response("POST", url, json_data={"sessionKey": "sess-123", "status": "AUTHORIZED"})

    result = client.create_session(
        amount=Decimal("10.50"),
        currency="PEN",
        purchase_number="1-100",
        payment_method="card",
        data_map={"MDD4": "test@example.com", "MDD57": "PushPayments"},
        antifraud={"merchantDefineData": {"MDD4": "test@example.com"}},
    )
    assert result["success"]
    assert result["data"]["sessionKey"] == "sess-123"


@responses.activate
def test_get_order_status_ok(client):
    url = f"{client.base_url}/api.ecommerce/v2/ecommerce/token/order/{client.merchant_id}/ORD-123"
    add_response("GET", url, json_data={"status": "PENDING"})

    result = client.get_order_status("ORD-123")
    assert result["success"]
    assert result["data"]["status"] == "PENDING"


# ----------------------
# Refunds
# ----------------------
@responses.activate
def test_refund_transaction_success(client):
    url = f"{client.base_url}/api.ecommerce/v2/ecommerce/token/{client.merchant_id}/refund"
    add_response("POST", url, json_data={"status": "REFUNDED", "transactionId": "TXN-1"})

    result = client.refund_transaction("TXN-1", Decimal("20.0"), "PEN", reason="Test refund")
    assert result["success"]
    assert result["status"] == "REFUNDED"
    assert result["transaction_id"] == "TXN-1"


@responses.activate
def test_refund_transaction_fail(client):
    url = f"{client.base_url}/api.ecommerce/v2/ecommerce/token/{client.merchant_id}/refund"
    add_response("POST", url, json_data={"status": "FAILED", "transactionId": "TXN-2"})

    result = client.refund_transaction("TXN-2", Decimal("20.0"), "PEN")
    assert not result["success"]
    assert result["status"] == "FAILED"


# ----------------------
# Capture
# ----------------------
@responses.activate
def test_capture_payment_ok(client):
    url = f"{client.base_url}/api.authorization/v3/authorization/{client.merchant_id}/capture"
    add_response("POST", url, json_data={"status": "CAPTURED", "transactionId": "TXN-3"})

    result = client.capture_payment("TXN-3")
    assert result["success"]
    assert result["status"] == "CAPTURED"


@responses.activate
def test_capture_payment_fail(client):
    url = f"{client.base_url}/api.authorization/v3/authorization/{client.merchant_id}/capture"
    add_response("POST", url, json_data={"status": "DECLINED", "transactionId": "TXN-4"})

    result = client.capture_payment("TXN-4")
    assert not result["success"]
    assert result["status"] == "DECLINED"


# ----------------------
# Void
# ----------------------
@responses.activate
def test_void_payment_ok(client):
    url = f"{client.base_url}/api.authorization/v3/authorization/{client.merchant_id}/void"
    add_response("POST", url, json_data={"status": "VOIDED", "transactionId": "TXN-5"})

    result = client.void_payment("TXN-5")
    assert result["success"]
    assert result["status"] == "VOIDED"


@responses.activate
def test_void_payment_fail(client):
    url = f"{client.base_url}/api.authorization/v3/authorization/{client.merchant_id}/void"
    add_response("POST", url, json_data={"status": "FAILED", "transactionId": "TXN-6"})

    result = client.void_payment("TXN-6")
    assert not result["success"]
    assert result["status"] == "FAILED"
# ----------------------
# Tokenización y Push
# ----------------------
@responses.activate
def test_verify_transaction_token_ok(client):
    token = "txn-token"
    url = f"{client.base_url}/api.ecommerce/v2/ecommerce/token/card/{client.merchant_id}/{token}"
    add_response("GET", url, json_data={"order": {"actionCode": "000"}, "card": {"tokenId": "tok-1"}})

    result = client.verify_transaction_token(token)
    assert result["success"]
    assert result["data"]["card"]["tokenId"] == "tok-1"


@responses.activate
def test_push_payment_success(client):
    url = f"{client.base_url}/api.instantpayments/pushpayment/{client.merchant_id}"
    add_response(
        "POST",
        url,
        json_data={"actionCode": "00", "transactionId": "TX-1", "status": "CAPTURED"},
    )

    result = client.push_payment(
        purchase_number="1-100",
        amount=Decimal("20.00"),
        currency="PEN",
        external_transaction_id="ext-1",
        token_id="tok-1",
        payer_email="test@example.com",
    )
    assert result["success"]
    assert result["transaction_id"] == "TX-1"


@responses.activate
def test_push_payment_failure(client):
    url = f"{client.base_url}/api.instantpayments/pushpayment/{client.merchant_id}"
    add_response(
        "POST",
        url,
        json_data={"actionCode": "05", "transactionId": "TX-2", "status": "DECLINED"},
    )

    result = client.push_payment(
        purchase_number="1-100",
        amount=Decimal("20.00"),
        currency="PEN",
        external_transaction_id="ext-2",
        token_id="tok-2",
        payer_email="test@example.com",
    )
    assert not result["success"]
    assert result["action_code"] == "05"


