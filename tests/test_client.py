import json
import pytest
import responses
from decimal import Decimal

from indico_payment_niubiz.client import NiubizClient, NiubizAPIError


@pytest.fixture
def client():
    return NiubizClient(
        merchant_id="123456789",
        access_key="fake-access",
        secret_key="fake-secret",
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
    url = f"{client.base_url}/api.security/v1/security"
    add_response("POST", url, json_data={"accessToken": "abc123"})

    token = client.get_auth_token()
    assert token == "abc123"
    # Cached en segunda llamada
    token2 = client.get_auth_token()
    assert token2 == "abc123"


@responses.activate
def test_get_auth_token_fail(client):
    url = f"{client.base_url}/api.security/v1/security"
    responses.add("POST", url, status=500)

    with pytest.raises(NiubizAPIError):
        client.get_auth_token()


# ----------------------
# Órdenes
# ----------------------
@responses.activate
def test_create_order_ok(client):
    url = f"{client.base_url}/api.ecommerce/v2/ecommerce/token/session/{client.merchant_id}"
    add_response("POST", url, json_data={"sessionKey": "sess-123", "status": "AUTHORIZED"})

    result = client.create_order(Decimal("10.50"), "PEN", "1-100")
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
