from decimal import Decimal

import pytest
import responses

from indico_payment_niubiz.client import NiubizClient


@pytest.fixture
def client():
    return NiubizClient(
        merchant_id="123456789",
        access_key="fake-access",
        secret_key="fake-secret",
        endpoint="sandbox",
    )


def add_token_response(client):
    token_url = f"{client.base_url}/api.security/v1/security"
    responses.add("POST", token_url, body='"abc123"', status=200)


@responses.activate
def test_refund_transaction_success(client):
    add_token_response(client)
    refund_url = (
        f"{client.base_url}/api.ecommerce/v2/ecommerce/token/{client.merchant_id}/refund"
    )
    responses.add(
        "POST",
        refund_url,
        json={"status": "REFUNDED", "transactionId": "TXN-1"},
        status=200,
    )

    result = client.refund_transaction("TXN-1", Decimal("20.0"), "PEN")
    assert result.success is True
    assert result.status == "REFUNDED"
    assert result.transaction_id == "TXN-1"
    assert result.action == "refund"


@responses.activate
def test_reverse_payment_falls_back_to_void(client):
    add_token_response(client)
    refund_url = (
        f"{client.base_url}/api.ecommerce/v2/ecommerce/token/{client.merchant_id}/refund"
    )
    void_url = f"{client.base_url}/api.authorization/v3/authorization/{client.merchant_id}/void"

    responses.add(
        "POST",
        refund_url,
        json={"status": "FAILED", "transactionId": "TXN-99", "error": "not captured"},
        status=200,
    )
    responses.add(
        "POST",
        void_url,
        json={"status": "VOIDED", "transactionId": "TXN-99"},
        status=200,
    )

    result = client.reverse_payment("TXN-99", Decimal("15.5"), "PEN", reason="Test")
    assert result.success is True
    assert result.action == "void"
    assert result.status == "VOIDED"
    assert result.data["refund"]["status"] == "FAILED"
    assert len(responses.calls) == 3
