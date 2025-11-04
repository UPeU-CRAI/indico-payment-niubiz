import json
from decimal import Decimal

import pytest
import responses

from indico_payment_niubiz.client import (
    NiubizAPIError,
    NiubizAuthError,
    NiubizClient,
)


@pytest.fixture
def client():
    return NiubizClient(
        merchant_id="123456789",
        access_key="fake-access",
        secret_key="fake-secret",
        endpoint="sandbox",
    )


def _add_response(method, url, *, status=200, json_data=None, body=None):
    if json_data is not None:
        body = json.dumps(json_data)
    responses.add(method, url, body=body, status=status, content_type="application/json")


@responses.activate
def test_get_access_token_cached(client):
    url = f"{client.base_url}/api.security/v1/security"
    _add_response("POST", url, json_data={"accessToken": "abc123"})

    token1 = client.get_access_token()
    token2 = client.get_access_token()

    assert token1 == "abc123"
    assert token2 == "abc123"
    assert len(responses.calls) == 1


@responses.activate
def test_get_access_token_failure(client):
    url = f"{client.base_url}/api.security/v1/security"
    responses.add("POST", url, status=500)

    with pytest.raises(NiubizAuthError):
        client.get_access_token(force_refresh=True)


@responses.activate
def test_create_session_adds_idempotency_header(client):
    security_url = f"{client.base_url}/api.security/v1/security"
    _add_response("POST", security_url, json_data={"accessToken": "token"})

    session_url = f"{client.base_url}/api.ecommerce/v2/ecommerce/token/session/{client.merchant_id}"
    _add_response("POST", session_url, json_data={"sessionKey": "sess-123"})

    response = client.create_session(amount=Decimal("10.50"), currency="PEN", purchase_number="1-100")

    assert response["sessionKey"] == "sess-123"
    headers = responses.calls[1].request.headers
    assert headers.get("Idempotency-Key") == "1-100"


@responses.activate
def test_get_token_card_returns_payload(client):
    security_url = f"{client.base_url}/api.security/v1/security"
    _add_response("POST", security_url, json_data={"accessToken": "token"})

    card_url = f"{client.base_url}/api.ecommerce/v2/ecommerce/token/card/{client.merchant_id}"
    _add_response("POST", card_url, json_data={"token": "card-token"})

    payload = client.get_token_card(transaction_token="txn-token", session_key="sess-1", purchase_number="1-2")
    assert payload["token"] == "card-token"


@responses.activate
def test_push_payment_retries_on_429(client, monkeypatch):
    security_url = f"{client.base_url}/api.security/v1/security"
    _add_response("POST", security_url, json_data={"accessToken": "token"})

    push_url = f"{client.base_url}/api.authorization/v3/authorization/{client.merchant_id}/push"
    _add_response("POST", push_url, status=429)
    _add_response("POST", push_url, json_data={"actionCode": "000", "transactionIdentifier": "ABC"})

    monkeypatch.setattr(client, "_sleep", lambda value: None)

    payload = client.push_payment(
        amount=Decimal("20"),
        currency="PEN",
        purchase_number="1-3",
        external_transaction_id="ext-1",
        card_token="card-token",
    )

    assert payload["actionCode"] == "000"
    assert len(responses.calls) == 3  # auth + two push attempts
    headers = responses.calls[-1].request.headers
    assert headers.get("Idempotency-Key") == "1-3:ext-1"


@responses.activate
def test_push_payment_error_raises(client, monkeypatch):
    security_url = f"{client.base_url}/api.security/v1/security"
    _add_response("POST", security_url, json_data={"accessToken": "token"})

    push_url = f"{client.base_url}/api.authorization/v3/authorization/{client.merchant_id}/push"
    responses.add("POST", push_url, status=500)

    with pytest.raises(NiubizAPIError):
        client.push_payment(
            amount="10",
            currency="PEN",
            purchase_number="1-4",
            external_transaction_id="ext-2",
            card_token="token",
        )
