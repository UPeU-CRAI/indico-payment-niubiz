import logging
from typing import Iterable

import requests_mock as requests_mock_lib

import pytest

from indico_payment_niubiz.client import (
    ORDER_BATCH_QUERY_ENDPOINTS,
    ORDER_QUERY_ENDPOINTS,
    ORDER_QUERY_EXTERNAL_ENDPOINTS,
    REFUND_ENDPOINTS,
    REVERSAL_ENDPOINTS,
    SECURITY_ENDPOINTS,
    NiubizClient,
    clear_token_cache,
)


@pytest.fixture(autouse=True)
def _clear_token_cache() -> Iterable[None]:
    clear_token_cache()
    yield
    clear_token_cache()


@pytest.fixture
def requests_mock():
    with requests_mock_lib.Mocker() as mock:
        yield mock


def _register_security_tokens(requests_mock, tokens):
    url = SECURITY_ENDPOINTS["sandbox"]
    if len(tokens) == 1:
        requests_mock.get(url, json={"accessToken": tokens[0], "expiresIn": 600})
    else:
        responses = [
            {"status_code": 200, "json": {"accessToken": token, "expiresIn": 600}}
            for token in tokens
        ]
        requests_mock.get(url, responses)


def _make_client() -> NiubizClient:
    return NiubizClient(
        merchant_id="MERCHANT",
        access_key="ACCESS",
        secret_key="SECRET",
        endpoint="sandbox",
    )


def test_refund_transaction_success(requests_mock, caplog):
    _register_security_tokens(requests_mock, ["token-1"])
    refund_url = REFUND_ENDPOINTS["sandbox"].format(merchant_id="MERCHANT", transaction_id="T-1")
    requests_mock.post(
        refund_url,
        json={"data": {"STATUS": "S", "transactionId": "T-1", "ACTION_CODE": "000"}},
    )

    client = _make_client()

    caplog.set_level(logging.INFO, logger="indico_payment_niubiz.client")
    result = client.refund_transaction(transaction_id="T-1", amount=25, currency="PEN")

    assert result["success"] is True
    assert result["status"] == "S"
    assert result["transaction_id"] == "T-1"
    assert result["access_token"] == "token-1"
    assert any("Refunded transaction T-1" in record.message for record in caplog.records)


def test_refund_transaction_refreshes_token_on_401(requests_mock, caplog):
    _register_security_tokens(requests_mock, ["token-old", "token-new"])
    refund_url = REFUND_ENDPOINTS["sandbox"].format(merchant_id="MERCHANT", transaction_id="T-2")
    requests_mock.post(
        refund_url,
        [
            {"status_code": 401, "json": {"message": "Token expired"}},
            {"status_code": 200, "json": {"data": {"STATUS": "S", "transactionId": "T-2"}}},
        ],
    )

    client = _make_client()

    caplog.set_level(logging.INFO, logger="indico_payment_niubiz.client")
    result = client.refund_transaction(transaction_id="T-2", amount=40, currency="PEN")

    assert result["success"] is True
    assert result["transaction_id"] == "T-2"
    assert any("Refunded transaction T-2" in record.message for record in caplog.records)

    # One security request (initial), one failed refund, token refresh, and retry.
    history = requests_mock.request_history
    assert [request.method for request in history] == ["GET", "POST", "GET", "POST"]
    assert history[-1].headers["Authorization"] == "token-new"


def test_refund_transaction_invalid_payload_logs_error(requests_mock, caplog):
    _register_security_tokens(requests_mock, ["token-err"])
    refund_url = REFUND_ENDPOINTS["sandbox"].format(merchant_id="MERCHANT", transaction_id="T-3")
    requests_mock.post(
        refund_url,
        status_code=400,
        json={"message": "Invalid payload"},
    )

    client = _make_client()

    caplog.set_level(logging.ERROR, logger="indico_payment_niubiz.client")
    result = client.refund_transaction(transaction_id="T-3", amount=10, currency="PEN")

    assert result["success"] is False
    assert result["status_code"] == 400
    assert any("Failed to refund transaction T-3" in record.message for record in caplog.records)


def test_refund_transaction_requires_transaction_id():
    client = _make_client()
    with pytest.raises(ValueError):
        client.refund_transaction(transaction_id="", amount=10, currency="PEN")


def test_reverse_transaction_success(requests_mock, caplog):
    _register_security_tokens(requests_mock, ["token-rev"])
    reversal_url = REVERSAL_ENDPOINTS["sandbox"].format(merchant_id="MERCHANT")
    requests_mock.post(
        reversal_url,
        json={"data": {"STATUS": "S", "transactionId": "T-4", "ACTION_CODE": "000"}},
    )

    client = _make_client()

    caplog.set_level(logging.INFO, logger="indico_payment_niubiz.client")
    result = client.reverse_transaction(transaction_id="T-4", amount=50, currency="PEN")

    assert result["success"] is True
    assert result["transaction_id"] == "T-4"
    assert any("Reversed transaction T-4" in record.message for record in caplog.records)


def test_reverse_transaction_error_logs(requests_mock, caplog):
    _register_security_tokens(requests_mock, ["token-rev"])
    reversal_url = REVERSAL_ENDPOINTS["sandbox"].format(merchant_id="MERCHANT")
    requests_mock.post(
        reversal_url,
        status_code=409,
        json={"message": "Cannot reverse"},
    )

    client = _make_client()

    caplog.set_level(logging.ERROR, logger="indico_payment_niubiz.client")
    result = client.reverse_transaction(transaction_id="T-5", amount=15, currency="PEN")

    assert result["success"] is False
    assert result["status_code"] == 409
    assert any("Failed to reverse transaction T-5" in record.message for record in caplog.records)


@pytest.mark.parametrize(
    "status",
    ["PENDING", "COMPLETED", "CANCELED", "EXPIRED"],
)
def test_query_order_statuses(requests_mock, caplog, status):
    _register_security_tokens(requests_mock, ["token-order"])
    order_url = ORDER_QUERY_ENDPOINTS["sandbox"].format(merchant_id="MERCHANT", order_id="ORDER-1")
    requests_mock.get(order_url, json={"order": {"status": status}})

    client = _make_client()

    caplog.set_level(logging.INFO, logger="indico_payment_niubiz.client")
    result = client.query_order("ORDER-1")

    assert result["order"]["status"] == status
    assert any(status in record.message for record in caplog.records)


def test_query_order_external_success(requests_mock):
    _register_security_tokens(requests_mock, ["token-order-external"])
    url = ORDER_QUERY_EXTERNAL_ENDPOINTS["sandbox"].format(merchant_id="MERCHANT", external_id="EXT-1")
    requests_mock.get(url, json={"order": {"status": "COMPLETED", "id": "EXT-1"}})

    client = _make_client()

    result = client.query_order_external("EXT-1")

    assert result["order"]["status"] == "COMPLETED"
    assert result["access_token"] == "token-order-external"


def test_query_order_batch_success(requests_mock):
    _register_security_tokens(requests_mock, ["token-batch"])
    url = ORDER_BATCH_QUERY_ENDPOINTS["sandbox"].format(merchant_id="MERCHANT", batch_id="BATCH-1")
    requests_mock.get(url, json={"batch": {"status": "COMPLETED", "id": "BATCH-1"}})

    client = _make_client()

    result = client.query_order_batch("BATCH-1")

    assert result["batch"]["status"] == "COMPLETED"
    assert result["access_token"] == "token-batch"


@pytest.mark.parametrize(
    "method_name",
    [
        ("query_order", {"order_id": ""}),
        ("query_order_external", {"external_id": ""}),
        ("query_order_batch", {"batch_id": ""}),
        ("reverse_transaction", {"transaction_id": "", "amount": 1, "currency": "PEN"}),
        ("confirm_transaction", {"transaction_id": ""}),
    ],
)
def test_parameter_validation(method_name):
    method, kwargs = method_name
    client = _make_client()

    with pytest.raises(ValueError):
        getattr(client, method)(**kwargs)
