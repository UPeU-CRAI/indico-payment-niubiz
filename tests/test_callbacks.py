from unittest.mock import MagicMock

import pytest

from indico.modules.events.payment.models.transactions import TransactionAction


@pytest.fixture
def registration(db, create_event, dummy_user):
    event = create_event()
    regform = event.add_registration_form(title="Test form", currency="PEN")
    registration = regform.create_registration(dummy_user, {"first_name": "Dummy", "last_name": "User"})
    db.session.add(registration)
    db.session.flush()
    return registration


def test_start_view_generates_session(client, monkeypatch, registration):
    fake_client = MagicMock()
    fake_client.create_session.return_value = {"sessionKey": "sess-1"}
    fake_client.merchant_id = "mid"
    fake_client.endpoint = "sandbox"

    monkeypatch.setattr("indico_payment_niubiz.views._load_registration", lambda **_: registration)
    monkeypatch.setattr("indico_payment_niubiz.views._build_client", lambda event: fake_client)
    monkeypatch.setattr("indico_payment_niubiz.views.generate_external_transaction_id", lambda: "ext-123")

    resp = client.post(
        "/payment/niubiz/start",
        json={
            "event_id": registration.event_id,
            "reg_form_id": registration.registration_form.id,
            "registration_id": registration.id,
            "amount": "100.00",
            "currency": "PEN",
        },
    )

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["sessionKey"] == "sess-1"
    assert payload["externalTransactionId"] == "ext-123"
    fake_client.create_session.assert_called_once()


def test_return_view_calls_push_payment(client, monkeypatch, registration):
    registration.is_paid = False

    fake_client = MagicMock()
    fake_client.get_token_card.return_value = {"token": "card-token"}
    fake_client.push_payment.return_value = {
        "status": "AUTHORIZED",
        "actionCode": "000",
        "transactionIdentifier": "ABC123",
    }

    handled = {}

    def fake_success(registration, **kwargs):
        handled.update(kwargs)
        return MagicMock(action=TransactionAction.complete)

    monkeypatch.setattr("indico_payment_niubiz.views._load_registration", lambda **_: registration)
    monkeypatch.setattr("indico_payment_niubiz.views._build_client", lambda event: fake_client)
    monkeypatch.setattr("indico_payment_niubiz.views.handle_successful_payment", fake_success)
    monkeypatch.setattr("indico_payment_niubiz.views.handle_pending_payment", lambda *_, **__: None)
    monkeypatch.setattr("indico_payment_niubiz.views.handle_failed_payment", lambda *_, **__: None)
    monkeypatch.setattr("indico_payment_niubiz.views.handle_refund", lambda *_, **__: None)

    resp = client.post(
        "/payment/niubiz/return",
        json={
            "purchaseNumber": f"{registration.event_id}-{registration.id}",
            "transactionToken": "token",
            "sessionKey": "sess",
            "externalTransactionId": "ext-1",
            "amount": "100.00",
            "currency": "PEN",
            "reg_form_id": registration.registration_form.id,
        },
    )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["transactionIdentifier"] == "ABC123"
    assert handled["data"]["purchase_number"] == f"{registration.event_id}-{registration.id}"
    assert handled["data"]["external_transaction_id"] == "ext-1"


def test_notify_view_enforces_security(client, monkeypatch, registration):
    payload = {
        "reg_form_id": registration.registration_form.id,
        "purchaseNumber": f"{registration.event_id}-{registration.id}",
        "status": "AUTHORIZED",
        "transactionId": "TXN-1",
        "amount": "100.00",
        "currency": "PEN",
    }

    monkeypatch.setattr("indico_payment_niubiz.views._load_registration", lambda **_: registration)
    monkeypatch.setattr("indico_payment_niubiz.views._validate_callback_security", lambda *_, **__: None)
    monkeypatch.setattr("indico_payment_niubiz.views.handle_successful_payment", lambda *_, **__: None)
    monkeypatch.setattr("indico_payment_niubiz.views.handle_pending_payment", lambda *_, **__: None)
    monkeypatch.setattr("indico_payment_niubiz.views.handle_failed_payment", lambda *_, **__: None)
    monkeypatch.setattr("indico_payment_niubiz.views.handle_refund", lambda *_, **__: None)

    resp = client.post(
        "/payment/niubiz/notify",
        json=payload,
        headers={"Content-Type": "application/json"},
    )

    assert resp.status_code == 200
    assert resp.get_json()["received"] is True
