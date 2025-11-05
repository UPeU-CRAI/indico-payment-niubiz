import pytest
from decimal import Decimal

from indico.modules.events.payment.models.transactions import TransactionAction


@pytest.fixture
def plugin(app):
    from indico_payment_niubiz.plugin import NiubizPlugin

    return NiubizPlugin.instance


@pytest.fixture
def registration(db, create_event, dummy_user):
    event = create_event()
    regform = event.add_registration_form(title="Test form", currency="PEN")
    registration = regform.create_registration(
        dummy_user,
        {"first_name": "Dummy", "last_name": "User"},
    )
    registration.price = Decimal("150.50")
    registration.currency = "PEN"
    registration.email = dummy_user.email
    db.session.add(registration)
    db.session.flush()
    return registration


@pytest.fixture
def start_url(registration):
    return (
        f"/event/{registration.event_id}/registrations/{registration.registration_form.id}"
        f"/payment/niubiz/{registration.id}/start"
    )


@pytest.fixture
def success_url(registration):
    return (
        f"/event/{registration.event_id}/registrations/{registration.registration_form.id}"
        f"/payment/niubiz/{registration.id}/success"
    )


@pytest.fixture
def cancel_url(registration):
    return (
        f"/event/{registration.event_id}/registrations/{registration.registration_form.id}"
        f"/payment/niubiz/{registration.id}/cancel"
    )


def test_start_returns_session_data(client, plugin, registration, start_url, monkeypatch):
    class DummyClient:
        def create_session(
            self,
            *,
            amount,
            currency,
            purchase_number,
            channel,
            payment_method,
            data_map,
            antifraud,
            token_id=None,
        ):
            assert amount == Decimal("150.50")
            assert currency == "PEN"
            assert purchase_number == f"{registration.event_id}-{registration.id}"
            assert channel == "paycard"
            assert payment_method == "card"
            assert data_map["MDD4"] == registration.email
            assert data_map["MDD57"] == "PushPayments"
            assert "merchantDefineData" in antifraud
            assert antifraud.get("deviceFingerprintId") == "fp-123"
            return {
                "success": True,
                "data": {
                    "sessionKey": "sess-123",
                    "expirationTime": "2025-01-01T00:00:00Z",
                },
            }

    monkeypatch.setattr(plugin, "_build_client", lambda event: DummyClient())

    response = client.post(
        start_url,
        data={"method": "card", "device_fingerprint_id": "fp-123"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["payment_channel"] == "card"
    assert payload["sessionKey"] == "sess-123"
    assert payload["session_expiration"] == "2025-01-01T00:00:00Z"
    assert payload["purchase_number"] == f"{registration.event_id}-{registration.id}"
    assert payload["amount"] == "150.50"
    assert payload["currency"] == "PEN"
    assert payload["merchantDefinedData"]["MDD4"] == registration.email


def test_start_requires_fingerprint(client, start_url):
    response = client.post(start_url, data={"method": "card"})
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["success"] is False
    assert payload["error"] == "missing_fingerprint"


def test_success_endpoint_marks_registration_paid(client, db, registration, success_url):
    registration.price = Decimal("120.00")
    registration.currency = "PEN"
    db.session.flush()

    response = client.get(
        success_url + "?transactionId=TX-1&status=AUTHORIZED&actionCode=000"
    )
    assert response.status_code == 302
    with client.application.test_request_context():
        expected_url = registration.display_regform_url
    assert response.location == expected_url

    db.session.refresh(registration)
    assert registration.is_paid is True
    transaction = registration.transaction
    assert transaction is not None
    assert transaction.action == TransactionAction.complete
    assert transaction.data.get("source") == "success"

    with client.session_transaction() as session:
        flashes = session.get("_flashes", [])
    assert any(msg == "Tu pago con Niubiz se registró correctamente." for _, msg in flashes)


def test_cancel_endpoint_registers_failure(client, db, registration, cancel_url):
    registration.price = Decimal("80.00")
    registration.currency = "PEN"
    db.session.flush()

    response = client.get(
        cancel_url + "?transactionId=TX-2&status=CANCELLED&actionCode=999"
    )
    assert response.status_code == 302
    with client.application.test_request_context():
        expected_url = registration.display_regform_url
    assert response.location == expected_url

    db.session.refresh(registration)
    assert registration.is_paid is False
    transaction = registration.transaction
    assert transaction is not None
    assert transaction.action == TransactionAction.cancel
    assert transaction.data.get("source") == "cancel"

    with client.session_transaction() as session:
        flashes = session.get("_flashes", [])
    assert any(
        msg == "El pago fue cancelado. Puedes intentarlo nuevamente cuando desees."
        for _, msg in flashes
    )
