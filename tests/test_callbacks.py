import hashlib
import hmac
import ipaddress
from decimal import Decimal

import pytest
from flask import url_for

from indico.modules.events.payment.models.transactions import TransactionAction
from indico_payment_niubiz.status_mapping import NIUBIZ_STATUS_MAP


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _make_payload(status="AUTHORIZED", purchase_number="1-1", txn_id="abc123", amount="100.00"):
    return {
        "purchaseNumber": purchase_number,
        "transactionId": txn_id,
        "STATUS": status,
        "amount": amount,
        "currency": "PEN",
        "actionCode": "000",
    }


def _make_signature(secret, payload_bytes):
    return hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256).hexdigest()


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------
@pytest.fixture
def plugin(app):
    """Obtener el plugin Niubiz ya cargado en Indico."""
    from indico_payment_niubiz.plugin import NiubizPaymentPlugin
    return NiubizPaymentPlugin.instance


@pytest.fixture
def registration(db, create_event, dummy_user):
    """Crear un evento y una inscripción de prueba."""
    event = create_event()
    regform = event.add_registration_form(title="Test form", currency="PEN")
    registration = regform.create_registration(dummy_user, {"first_name": "Dummy", "last_name": "User"})
    db.session.add(registration)
    db.session.flush()
    return registration


@pytest.fixture
def callback_url(registration):
    return f"/event/{registration.event_id}/registrations/{registration.registration_form.id}/payment/response/niubiz/notify"


# ----------------------------------------------------------------------
# Tests de seguridad
# ----------------------------------------------------------------------
def test_callback_rejects_invalid_token(client, plugin, registration, callback_url):
    plugin.settings.set("callback_authorization_token", "SECRET123")

    resp = client.post(callback_url, json=_make_payload(), headers={"Authorization": "WRONG"})
    assert resp.status_code == 403


def test_callback_rejects_invalid_signature(client, plugin, registration, callback_url):
    plugin.settings.set("callback_hmac_secret", "hmac_secret")

    payload = _make_payload()
    resp = client.post(
        callback_url,
        json=payload,
        headers={"NBZ-Signature": "bad_signature"},
    )
    assert resp.status_code == 403


def test_callback_rejects_ip_not_in_whitelist(client, plugin, registration, callback_url, monkeypatch):
    plugin.settings.set("callback_ip_whitelist", "192.168.0.0/24")

    monkeypatch.setattr("flask.Request.remote_addr", "10.0.0.1")
    resp = client.post(callback_url, json=_make_payload())
    assert resp.status_code == 403


# ----------------------------------------------------------------------
# Tests de estados Niubiz
# ----------------------------------------------------------------------
@pytest.mark.parametrize("status_key,expected_action,toggle_paid", [
    ("AUTHORIZED", TransactionAction.complete, True),
    ("REJECTED", TransactionAction.reject, False),
    ("VOIDED", TransactionAction.cancel, False),
    ("PENDING", TransactionAction.pending, False),
    ("REFUNDED", TransactionAction.cancel, False),
    ("EXPIRED", TransactionAction.reject, False),
    ("REVIEW", TransactionAction.pending, False),
])
def test_callback_process_status(
    client, db, registration, callback_url, status_key, expected_action, toggle_paid
):
    payload = _make_payload(status=status_key, purchase_number=f"{registration.event_id}-{registration.id}")
    resp = client.post(callback_url, json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["received"] is True

    # Verificar transacción
    txn = registration.transaction
    assert txn is not None
    assert txn.action == expected_action
    assert txn.amount == pytest.approx(100.0)

    # Verificar estado de inscripción según mapping
    if status_key == "AUTHORIZED":
        assert registration.is_paid
    elif status_key == "REFUNDED":
        assert not registration.is_paid
    else:
        # No debe marcar como pagado
        assert not registration.is_paid


# ----------------------------------------------------------------------
# Tests de estado desconocido
# ----------------------------------------------------------------------
def test_callback_unknown_status(client, registration, callback_url):
    payload = _make_payload(status="WTFSTATE", purchase_number=f"{registration.event_id}-{registration.id}")
    resp = client.post(callback_url, json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["received"] is True

    txn = registration.transaction
    assert txn.action == TransactionAction.reject
    assert not registration.is_paid
