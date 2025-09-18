import pytest
from decimal import Decimal
from unittest.mock import MagicMock

from indico.modules.events.payment.models.transactions import TransactionAction

from indico_payment_niubiz import indico_integration as integration
from indico_payment_niubiz.status_mapping import NIUBIZ_STATUS_MAP, DEFAULT_STATUS


@pytest.mark.parametrize("status_key,expected_action,expected_toggle", [
    ("AUTHORIZED", TransactionAction.complete, True),
    ("REJECTED", TransactionAction.reject, False),
    ("NOT AUTHORIZED", TransactionAction.reject, False),
    ("VOIDED", TransactionAction.cancel, False),
    ("CANCELLED", TransactionAction.cancel, False),
    ("PENDING", TransactionAction.pending, False),
    ("REFUNDED", TransactionAction.cancel, False),
    ("EXPIRED", TransactionAction.reject, False),
    ("REVIEW", TransactionAction.pending, False),
    ("UNKNOWN_STATUS", DEFAULT_STATUS["action"], DEFAULT_STATUS["toggle_paid"]),
])
def test_status_mapping_contains_expected(status_key, expected_action, expected_toggle):
    """Verifica que cada estado Niubiz esté mapeado al TransactionAction correcto."""
    config = NIUBIZ_STATUS_MAP.get(status_key, DEFAULT_STATUS)
    assert config["action"] == expected_action
    assert config["toggle_paid"] == expected_toggle
    assert "summary" in config


def test_handle_successful_payment_sets_paid(monkeypatch):
    reg = MagicMock()
    reg.id = 1
    reg.price = Decimal("50.00")
    reg.currency = "PEN"
    reg.event = MagicMock()

    called = {}

    def fake_register_transaction(**kwargs):
        called.update(kwargs)
        return MagicMock(status="successful")

    monkeypatch.setattr(integration, "register_transaction", fake_register_transaction)

    tx = integration.handle_successful_payment(
        reg,
        amount=Decimal("50.00"),
        currency="PEN",
        transaction_id="TX1",
        status="AUTHORIZED",
        summary="Pago confirmado",
        data={"foo": "bar"},
        toggle_paid=True,
    )

    assert called["action"] == TransactionAction.complete
    assert tx is not None


def test_handle_failed_payment_sets_unpaid(monkeypatch):
    reg = MagicMock()
    reg.id = 2
    reg.price = Decimal("75.00")
    reg.currency = "PEN"
    reg.event = MagicMock()

    called = {}

    def fake_register_transaction(**kwargs):
        called.update(kwargs)
        return MagicMock(status="rejected")

    monkeypatch.setattr(integration, "register_transaction", fake_register_transaction)

    tx = integration.handle_failed_payment(
        reg,
        amount=Decimal("75.00"),
        currency="PEN",
        transaction_id="TX2",
        status="REJECTED",
        summary="Pago rechazado",
        data={"foo": "bar"},
        cancelled=False,
    )

    assert called["action"] == TransactionAction.reject
    assert tx is not None


def test_handle_refund_marks_unpaid(monkeypatch):
    reg = MagicMock()
    reg.id = 3
    reg.price = Decimal("80.00")
    reg.currency = "PEN"
    reg.event = MagicMock()

    called = {}

    def fake_register_transaction(**kwargs):
        called.update(kwargs)
        return MagicMock(status="cancelled")

    monkeypatch.setattr(integration, "register_transaction", fake_register_transaction)

    tx = integration.handle_refund(
        reg,
        amount=Decimal("80.00"),
        currency="PEN",
        transaction_id="TX3",
        status="REFUNDED",
        summary="Reembolso confirmado",
        data={"foo": "bar"},
        success=True,
    )

    assert called["action"] == TransactionAction.cancel
    assert tx is not None


def test_handle_pending_payment(monkeypatch):
    reg = MagicMock()
    reg.id = 4
    reg.price = Decimal("120.00")
    reg.currency = "PEN"
    reg.event = MagicMock()

    called = {}

    def fake_register_transaction(**kwargs):
        called.update(kwargs)
        return MagicMock(status="pending")

    monkeypatch.setattr(integration, "register_transaction", fake_register_transaction)

    tx = integration.handle_pending_payment(
        reg,
        amount=Decimal("120.00"),
        currency="PEN",
        transaction_id="TX4",
        status="PENDING",
        summary="Pago pendiente",
        data={"foo": "bar"},
    )

    assert called["action"] == TransactionAction.pending
    assert tx is not None
