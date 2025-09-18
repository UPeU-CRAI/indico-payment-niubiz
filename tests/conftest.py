import hashlib
import hmac
import json
import os
import sys
from decimal import Decimal
from unittest.mock import MagicMock

import pytest


# Ensure the package under development is importable even when pytest changes
# the working directory (as it happens in the execution environment of these
# kata-style exercises).
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


pytest.importorskip("indico", reason="Indico no está disponible en el entorno de pruebas.")
pytest.importorskip("indico.modules.events.payment", reason="Indico no está disponible en el entorno de pruebas.")
pytest.importorskip("indico.modules.events.logs", reason="Indico no está disponible en el entorno de pruebas.")

from indico_payment_niubiz.plugin import NiubizPaymentPlugin


@pytest.fixture
def plugin(monkeypatch):
    """Mock del plugin Niubiz con configuraciones mínimas."""
    plugin = MagicMock(spec=NiubizPaymentPlugin)
    plugin._get_setting = MagicMock(return_value=None)
    return plugin


@pytest.fixture
def event():
    """Evento simulado con ID fijo y log de eventos."""
    mock_event = MagicMock()
    mock_event.id = 123
    mock_event.log = MagicMock()
    return mock_event


@pytest.fixture
def registration(event):
    """Inscripción simulada con ID y precio."""
    reg = MagicMock()
    reg.id = 456
    reg.event_id = event.id
    reg.event = event
    reg.price = Decimal("100.00")
    reg.currency = "PEN"
    return reg


@pytest.fixture
def niubiz_payload(event, registration):
    """Genera un payload base válido de Niubiz para tests."""
    return {
        "order": {
            "purchaseNumber": f"{event.id}-{registration.id}",
            "transactionId": "TX123456",
        },
        "dataMap": {
            "STATUS": "AUTHORIZED",
            "actionCode": "000",
            "amount": "100.00",
            "currency": "PEN",
        },
    }


@pytest.fixture
def hmac_signature(niubiz_payload):
    """Genera firma HMAC simulada con un secreto fijo."""
    secret = "testsecret"
    payload_bytes = json.dumps(niubiz_payload).encode("utf-8")
    signature = hmac.new(secret.encode(), msg=payload_bytes, digestmod=hashlib.sha256).hexdigest()
    return signature


@pytest.fixture
def client(app):
    """Cliente Flask de prueba."""
    return app.test_client()
