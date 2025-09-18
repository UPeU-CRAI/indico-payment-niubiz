import hashlib
import hmac
import ipaddress
import pytest
from decimal import Decimal
from flask import Flask

from indico_payment_niubiz.blueprint import blueprint


@pytest.fixture
def app():
    """Crea una app Flask mínima con el blueprint Niubiz registrado."""
    app = Flask(__name__)
    app.register_blueprint(blueprint, url_prefix="/test")
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def make_payload(status="AUTHORIZED", purchase_number="1-123", amount="100.00"):
    """Crea un payload Niubiz de prueba."""
    return {
        "order": {"purchaseNumber": purchase_number},
        "dataMap": {
            "STATUS": status,
            "transactionId": "TX123",
            "amount": amount,
            "currency": "PEN",
            "actionCode": "000",
        },
    }


def add_headers(app, payload, token=None, hmac_secret=None, ip=None):
    """Genera headers válidos para la petición simulada."""
    headers = {"Content-Type": "application/json"}

    if token:
        headers["Authorization"] = token

    if hmac_secret:
        sig = hmac.new(
            hmac_secret.encode("utf-8"),
            msg=app.json.dumps(payload).encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()
        headers["NBZ-Signature"] = sig

    if ip:
        headers["X-Forwarded-For"] = ip

    return headers


# ----------------------------------------------------------------------
# Casos de éxito por estado
# ----------------------------------------------------------------------
@pytest.mark.parametrize("status", [
    "AUTHORIZED", "REJECTED", "VOIDED",
    "PENDING", "REFUNDED", "EXPIRED", "REVIEW"
])
def test_callback_processes_known_status(client, app, status):
    payload = make_payload(status=status)
    headers = add_headers(app, payload)
    resp = client.post("/test/event/1/registrations/1/payment/response/niubiz/notify",
                       json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["received"] is True


def test_callback_missing_purchase_number(client, app):
    payload = make_payload()
    payload["order"].pop("purchaseNumber")
    headers = add_headers(app, payload)
    resp = client.post("/test/event/1/registrations/1/payment/response/niubiz/notify",
                       json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["received"] is False
    assert data["error"] == "missing_purchase_number"


# ----------------------------------------------------------------------
# Validaciones de seguridad
# ----------------------------------------------------------------------
def test_callback_rejects_invalid_authorization(client, app):
    payload = make_payload()
    headers = add_headers(app, payload, token="WRONG")
    resp = client.post("/test/event/1/registrations/1/payment/response/niubiz/notify",
                       json=payload, headers=headers)
    assert resp.status_code == 403


def test_callback_rejects_invalid_hmac(client, app):
    payload = make_payload()
    headers = add_headers(app, payload, hmac_secret="badsecret")
    # Sobreescribir con firma inválida
    headers["NBZ-Signature"] = "invalidsig"
    resp = client.post("/test/event/1/registrations/1/payment/response/niubiz/notify",
                       json=payload, headers=headers)
    assert resp.status_code == 403


def test_callback_rejects_invalid_ip(client, app, monkeypatch):
    payload = make_payload()
    headers = add_headers(app, payload, ip="203.0.113.55")

    # Simula que whitelist está configurado y no incluye la IP
    from indico_payment_niubiz import blueprint as bp
    monkeypatch.setattr(bp, "_get_plugin", lambda: type("P", (), {
        "_get_setting": lambda self, event, key: "10.0.0.0/8" if key == "callback_ip_whitelist" else None
    })())

    resp = client.post("/test/event/1/registrations/1/payment/response/niubiz/notify",
                       json=payload, headers=headers)
    assert resp.status_code == 403
