import hashlib
import hmac

from indico_payment_niubiz.security import validate_nbz_signature


def test_validate_nbz_signature_success():
    secret = "s3cr3t"
    body = b'{"foo": "bar"}'
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    assert validate_nbz_signature(secret, body, signature)


def test_validate_nbz_signature_failure():
    secret = "s3cr3t"
    body = b"{}"
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    assert not validate_nbz_signature(secret, body, signature[:-1] + "0")
    assert not validate_nbz_signature("", body, signature)
    assert not validate_nbz_signature(secret, body, "")
