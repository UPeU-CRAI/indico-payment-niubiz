from types import SimpleNamespace
from unittest.mock import patch

from indico.modules.events.payment.models.transactions import TransactionAction, TransactionStatus
from indico.modules.events.payment.util import register_transaction
from indico_payment_niubiz.util import (authorize_transaction, create_session_token,
                                        get_security_token)


def test_get_security_token_sandbox():
    with patch('indico_payment_niubiz.util.requests.post') as post:
        post.return_value.text = '  abc  '
        post.return_value.raise_for_status.return_value = None
        post.return_value.status_code = 200
        post.return_value.json.return_value = {}
        token = get_security_token('access', 'secret', 'sandbox')
        assert token == 'abc'

        args, kwargs = post.call_args
        assert args[0] == 'https://apisandbox.vnforappstest.com/api.security/v1/security'
        assert 'Authorization' in kwargs['headers']
        assert kwargs['headers']['Authorization'].startswith('Basic ')
        assert kwargs['timeout'] > 0


def test_create_session_token_sandbox():
    with patch('indico_payment_niubiz.util.requests.post') as post:
        post.return_value.json.return_value = {'sessionKey': 'xyz'}
        post.return_value.raise_for_status.return_value = None
        post.return_value.status_code = 200
        token = create_session_token('MERCHANT', 10, 'PEN', 'token', 'sandbox')

        args, kwargs = post.call_args
        assert args[0] == ('https://apisandbox.vnforappstest.com/api.ecommerce/v2/ecommerce/'
                           'token/session/MERCHANT')
        assert kwargs['headers'] == {'Content-Type': 'application/json', 'Authorization': 'token'}
        assert kwargs['json']['amount'] == 10.0
        assert kwargs['json']['currency'] == 'PEN'
        assert kwargs['json']['channel'] == 'web'
        assert kwargs['json']['antifraud']['clientIp'] == '127.0.0.1'
        assert kwargs['json']['dataMap']['clientId'] == 'indico-user'
        assert kwargs['timeout'] > 0
        assert token == 'xyz'


def test_authorize_transaction_sandbox():
    with patch('indico_payment_niubiz.util.requests.post') as post:
        response_payload = {'data': {'ACTION_CODE': '000', 'TRANSACTION_ID': 'abc'}}
        post.return_value.json.return_value = response_payload
        post.return_value.raise_for_status.return_value = None
        post.return_value.status_code = 200

        result = authorize_transaction('MERCHANT', 'tx-token', 'PN-1', 50, 'PEN', 'token', 'sandbox')

        args, kwargs = post.call_args
        assert args[0] == ('https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/'
                           'ecommerce/MERCHANT')
        assert kwargs['headers'] == {'Content-Type': 'application/json', 'Authorization': 'token'}
        assert kwargs['json']['order']['tokenId'] == 'tx-token'
        assert kwargs['json']['order']['purchaseNumber'] == 'PN-1'
        assert kwargs['json']['order']['amount'] == 50.0
        assert kwargs['json']['order']['currency'] == 'PEN'
        assert kwargs['json']['dataMap']['clientIp'] == '127.0.0.1'
        assert kwargs['timeout'] > 0
        assert result == response_payload


def test_authorize_transaction_with_custom_ip():
    with patch('indico_payment_niubiz.util.requests.post') as post:
        post.return_value.json.return_value = {'data': {}}
        post.return_value.raise_for_status.return_value = None
        post.return_value.status_code = 200

        authorize_transaction('MERCHANT', 'tx-token', 'PN-1', 50, 'PEN', 'token', 'sandbox',
                              client_ip='10.0.0.1')

        kwargs = post.call_args[1]
        assert kwargs['json']['dataMap']['clientIp'] == '10.0.0.1'


def test_successful_flow_marks_registration_paid(monkeypatch):
    class DummyResponse:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload
            self.text = ''

        def json(self):
            return self._payload

    def fake_post(url, **kwargs):
        if 'token/session' in url:
            return DummyResponse({'sessionKey': 'session-123'})
        if 'authorization' in url:
            return DummyResponse({'data': {'ACTION_CODE': '000', 'TRANSACTION_ID': 'txn-123'}})
        raise AssertionError(f'Unexpected URL {url}')

    monkeypatch.setattr('indico_payment_niubiz.util.requests.post', fake_post)

    session_token = create_session_token('MERCHANT', 20, 'PEN', 'token', 'sandbox')
    assert session_token == 'session-123'

    authorization = authorize_transaction('MERCHANT', 'tx-token', 'PN-1', 20, 'PEN', 'token', 'sandbox')
    assert authorization['data']['ACTION_CODE'] == '000'

    registration = SimpleNamespace(paid=False)

    def update_state(*, paid):
        registration.paid = paid

    registration.update_state = update_state

    monkeypatch.setattr('indico.modules.events.payment.util.PaymentTransaction.create_next',
                        lambda **kwargs: SimpleNamespace(status=TransactionStatus.successful))
    monkeypatch.setattr('indico.modules.events.payment.util.db.session.flush', lambda: None)
    monkeypatch.setattr('indico.modules.events.payment.util.notify_registration_state_update',
                        lambda *args, **kwargs: None)

    register_transaction(registration=registration,
                         amount=20,
                         currency='PEN',
                         action=TransactionAction.complete,
                         provider='niubiz',
                         data=authorization)

    assert registration.paid is True
