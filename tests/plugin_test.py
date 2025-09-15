from unittest.mock import patch

from indico_payment_niubiz.util import (authorize_transaction, create_session_token,
                                        get_security_token)


def test_get_security_token_sandbox():
    with patch('indico_payment_niubiz.util.requests.post') as post:
        post.return_value.text = '  abc  '
        post.return_value.raise_for_status.return_value = None
        token = get_security_token('access', 'secret', 'sandbox')
        assert token == 'abc'

        args, kwargs = post.call_args
        assert args[0] == 'https://apisandbox.vnforappstest.com/api.security/v1/security'
        assert 'Authorization' in kwargs['headers']
        assert kwargs['headers']['Authorization'].startswith('Basic ')


def test_create_session_token_sandbox():
    with patch('indico_payment_niubiz.util.requests.post') as post:
        post.return_value.json.return_value = {'sessionKey': 'xyz'}
        post.return_value.raise_for_status.return_value = None
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
        assert token == 'xyz'


def test_authorize_transaction_sandbox():
    with patch('indico_payment_niubiz.util.requests.post') as post:
        response_payload = {'data': {'ACTION_CODE': '000', 'TRANSACTION_ID': 'abc'}}
        post.return_value.json.return_value = response_payload
        post.return_value.raise_for_status.return_value = None

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
        assert result == response_payload


def test_authorize_transaction_with_custom_ip():
    with patch('indico_payment_niubiz.util.requests.post') as post:
        post.return_value.json.return_value = {'data': {}}
        post.return_value.raise_for_status.return_value = None

        authorize_transaction('MERCHANT', 'tx-token', 'PN-1', 50, 'PEN', 'token', 'sandbox',
                              client_ip='10.0.0.1')

        kwargs = post.call_args[1]
        assert kwargs['json']['dataMap']['clientIp'] == '10.0.0.1'
