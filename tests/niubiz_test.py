from unittest.mock import Mock, patch

import requests

from indico_payment_niubiz.controllers import _apply_registration_status
from indico_payment_niubiz.util import authorize_transaction, get_security_token


def _build_response(*, text='', json_payload=None, status_code=200):
    response = Mock()
    response.status_code = status_code
    response.text = text
    response.json = Mock(return_value=json_payload if json_payload is not None else {})
    response.raise_for_status = Mock()
    return response


def test_get_security_token_returns_token():
    response = _build_response(text='  abc  ')
    with patch('indico_payment_niubiz.util._', lambda text: text), \
            patch('indico_payment_niubiz.util.requests.post', return_value=response) as mock_post:
        result = get_security_token('access', 'secret', 'sandbox')

    assert result['success'] is True
    assert result['token'] == 'abc'
    mock_post.assert_called_once()
    called_url = mock_post.call_args.args[0]
    assert called_url.endswith('/api.security/v1/security')


def test_authorization_success_marks_registration_paid():
    response = _build_response(json_payload={'data': {'ACTION_CODE': '000', 'TRANSACTION_ID': 'abc123'}})
    with patch('indico_payment_niubiz.util._', lambda text: text), \
            patch('indico_payment_niubiz.util.requests.post', return_value=response):
        assert callable(authorize_transaction.__globals__['_'])
        result = authorize_transaction('MERCHANT', 'tx-token', 'PN-1', 50, 'PEN', 'token', 'sandbox')

    assert result['success'] is True
    assert result['data']['data']['ACTION_CODE'] == '000'

    registration = Mock()
    with patch('indico_payment_niubiz.controllers.db.session.flush'):
        _apply_registration_status(registration=registration, paid=True)

    registration.update_state.assert_called_once_with(paid=True)


def test_authorization_error_returns_failure():
    response = _build_response(json_payload={'error': 'invalid'}, status_code=401)
    http_error = requests.HTTPError('401 error')
    http_error.response = response
    response.raise_for_status.side_effect = http_error

    with patch('indico_payment_niubiz.util._', lambda text: text), \
            patch('indico_payment_niubiz.util.requests.post', return_value=response):
        assert callable(authorize_transaction.__globals__['_'])
        result = authorize_transaction('MERCHANT', 'tx-token', 'PN-1', 50, 'PEN', 'token', 'sandbox')

    assert result['success'] is False
    assert result.get('token_expired') is True
    assert 'error' in result
