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

    with patch('indico_payment_niubiz.util.requests.post', return_value=response) as mock_post:
        result = get_security_token('access', 'secret', 'sandbox')

    assert result['success'] is True
    assert result['token'] == 'abc'
    mock_post.assert_called_once()


def test_authorization_success_marks_registration_paid():
    response = _build_response(json_payload={'data': {'ACTION_CODE': '000', 'TRANSACTION_ID': 'abc123'}})

    with patch('indico_payment_niubiz.util.requests.post', return_value=response):
        result = authorize_transaction('MERCHANT', 'tx-token', 'PN-1', 50, 'PEN', 'token', 'sandbox')

    assert result['success'] is True
    assert result['data']['data']['ACTION_CODE'] == '000'

    registration = Mock()
    with patch('indico_payment_niubiz.controllers.db.session.flush'):
        _apply_registration_status(registration=registration, paid=True)

    registration.update_state.assert_called_once_with(paid=True)


def test_authorization_rejection_marks_registration_unpaid():
    response = _build_response(json_payload={'data': {'ACTION_CODE': '400', 'TRANSACTION_ID': 'def456'}})

    with patch('indico_payment_niubiz.util.requests.post', return_value=response):
        result = authorize_transaction('MERCHANT', 'tx-token', 'PN-2', 50, 'PEN', 'token', 'sandbox')

    assert result['success'] is True
    assert result['data']['data']['ACTION_CODE'] == '400'

    registration = Mock()
    with patch('indico_payment_niubiz.controllers.db.session.flush'):
        _apply_registration_status(registration=registration, paid=False)

    registration.update_state.assert_called_once_with(paid=False)


def test_cancellation_marks_registration_withdrawn():
    registration = Mock()

    with patch('indico_payment_niubiz.controllers.db.session.flush'):
        _apply_registration_status(registration=registration, cancelled=True)

    registration.update_state.assert_called_once_with(withdrawn=True, paid=False)


def test_authorization_refreshes_token_on_expiration():
    expired_response = _build_response(status_code=401, json_payload={'error': 'token expired'})
    http_error = requests.HTTPError('401 error')
    http_error.response = expired_response
    expired_response.raise_for_status.side_effect = http_error

    success_payload = {'data': {'ACTION_CODE': '000', 'TRANSACTION_ID': 'ghi789'}}
    success_response = _build_response(json_payload=success_payload)

    captured_headers = []

    def post_side_effect(url, json=None, headers=None, timeout=None):
        captured_headers.append(headers['Authorization'])
        return expired_response if len(captured_headers) == 1 else success_response

    token_refresher = Mock(return_value={'success': True, 'token': 'new-token'})

    with patch('indico_payment_niubiz.util.requests.post', side_effect=post_side_effect) as mock_post:
        result = authorize_transaction(
            'MERCHANT',
            'tx-token',
            'PN-3',
            75,
            'PEN',
            'initial-token',
            'sandbox',
            token_refresher=token_refresher,
        )

    assert result['success'] is True
    assert result['data']['data']['ACTION_CODE'] == '000'
    assert captured_headers == ['initial-token', 'new-token']
    assert mock_post.call_count == 2
    token_refresher.assert_called_once_with()
