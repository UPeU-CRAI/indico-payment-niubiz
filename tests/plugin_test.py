from unittest.mock import patch

from indico_payment_niubiz.util import get_security_token, create_session_token


def test_get_security_token():
    with patch('indico_payment_niubiz.util.requests.post') as post:
        post.return_value.json.return_value = {'accessToken': 'abc'}
        token = get_security_token('url', 'u', 'p')
        assert token == 'abc'
        post.assert_called_once_with('url', auth=('u', 'p'))


def test_create_session_token():
    with patch('indico_payment_niubiz.util.requests.post') as post:
        post.return_value.json.return_value = {'sessionKey': 'xyz'}
        token = create_session_token('url', 'sec', {'amount': 1})
        post.assert_called_once_with('url', json={'amount': 1}, headers={'Authorization': 'sec', 'Content-Type': 'application/json'})
        assert token == 'xyz'
