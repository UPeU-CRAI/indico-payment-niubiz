import base64
import logging
from typing import Any, Dict, Optional

import requests

from indico_payment_niubiz import _

SECURITY_ENDPOINTS = {
    'sandbox': 'https://apisandbox.vnforappstest.com/api.security/v1/security',
    'prod': 'https://apiprod.vnforapps.com/api.security/v1/security',
}

SESSION_ENDPOINTS = {
    'sandbox': 'https://apisandbox.vnforappstest.com/api.ecommerce/v2/ecommerce/token/session/{merchant_id}',
    'prod': 'https://apiprod.vnforapps.com/api.ecommerce/v2/ecommerce/token/session/{merchant_id}',
}

AUTHORIZATION_ENDPOINTS = {
    'sandbox': 'https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/ecommerce/{merchant_id}',
    'prod': 'https://apiprod.vnforapps.com/api.authorization/v3/authorization/ecommerce/{merchant_id}',
}


logger = logging.getLogger(__name__)


class NiubizAPIError(Exception):
    """Raised when a Niubiz API call fails."""

    def __init__(self, message: str, *, payload: Optional[Dict[str, Any]] = None,
                 status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.message = message
        self.payload = payload or {}
        self.status_code = status_code

    def __str__(self) -> str:  # pragma: no cover - mostly for debugging/flash messages
        return self.message


class NiubizTokenExpired(NiubizAPIError):
    """Raised when the Niubiz security token has expired."""

    pass


def _normalize_endpoint(endpoint: Optional[str]) -> str:
    endpoint = (endpoint or 'sandbox').lower()
    return 'sandbox' if endpoint == 'sandbox' else 'prod'


def _extract_error_message(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}

    if isinstance(payload, dict):
        for key in ('message', 'errorMessage', 'title', 'error'):  # pragma: no branch - simple loop
            value = payload.get(key)
            if value:
                return str(value)
        data = payload.get('data')
        if isinstance(data, dict):
            for key in ('ACTION_DESCRIPTION', 'ACTION_MESSAGE', 'ACTION_CODE', 'status'):  # pragma: no branch
                value = data.get(key)
                if value:
                    return str(value)

    text = (response.text or '').strip()
    return text


def _handle_response_errors(response: requests.Response, default_message: str,
                            allow_token_refresh: bool = False) -> None:
    message = _extract_error_message(response)
    status_code = response.status_code
    if allow_token_refresh and status_code == 401:
        logger.exception('Niubiz security token expired (HTTP %s).', status_code)
        raise NiubizTokenExpired(
            _('The Niubiz security token expired. A new token is being requested.'),
            status_code=status_code,
            payload=_safe_json(response),
        )

    if message:
        formatted = f'{default_message} [HTTP {status_code}] - {message}'
    else:
        formatted = f'{default_message} [HTTP {status_code}]'
    logger.exception('Niubiz API responded with an error: %s', formatted)
    raise NiubizAPIError(formatted, status_code=status_code, payload=_safe_json(response))


def _safe_json(response: requests.Response) -> Dict[str, Any]:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _perform_request(url: str, *, headers: Dict[str, str], json: Optional[Dict[str, Any]] = None,
                     timeout: int = 15, error_message: str,
                     allow_token_refresh: bool = False) -> requests.Response:
    try:
        response = requests.post(url, json=json, headers=headers, timeout=timeout)
    except requests.Timeout as exc:
        logger.exception('Timeout while calling Niubiz API at %s', url)
        raise NiubizAPIError(_('The Niubiz service did not respond in time. Please try again.'),
                              payload={'timeout': True}) from exc
    except requests.RequestException as exc:
        logger.exception('Error while calling Niubiz API at %s', url)
        raise NiubizAPIError(_('Could not communicate with Niubiz. Please try again later.')) from exc

    if response.status_code >= 400:
        _handle_response_errors(response, error_message, allow_token_refresh)

    return response


def get_security_token(access_key: str, secret_key: str, endpoint: str = 'sandbox') -> str:
    """Generate a security token from the Niubiz security API."""

    endpoint_key = _normalize_endpoint(endpoint)
    url = SECURITY_ENDPOINTS[endpoint_key]

    credentials = f'{access_key}:{secret_key}'.encode('utf-8')
    headers = {'Authorization': 'Basic ' + base64.b64encode(credentials).decode('utf-8')}

    response = _perform_request(url,
                                headers=headers,
                                error_message=_('Failed to obtain the Niubiz security token.'))

    token = response.text.strip()
    if token:
        return token

    payload = _safe_json(response)
    return payload.get('accessToken', '')


def create_session_token(
    merchant_id: str,
    amount: Any,
    currency: str,
    access_token: str,
    endpoint: str = 'sandbox',
    *,
    client_ip: Optional[str] = None,
    client_id: Optional[str] = None,
) -> str:
    """Generate a session token for the Niubiz web checkout."""

    endpoint_key = _normalize_endpoint(endpoint)
    url = SESSION_ENDPOINTS[endpoint_key].format(merchant_id=merchant_id)

    headers = {'Content-Type': 'application/json', 'Authorization': access_token}
    antifraud_ip = client_ip or '127.0.0.1'
    customer_id = client_id or 'indico-user'
    body = {
        'channel': 'web',
        'amount': float(amount),
        'currency': currency,
        'antifraud': {'clientIp': antifraud_ip},
        'dataMap': {'clientId': customer_id},
    }
    response = _perform_request(
        url,
        headers=headers,
        json=body,
        error_message=_('Failed to create the Niubiz checkout session.'),
        allow_token_refresh=True,
    )

    payload = _safe_json(response)
    try:
        return payload['sessionKey']
    except KeyError as exc:  # pragma: no cover - defensive programming
        logger.exception('Niubiz session token response did not include a sessionKey.')
        raise NiubizAPIError(_('The Niubiz session response was invalid.')) from exc


def authorize_transaction(
    merchant_id: str,
    transaction_token: str,
    purchase_number: str,
    amount: Any,
    currency: str,
    access_token: str,
    endpoint: str = 'sandbox',
    *,
    client_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Authorize a Niubiz transaction using the checkout transaction token."""

    endpoint_key = _normalize_endpoint(endpoint)
    url = AUTHORIZATION_ENDPOINTS[endpoint_key].format(merchant_id=merchant_id)

    headers = {'Content-Type': 'application/json', 'Authorization': access_token}
    antifraud_ip = client_ip or '127.0.0.1'
    body = {
        'channel': 'web',
        'captureType': 'manual',
        'countable': True,
        'order': {
            'tokenId': transaction_token,
            'purchaseNumber': purchase_number,
            'amount': float(amount),
            'currency': currency,
        },
        'dataMap': {'clientIp': antifraud_ip},
    }
    response = _perform_request(
        url,
        headers=headers,
        json=body,
        error_message=_('Failed to authorise the Niubiz transaction.'),
        allow_token_refresh=True,
    )

    return _safe_json(response)
