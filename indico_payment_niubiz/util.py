import base64
from typing import Any, Dict, Optional

import requests

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


def _normalize_endpoint(endpoint: Optional[str]) -> str:
    endpoint = (endpoint or 'sandbox').lower()
    return 'sandbox' if endpoint == 'sandbox' else 'prod'


def get_security_token(access_key: str, secret_key: str, endpoint: str = 'sandbox') -> str:
    """Generate a security token from the Niubiz security API."""

    endpoint_key = _normalize_endpoint(endpoint)
    url = SECURITY_ENDPOINTS[endpoint_key]

    credentials = f'{access_key}:{secret_key}'.encode('utf-8')
    headers = {'Authorization': 'Basic ' + base64.b64encode(credentials).decode('utf-8')}
    response = requests.post(url, headers=headers)
    response.raise_for_status()

    token = response.text.strip()
    if token:
        return token

    try:
        payload = response.json()
    except ValueError:
        payload = {}
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
    response = requests.post(url, json=body, headers=headers)
    response.raise_for_status()
    return response.json()['sessionKey']


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
    response = requests.post(url, json=body, headers=headers)
    response.raise_for_status()
    return response.json()
