import base64
import logging
from typing import Any, Callable, Dict, Optional

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

CHECKOUT_JS_URLS = {
    'sandbox': 'https://static-content-qas.vnforapps.com/env/sandbox/js/checkout.js',
    'prod': 'https://static-content.vnforapps.com/v2/js/checkout.js',
}

DEFAULT_TIMEOUT = 30


logger = logging.getLogger(__name__)


def _normalize_endpoint(endpoint: Optional[str]) -> str:
    endpoint = (endpoint or 'sandbox').lower()
    return 'sandbox' if endpoint == 'sandbox' else 'prod'


def _extract_error_message(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}

    if isinstance(payload, dict):
        for key in ('message', 'errorMessage', 'title', 'error'):
            value = payload.get(key)
            if value:
                return str(value)
        data = payload.get('data')
        if isinstance(data, dict):
            for key in ('ACTION_DESCRIPTION', 'ACTION_MESSAGE', 'ACTION_CODE', 'status'):
                value = data.get(key)
                if value:
                    return str(value)

    text = (response.text or '').strip()
    return text


def _safe_json(response: requests.Response) -> Dict[str, Any]:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _perform_request(
    method: str,
    url: str,
    *,
    headers: Dict[str, str],
    json: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    error_message: str,
    allow_token_refresh: bool = False,
) -> Dict[str, Any]:
    try:
        response = requests.request(method.upper(), url, json=json, headers=headers, timeout=timeout)
        response.raise_for_status()
    except requests.Timeout:
        logger.exception('Timeout while calling Niubiz API at %s', url)
        return {
            'success': False,
            'error': _('The Niubiz service did not respond in time. Please try again.'),
            'timeout': True,
        }
    except requests.HTTPError as exc:
        response = exc.response
        payload = _safe_json(response) if response is not None else {}
        status_code = response.status_code if response is not None else None
        if allow_token_refresh and status_code == 401:
            logger.warning('Niubiz security token expired (HTTP %s).', status_code)
            return {
                'success': False,
                'error': _('The Niubiz security token expired. A new token is being requested.'),
                'status_code': status_code,
                'payload': payload,
                'token_expired': True,
            }

        message = _extract_error_message(response) if response is not None else ''
        if message:
            formatted = f'{error_message} [HTTP {status_code}] - {message}'
        else:
            formatted = f'{error_message} [HTTP {status_code}]'
        logger.error('Niubiz API responded with an error: %s', formatted)
        return {
            'success': False,
            'error': formatted,
            'status_code': status_code,
            'payload': payload,
        }
    except requests.RequestException:
        logger.exception('Error while calling Niubiz API at %s', url)
        return {
            'success': False,
            'error': _('Could not communicate with Niubiz. Please try again later.'),
        }

    logger.info('Niubiz API call to %s succeeded with status %s', url, response.status_code)
    return {'success': True, 'response': response}


def get_checkout_script_url(endpoint: str = 'sandbox') -> str:
    endpoint_key = _normalize_endpoint(endpoint)
    return CHECKOUT_JS_URLS[endpoint_key]


def get_security_token(access_key: str, secret_key: str, endpoint: str = 'sandbox') -> Dict[str, Any]:
    """Generate a security token from the Niubiz security API."""

    endpoint_key = _normalize_endpoint(endpoint)
    url = SECURITY_ENDPOINTS[endpoint_key]

    credentials = f'{access_key}:{secret_key}'.encode('utf-8')
    headers = {'Authorization': 'Basic ' + base64.b64encode(credentials).decode('utf-8')}

    result = _perform_request('GET', url, headers=headers,
                              error_message=_('Failed to obtain the Niubiz security token.'))

    if not result['success']:
        return result

    response = result['response']

    token = response.text.strip()
    if token:
        logger.info('Niubiz security token obtained successfully for endpoint %s', endpoint_key)
        return {'success': True, 'token': token}

    payload = _safe_json(response)
    token = payload.get('accessToken', '')
    if token:
        logger.info('Niubiz security token obtained successfully for endpoint %s', endpoint_key)
        return {'success': True, 'token': token, 'payload': payload}

    logger.error('Niubiz security token response was empty for endpoint %s', endpoint_key)
    return {
        'success': False,
        'error': _('Failed to obtain the Niubiz security token. The response was empty.'),
        'payload': payload,
    }


def create_session_token(
    merchant_id: str,
    amount: Any,
    currency: str,
    access_token: str,
    endpoint: str = 'sandbox',
    *,
    client_ip: Optional[str] = None,
    client_id: Optional[str] = None,
    purchase_number: Optional[str] = None,
    merchant_defined_data: Optional[Dict[str, Any]] = None,
    customer_email: Optional[str] = None,
    token_refresher: Optional[Callable[[], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Generate a session token for the Niubiz web checkout."""

    endpoint_key = _normalize_endpoint(endpoint)
    url = SESSION_ENDPOINTS[endpoint_key].format(merchant_id=merchant_id)

    headers = {'Content-Type': 'application/json', 'Authorization': access_token}
    antifraud_ip = client_ip or '127.0.0.1'
    customer_id = client_id or 'indico-user'
    antifraud: Dict[str, Any] = {'clientIp': antifraud_ip}
    if merchant_defined_data:
        antifraud['merchantDefineData'] = merchant_defined_data

    data_map: Dict[str, Any] = {'clientId': customer_id}
    if customer_email:
        data_map['customerEmail'] = customer_email

    body: Dict[str, Any] = {
        'channel': 'web',
        'amount': float(amount),
        'currency': currency,
        'antifraud': antifraud,
        'dataMap': data_map,
    }
    if purchase_number:
        body['order'] = {'purchaseNumber': purchase_number}

    token = access_token
    for attempt in range(2):
        headers['Authorization'] = token
        result = _perform_request(
            'POST',
            url,
            headers=headers,
            json=body,
            error_message=_('Failed to create the Niubiz checkout session.'),
            allow_token_refresh=True,
        )

        if result['success']:
            payload = _safe_json(result['response'])
            session_key = payload.get('sessionKey')
            if session_key:
                logger.info('Niubiz checkout session created successfully for merchant %s', merchant_id)
                return {
                    'success': True,
                    'session_key': session_key,
                    'payload': payload,
                    'access_token': token,
                    'expiration_time': payload.get('expirationTime'),
                }
            logger.error('Niubiz session token response did not include a sessionKey.')
            return {
                'success': False,
                'error': _('The Niubiz session response was invalid.'),
                'payload': payload,
            }

        if result.get('token_expired') and token_refresher:
            logger.info('Niubiz security token expired while creating a session. Requesting a new token.')
            refreshed = token_refresher()
            if not refreshed or not refreshed.get('success'):
                return refreshed or {
                    'success': False,
                    'error': _('Failed to obtain a new Niubiz security token.'),
                }
            token = refreshed['token']
            continue

        return result

    return {'success': False, 'error': _('Failed to create the Niubiz checkout session.')}


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
    client_id: Optional[str] = None,
    token_refresher: Optional[Callable[[], Dict[str, Any]]] = None,
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
    if client_id:
        body['dataMap']['clientId'] = client_id

    token = access_token
    for attempt in range(2):
        headers['Authorization'] = token
        result = _perform_request(
            'POST',
            url,
            headers=headers,
            json=body,
            error_message=_('Failed to authorise the Niubiz transaction.'),
            allow_token_refresh=True,
        )

        if result['success']:
            payload = _safe_json(result['response'])
            logger.info('Niubiz transaction authorised successfully for purchase %s', purchase_number)
            return {'success': True, 'data': payload, 'access_token': token}

        if result.get('token_expired') and token_refresher:
            logger.info('Niubiz security token expired while authorising a transaction. Requesting a new token.')
            refreshed = token_refresher()
            if not refreshed or not refreshed.get('success'):
                return refreshed or {
                    'success': False,
                    'error': _('Failed to obtain a new Niubiz security token.'),
                }
            token = refreshed['token']
            continue

        return result

    return {'success': False, 'error': _('Failed to authorise the Niubiz transaction.')}
