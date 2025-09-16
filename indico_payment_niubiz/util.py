import base64
import logging
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock
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

ORDER_STATUS_ENDPOINTS = {
    'sandbox': 'https://apisandbox.vnforappstest.com/api.ecommerce/v2/ecommerce/orders/{merchant_id}/{order_id}',
    'prod': 'https://apiprod.vnforapps.com/api.ecommerce/v2/ecommerce/orders/{merchant_id}/{order_id}',
}

ORDER_EXTERNAL_STATUS_ENDPOINTS = {
    'sandbox': 'https://apisandbox.vnforappstest.com/api.ecommerce/v2/ecommerce/orders/{merchant_id}/external/{external_id}',
    'prod': 'https://apiprod.vnforapps.com/api.ecommerce/v2/ecommerce/orders/{merchant_id}/external/{external_id}',
}

TRANSACTION_STATUS_ENDPOINTS = {
    'sandbox': 'https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/transactions/{merchant_id}/{transaction_id}',
    'prod': 'https://apiprod.vnforapps.com/api.authorization/v3/authorization/transactions/{merchant_id}/{transaction_id}',
}

REFUND_ENDPOINTS = {
    'sandbox': 'https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/ecommerce/{merchant_id}/refund/{transaction_id}',
    'prod': 'https://apiprod.vnforapps.com/api.authorization/v3/authorization/ecommerce/{merchant_id}/refund/{transaction_id}',
}

DEFAULT_TIMEOUT = 30

TOKEN_TTL_SECONDS = 55 * 60
TOKEN_REFRESH_THRESHOLD_SECONDS = 5 * 60

SENSITIVE_KEYS = {
    'accesskey',
    'authorization',
    'card',
    'cardnumber',
    'card_number',
    'cvv',
    'cvv2',
    'pan',
    'secret',
    'secretkey',
    'token',
    'tokenid',
    'transactiontoken',
}


logger = logging.getLogger(__name__)


@dataclass
class _TokenEntry:
    token: str
    expires_at: datetime

    def is_valid(self) -> bool:
        now = datetime.now(timezone.utc)
        return self.expires_at > now + timedelta(seconds=TOKEN_REFRESH_THRESHOLD_SECONDS)


class _NiubizTokenCache:
    def __init__(self):
        self._tokens: Dict[tuple, _TokenEntry] = {}
        self._lock = RLock()

    @staticmethod
    def _make_key(access_key: str, secret_key: str, endpoint: str) -> tuple:
        return (endpoint, access_key, secret_key)

    def get(self, access_key: str, secret_key: str, endpoint: str) -> Optional[_TokenEntry]:
        key = self._make_key(access_key, secret_key, endpoint)
        with self._lock:
            entry = self._tokens.get(key)
            if not entry:
                return None
            if entry.is_valid():
                return entry
            self._tokens.pop(key, None)
            return None

    def store(self, access_key: str, secret_key: str, endpoint: str, token: str, expires_at: datetime) -> None:
        key = self._make_key(access_key, secret_key, endpoint)
        with self._lock:
            self._tokens[key] = _TokenEntry(token=token, expires_at=expires_at)

    def invalidate(self, access_key: str, secret_key: str, endpoint: str) -> None:
        key = self._make_key(access_key, secret_key, endpoint)
        with self._lock:
            self._tokens.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._tokens.clear()


_TOKEN_CACHE = _NiubizTokenCache()


def _normalize_endpoint(endpoint: Optional[str]) -> str:
    endpoint = (endpoint or 'sandbox').lower()
    return 'sandbox' if endpoint == 'sandbox' else 'prod'


def _mask_string(value: str) -> str:
    value = str(value)
    if len(value) <= 4:
        return '*' * len(value)
    if len(value) <= 10:
        return value[0] + '*' * (len(value) - 2) + value[-1]
    return f"{value[:6]}{'*' * (len(value) - 10)}{value[-4:]}"


def _sanitize_payload(payload: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return payload

    def _sanitize(value: Any, key: Optional[str] = None) -> Any:
        if isinstance(value, dict):
            return {k: _sanitize(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [_sanitize(item, key) for item in value]
        if key and key.lower() in SENSITIVE_KEYS:
            if isinstance(value, str):
                return _mask_string(value)
            return '***'
        return value

    return _sanitize(payload)


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
    sanitized_headers = {k: ('***' if k.lower() == 'authorization' else v) for k, v in headers.items()}
    sanitized_json = _sanitize_payload(deepcopy(json)) if isinstance(json, dict) else None
    logger.info('Calling Niubiz API %s %s headers=%s body=%s',
                method.upper(), url, sanitized_headers, sanitized_json)
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
        logger.exception('Niubiz API responded with an error: %s', formatted)
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


def invalidate_security_token(access_key: str, secret_key: str, endpoint: str = 'sandbox') -> None:
    endpoint_key = _normalize_endpoint(endpoint)
    _TOKEN_CACHE.invalidate(access_key, secret_key, endpoint_key)


def clear_security_token_cache() -> None:
    _TOKEN_CACHE.clear()


def _parse_expiration_from_payload(payload: Dict[str, Any]) -> Optional[datetime]:
    if not isinstance(payload, dict):
        return None
    expires_in = payload.get('expiresIn') or payload.get('expires_in')
    if expires_in:
        try:
            seconds = float(expires_in)
            return datetime.now(timezone.utc) + timedelta(seconds=seconds)
        except (TypeError, ValueError):
            pass
    expires_at = payload.get('expiresAt') or payload.get('expirationDate')
    if isinstance(expires_at, (int, float)):
        try:
            return datetime.fromtimestamp(float(expires_at), tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            return None
    if isinstance(expires_at, str):
        try:
            cleaned = expires_at.replace('Z', '+00:00')
            parsed = datetime.fromisoformat(cleaned)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            else:
                parsed = parsed.astimezone(timezone.utc)
            return parsed
        except ValueError:
            return None
    return None


def get_security_token(access_key: str, secret_key: str, endpoint: str = 'sandbox', *,
                       force_refresh: bool = False) -> Dict[str, Any]:
    """Generate a security token from the Niubiz security API."""

    endpoint_key = _normalize_endpoint(endpoint)
    url = SECURITY_ENDPOINTS[endpoint_key]

    credentials = f'{access_key}:{secret_key}'.encode('utf-8')
    headers = {'Authorization': 'Basic ' + base64.b64encode(credentials).decode('utf-8')}

    if not force_refresh:
        cached = _TOKEN_CACHE.get(access_key, secret_key, endpoint_key)
    else:
        cached = None
    if cached:
        logger.info('Using cached Niubiz security token for endpoint %s', endpoint_key)
        return {
            'success': True,
            'token': cached.token,
            'cached': True,
            'expires_at': cached.expires_at.isoformat(),
        }

    result = _perform_request('GET', url, headers=headers,
                              error_message=_('Failed to obtain the Niubiz security token.'))

    if not result['success']:
        return result

    response = result['response']

    token = response.text.strip()
    payload = _safe_json(response)
    if not token:
        token = payload.get('accessToken') or payload.get('access_token') or ''

    if token:
        expires_at = _parse_expiration_from_payload(payload) or (datetime.now(timezone.utc) + timedelta(seconds=TOKEN_TTL_SECONDS))
        _TOKEN_CACHE.store(access_key, secret_key, endpoint_key, token, expires_at)
        logger.info('Niubiz security token obtained successfully for endpoint %s', endpoint_key)
        result_payload: Dict[str, Any] = {'success': True, 'token': token, 'expires_at': expires_at.isoformat()}
        if payload:
            result_payload['payload'] = payload
        return result_payload

    invalidate_security_token(access_key, secret_key, endpoint_key)
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


def _extract_status(payload: Dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return ''
    status = payload.get('status') or payload.get('statusOrder')
    if status:
        return str(status)
    order_info = payload.get('order')
    if isinstance(order_info, dict):
        status = order_info.get('status')
        if status:
            return str(status)
    data = payload.get('data')
    if isinstance(data, dict):
        status = data.get('status') or data.get('STATUS')
        if status:
            return str(status)
    return ''


def query_order_status_by_order_id(
    merchant_id: str,
    order_id: str,
    access_token: str,
    endpoint: str = 'sandbox',
    *,
    token_refresher: Optional[Callable[[], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    endpoint_key = _normalize_endpoint(endpoint)
    url = ORDER_STATUS_ENDPOINTS[endpoint_key].format(merchant_id=merchant_id, order_id=order_id)
    headers = {'Authorization': access_token, 'Accept': 'application/json'}

    token = access_token
    for attempt in range(2):
        headers['Authorization'] = token
        result = _perform_request(
            'GET',
            url,
            headers=headers,
            error_message=_('Failed to query the Niubiz order status.'),
            allow_token_refresh=True,
        )

        if result['success']:
            payload = _safe_json(result['response'])
            status = _extract_status(payload)
            logger.info('Niubiz order %s status query succeeded with status %s', order_id, status or 'UNKNOWN')
            return {'success': True, 'status': status, 'payload': payload, 'access_token': token}

        if result.get('token_expired') and token_refresher:
            logger.info('Niubiz security token expired while querying order %s. Requesting a new token.', order_id)
            refreshed = token_refresher()
            if not refreshed or not refreshed.get('success'):
                return refreshed or {
                    'success': False,
                    'error': _('Failed to obtain a new Niubiz security token.'),
                }
            token = refreshed['token']
            continue

        return result

    return {'success': False, 'error': _('Failed to query the Niubiz order status.')}


def query_order_status_by_external_id(
    merchant_id: str,
    external_id: str,
    access_token: str,
    endpoint: str = 'sandbox',
    *,
    token_refresher: Optional[Callable[[], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    endpoint_key = _normalize_endpoint(endpoint)
    url = ORDER_EXTERNAL_STATUS_ENDPOINTS[endpoint_key].format(merchant_id=merchant_id, external_id=external_id)
    headers = {'Authorization': access_token, 'Accept': 'application/json'}

    token = access_token
    for attempt in range(2):
        headers['Authorization'] = token
        result = _perform_request(
            'GET',
            url,
            headers=headers,
            error_message=_('Failed to query the Niubiz order status.'),
            allow_token_refresh=True,
        )

        if result['success']:
            payload = _safe_json(result['response'])
            status = _extract_status(payload)
            logger.info('Niubiz order (external %s) status query succeeded with status %s',
                        external_id, status or 'UNKNOWN')
            return {'success': True, 'status': status, 'payload': payload, 'access_token': token}

        if result.get('token_expired') and token_refresher:
            logger.info('Niubiz security token expired while querying order %s (external). Requesting a new token.',
                        external_id)
            refreshed = token_refresher()
            if not refreshed or not refreshed.get('success'):
                return refreshed or {
                    'success': False,
                    'error': _('Failed to obtain a new Niubiz security token.'),
                }
            token = refreshed['token']
            continue

        return result

    return {'success': False, 'error': _('Failed to query the Niubiz order status.')}


def query_transaction_status(
    merchant_id: str,
    transaction_id: str,
    access_token: str,
    endpoint: str = 'sandbox',
    *,
    token_refresher: Optional[Callable[[], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    endpoint_key = _normalize_endpoint(endpoint)
    url = TRANSACTION_STATUS_ENDPOINTS[endpoint_key].format(merchant_id=merchant_id, transaction_id=transaction_id)
    headers = {'Authorization': access_token, 'Accept': 'application/json'}

    token = access_token
    for attempt in range(2):
        headers['Authorization'] = token
        result = _perform_request(
            'GET',
            url,
            headers=headers,
            error_message=_('Failed to query the Niubiz transaction status.'),
            allow_token_refresh=True,
        )

        if result['success']:
            payload = _safe_json(result['response'])
            status = _extract_status(payload)
            logger.info('Niubiz transaction %s status query succeeded with status %s',
                        transaction_id, status or 'UNKNOWN')
            return {'success': True, 'status': status, 'payload': payload, 'access_token': token}

        if result.get('token_expired') and token_refresher:
            logger.info('Niubiz security token expired while querying transaction %s. Requesting a new token.',
                        transaction_id)
            refreshed = token_refresher()
            if not refreshed or not refreshed.get('success'):
                return refreshed or {
                    'success': False,
                    'error': _('Failed to obtain a new Niubiz security token.'),
                }
            token = refreshed['token']
            continue

        return result

    return {'success': False, 'error': _('Failed to query the Niubiz transaction status.')}


def refund_transaction(
    merchant_id: str,
    transaction_id: str,
    amount: Any,
    currency: str,
    access_token: str,
    endpoint: str = 'sandbox',
    *,
    reason: Optional[str] = None,
    token_refresher: Optional[Callable[[], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    endpoint_key = _normalize_endpoint(endpoint)
    url = REFUND_ENDPOINTS[endpoint_key].format(merchant_id=merchant_id, transaction_id=transaction_id)
    headers = {'Content-Type': 'application/json', 'Authorization': access_token}
    body: Dict[str, Any] = {'amount': float(amount), 'currency': currency}
    if reason:
        body['reason'] = reason

    token = access_token
    for attempt in range(2):
        headers['Authorization'] = token
        result = _perform_request(
            'POST',
            url,
            headers=headers,
            json=body,
            error_message=_('Failed to refund the Niubiz transaction.'),
            allow_token_refresh=True,
        )

        if result['success']:
            payload = _safe_json(result['response'])
            status = _extract_status(payload)
            logger.info('Niubiz refund for transaction %s completed with status %s',
                        transaction_id, status or 'UNKNOWN')
            return {'success': True, 'status': status, 'data': payload, 'access_token': token}

        if result.get('token_expired') and token_refresher:
            logger.info('Niubiz security token expired while issuing a refund. Requesting a new token.')
            refreshed = token_refresher()
            if not refreshed or not refreshed.get('success'):
                return refreshed or {
                    'success': False,
                    'error': _('Failed to obtain a new Niubiz security token.'),
                }
            token = refreshed['token']
            continue

        return result

    return {'success': False, 'error': _('Failed to refund the Niubiz transaction.')}
