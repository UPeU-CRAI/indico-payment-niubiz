import base64
from typing import Any, Dict

import requests


def _is_legacy_security_args(endpoint: str) -> bool:
    return endpoint not in {"sandbox", "prod"}


def _is_legacy_session_args(currency: Any) -> bool:
    return isinstance(currency, dict)


def get_security_token(access_key: str, secret_key: str, endpoint: str = "sandbox") -> str:
    """Generates a security token from the Niubiz security API."""

    if _is_legacy_security_args(endpoint):
        resp = requests.post(access_key, auth=(secret_key, endpoint))
        resp.raise_for_status()
        try:
            return resp.json().get("accessToken")
        except ValueError:
            return resp.text.strip()

    url = {
        "sandbox": "https://apisandbox.vnforappstest.com/api.security/v1/security",
        "prod": "https://apiprod.vnforapps.com/api.security/v1/security",
    }[endpoint]

    auth = f"{access_key}:{secret_key}".encode("utf-8")
    headers = {"Authorization": "Basic " + base64.b64encode(auth).decode("utf-8")}
    response = requests.post(url, headers=headers)
    response.raise_for_status()
    return response.text.strip()


def create_session_token(
    merchant_id: str,
    amount: Any,
    currency: str,
    access_token: str,
    endpoint: str = "sandbox",
) -> str:
    """Generates a session token for the Niubiz web checkout."""

    if _is_legacy_session_args(currency):
        url = merchant_id
        security_token = amount
        payload: Dict[str, Any] = currency
        headers = {"Authorization": security_token, "Content-Type": "application/json"}
        resp = requests.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json().get("sessionKey")

    url = {
        "sandbox": f"https://apisandbox.vnforappstest.com/api.ecommerce/v2/ecommerce/token/session/{merchant_id}",
        "prod": f"https://apiprod.vnforapps.com/api.ecommerce/v2/ecommerce/token/session/{merchant_id}",
    }[endpoint]

    headers = {"Content-Type": "application/json", "Authorization": access_token}
    body = {
        "channel": "web",
        "amount": float(amount),
        "currency": currency,
        "antifraud": {"clientIp": "127.0.0.1"},
        "dataMap": {"clientId": "indico-user"},
    }
    response = requests.post(url, json=body, headers=headers)
    response.raise_for_status()
    return response.json()["sessionKey"]


def authorize_transaction(
    merchant_id: str,
    transaction_token: str,
    purchase_number: str,
    amount: Any,
    currency: str,
    access_token: str,
    endpoint: str = "sandbox",
) -> Dict[str, Any]:
    """Authorizes a Niubiz transaction using the checkout transaction token."""

    url = {
        "sandbox": f"https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/ecommerce/{merchant_id}",
        "prod": f"https://apiprod.vnforapps.com/api.authorization/v3/authorization/ecommerce/{merchant_id}",
    }[endpoint]

    headers = {"Content-Type": "application/json", "Authorization": access_token}
    body = {
        "channel": "web",
        "captureType": "manual",
        "countable": True,
        "order": {
            "tokenId": transaction_token,
            "purchaseNumber": purchase_number,
            "amount": float(amount),
            "currency": currency,
        },
        "dataMap": {"clientIp": "127.0.0.1"},
    }
    response = requests.post(url, json=body, headers=headers)
    response.raise_for_status()
    return response.json()
