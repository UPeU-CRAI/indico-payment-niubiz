import requests


def get_security_token(url, username, password):
    resp = requests.post(url, auth=(username, password))
    resp.raise_for_status()
    return resp.json().get('accessToken')


def create_session_token(url, security_token, payload):
    headers = {'Authorization': security_token, 'Content-Type': 'application/json'}
    resp = requests.post(url, json=payload, headers=headers)
    resp.raise_for_status()
    return resp.json().get('sessionKey')
