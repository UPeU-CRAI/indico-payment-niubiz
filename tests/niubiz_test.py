from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from flask import Flask, request

import requests

from indico.modules.events.registration.models.registrations import RegistrationState

from indico_payment_niubiz.controllers import RHNiubizCallback, RHNiubizSuccess
from indico_payment_niubiz.indico_integration import apply_registration_status, handle_failed_payment
from indico_payment_niubiz.plugin import NiubizPaymentPlugin
from indico_payment_niubiz.util import (create_session_token, get_security_token,
                                        query_order_status_by_order_id, query_transaction_status)


def _build_response(*, text='', json_payload=None, status_code=200):
    response = Mock()
    response.status_code = status_code
    response.text = text
    response.json = Mock(return_value=json_payload if json_payload is not None else {})
    response.raise_for_status = Mock()
    return response


@pytest.fixture
def flask_app():
    app = Flask(__name__)
    app.secret_key = 'testing-niubiz'
    return app


def _make_registration():
    registration = Mock()
    registration.price = 50
    registration.currency = 'PEN'
    registration.event_id = 1
    registration.id = 10
    registration.registration_form_id = 2
    registration.registration_form = SimpleNamespace(id=2)
    event_log = Mock()
    registration.event = SimpleNamespace(id=1, log=event_log)
    registration.locator = SimpleNamespace(registrant='locator-token')
    registration.set_state = Mock()
    registration.update_state = Mock()
    registration.event.log = event_log
    registration.user = SimpleNamespace(id=5)
    return registration


def _make_plugin(settings=None, event_settings=None):
    class DummyPlugin(NiubizPaymentPlugin):
        name = 'payment_niubiz_test'

    class _Settings:
        def __init__(self, data):
            self._data = data

        def get(self, name):
            return self._data.get(name)

        def get_all(self, event=None):
            return dict(self._data)

    class _EventSettings:
        def __init__(self, data):
            self._data = data

        def get(self, event, name):
            return self._data.get(name)

        def get_all(self, event):
            return dict(self._data)

    settings_proxy = _Settings(settings or {
        'merchant_id': 'MERCHANT',
        'access_key': 'ACCESS',
        'secret_key': 'SECRET',
        'endpoint': 'sandbox',
    })
    event_settings_proxy = _EventSettings(event_settings or {})
    DummyPlugin.settings = settings_proxy
    DummyPlugin.event_settings = event_settings_proxy
    return object.__new__(DummyPlugin)


def test_get_security_token_returns_token():
    response = _build_response(text='  my-token  ')

    with patch('indico_payment_niubiz.util.requests.request', return_value=response) as mock_request:
        result = get_security_token('access', 'secret', 'sandbox')

    assert result['success'] is True
    assert result['token'] == 'my-token'
    mock_request.assert_called_once()
    response.raise_for_status.assert_called_once()


def test_authorization_success_marks_registration_paid(flask_app, monkeypatch):
    registration = _make_registration()
    handler = RHNiubizSuccess()
    handler.registration = registration
    handler.event = registration.event

    monkeypatch.setattr(RHNiubizSuccess, '_get_credentials', lambda self: ('access', 'secret'))
    monkeypatch.setattr(RHNiubizSuccess, '_get_endpoint', lambda self: 'sandbox')
    monkeypatch.setattr(RHNiubizSuccess, '_get_merchant_id', lambda self: 'MERCHANT')
    monkeypatch.setattr(RHNiubizSuccess, '_get_purchase_number', lambda self: '1-10')

    token_payload = {'success': True, 'token': 'SEC_TOKEN'}
    auth_payload = {
        'data': {
            'ACTION_CODE': '000',
            'AUTHORIZATION_CODE': '123456',
            'TRANSACTION_ID': 'T-100',
            'TRANSACTION_DATE': '2024-01-01T12:00:00',
            'CARD': {'PAN': '411111******1111'},
            'STATUS': 'completed',
        }
    }

    monkeypatch.setattr('indico_payment_niubiz.controllers.get_security_token', lambda *a, **k: token_payload)
    monkeypatch.setattr('indico_payment_niubiz.controllers.authorize_transaction',
                        lambda *a, **k: {'success': True, 'data': auth_payload})
    transactions = []

    def fake_register_transaction(**kwargs):
        transactions.append(kwargs)
        return None

    monkeypatch.setattr('indico_payment_niubiz.indico_integration.register_transaction', fake_register_transaction)
    monkeypatch.setattr('indico_payment_niubiz.indico_integration.db.session.flush', lambda: None)
    monkeypatch.setattr('indico_payment_niubiz.controllers.url_for', lambda *a, **k: 'redirect-url')

    flashes = []
    monkeypatch.setattr('indico_payment_niubiz.controllers.flash', lambda message, category: flashes.append((category, message)))

    rendered = {}

    def fake_render(template_name, **context):
        rendered['template'] = template_name
        rendered['context'] = context
        return context

    monkeypatch.setattr('indico_payment_niubiz.controllers.render_template', fake_render)

    with flask_app.test_request_context('/success/10', method='POST', data={'transactionToken': 'checkout-token'},
                                        environ_overrides={'REMOTE_ADDR': '198.51.100.10'}):
        result = handler._process()

    registration.set_state.assert_called_once_with(RegistrationState.complete)
    registration.update_state.assert_not_called()
    assert flashes == [('success', '¡Tu pago ha sido procesado con éxito!')]
    assert rendered['template'] == 'payment_niubiz/transaction_details.html'
    assert result['status_label'] == 'Autorizado'
    assert transactions
    assert transactions[0]['data']['source'] == 'checkout'
    assert registration.event.log.call_args[0][3] == 'Niubiz confirmó el pago.'


def test_authorization_rejection_marks_registration_rejected(flask_app, monkeypatch):
    registration = _make_registration()
    handler = RHNiubizSuccess()
    handler.registration = registration
    handler.event = registration.event

    monkeypatch.setattr(RHNiubizSuccess, '_get_credentials', lambda self: ('access', 'secret'))
    monkeypatch.setattr(RHNiubizSuccess, '_get_endpoint', lambda self: 'sandbox')
    monkeypatch.setattr(RHNiubizSuccess, '_get_merchant_id', lambda self: 'MERCHANT')
    monkeypatch.setattr(RHNiubizSuccess, '_get_purchase_number', lambda self: '1-10')

    token_payload = {'success': True, 'token': 'SEC_TOKEN'}
    auth_payload = {
        'data': {
            'ACTION_CODE': '101',
            'ACTION_DESCRIPTION': 'Tarjeta rechazada',
            'TRANSACTION_ID': 'T-101',
            'TRANSACTION_DATE': '2024-01-02T10:30:00',
            'CARD': {'PAN': '411111******1111'},
            'STATUS': 'denied',
        }
    }

    monkeypatch.setattr('indico_payment_niubiz.controllers.get_security_token', lambda *a, **k: token_payload)
    monkeypatch.setattr('indico_payment_niubiz.controllers.authorize_transaction',
                        lambda *a, **k: {'success': True, 'data': auth_payload})
    transactions = []

    def fake_register_transaction(**kwargs):
        transactions.append(kwargs)
        return None

    monkeypatch.setattr('indico_payment_niubiz.indico_integration.register_transaction', fake_register_transaction)
    monkeypatch.setattr('indico_payment_niubiz.indico_integration.db.session.flush', lambda: None)
    monkeypatch.setattr('indico_payment_niubiz.controllers.url_for', lambda *a, **k: 'redirect-url')

    flashes = []
    monkeypatch.setattr('indico_payment_niubiz.controllers.flash', lambda message, category: flashes.append((category, message)))

    def fake_render(template_name, **context):
        return context

    monkeypatch.setattr('indico_payment_niubiz.controllers.render_template', fake_render)

    with flask_app.test_request_context('/success/10', method='POST', data={'transactionToken': 'checkout-token'},
                                        environ_overrides={'REMOTE_ADDR': '198.51.100.10'}):
        result = handler._process()

    registration.set_state.assert_called_once_with(RegistrationState.rejected)
    registration.update_state.assert_not_called()
    assert flashes == [('error', 'Niubiz rechazó tu pago (código 101). Tarjeta rechazada')]
    assert result['status_label'] == 'Rechazado'
    assert transactions
    assert transactions[0]['data']['source'] == 'checkout'
    assert registration.event.log.call_args[0][3] == 'Niubiz rechazó el pago.'


def test_notify_expired_marks_registration_expired(monkeypatch):
    registration = _make_registration()

    monkeypatch.setattr('indico_payment_niubiz.indico_integration.register_transaction', lambda **kwargs: None)
    monkeypatch.setattr('indico_payment_niubiz.indico_integration.db.session.flush', lambda: None)

    handle_failed_payment(
        registration,
        amount=None,
        currency='PEN',
        transaction_id='T-1',
        status='EXPIRED',
        action_code=None,
        summary='Expired',
        data={},
        expired=True,
    )

    registration.set_state.assert_called_once_with(RegistrationState.unpaid)
    registration.update_state.assert_not_called()


def test_session_token_refreshes_on_token_expiration(monkeypatch):
    expired_response = _build_response(json_payload={'errorMessage': 'token expired'}, status_code=401)
    expired_error = requests.exceptions.HTTPError(response=expired_response)
    expired_response.raise_for_status.side_effect = expired_error

    success_response = _build_response(json_payload={'sessionKey': 'SESSION123'})

    post_mock = Mock(side_effect=[expired_response, success_response])
    monkeypatch.setattr('indico_payment_niubiz.util.requests.request', post_mock)

    refreshed_tokens = []

    def refresher():
        refreshed_tokens.append(True)
        return {'success': True, 'token': 'NEW_TOKEN'}

    result = create_session_token('MERCHANT', 10, 'PEN', 'OLD_TOKEN', 'sandbox', token_refresher=refresher)

    assert result['success'] is True
    assert result['session_key'] == 'SESSION123'
    assert len(refreshed_tokens) == 1
    assert post_mock.call_count == 2
    assert post_mock.call_args_list[-1][1]['headers']['Authorization'] == 'NEW_TOKEN'


def test_get_security_token_uses_cache(monkeypatch):
    response = _build_response(text='TOKEN_A')

    request_mock = Mock(return_value=response)
    monkeypatch.setattr('indico_payment_niubiz.util.requests.request', request_mock)

    first = get_security_token('access', 'secret', 'sandbox')
    second = get_security_token('access', 'secret', 'sandbox')

    assert first['success'] is True
    assert second['success'] is True
    assert second.get('cached') is True
    assert request_mock.call_count == 1


def test_get_security_token_force_refresh(monkeypatch):
    first_response = _build_response(text='TOKEN_A')
    second_response = _build_response(text='TOKEN_B')
    request_mock = Mock(side_effect=[first_response, second_response])
    monkeypatch.setattr('indico_payment_niubiz.util.requests.request', request_mock)

    first = get_security_token('access', 'secret', 'sandbox')
    second = get_security_token('access', 'secret', 'sandbox', force_refresh=True)

    assert first['token'] == 'TOKEN_A'
    assert second['token'] == 'TOKEN_B'
    assert request_mock.call_count == 2


def test_query_order_status_success(monkeypatch):
    response = _build_response(json_payload={'status': 'COMPLETED'})
    request_mock = Mock(return_value=response)
    monkeypatch.setattr('indico_payment_niubiz.util.requests.request', request_mock)

    result = query_order_status_by_order_id('MERCHANT', 'ORDER1', 'TOKEN', 'sandbox')

    assert result['success'] is True
    assert result['status'] == 'COMPLETED'
    assert request_mock.call_args[0][0] == 'GET'
    assert 'ORDER1' in request_mock.call_args[0][1]


def test_query_order_status_refreshes_token(monkeypatch):
    expired_response = _build_response(json_payload={'message': 'expired'}, status_code=401)
    expired_error = requests.exceptions.HTTPError(response=expired_response)
    expired_response.raise_for_status.side_effect = expired_error
    success_response = _build_response(json_payload={'status': 'COMPLETED'})

    request_mock = Mock(side_effect=[expired_response, success_response])
    monkeypatch.setattr('indico_payment_niubiz.util.requests.request', request_mock)

    refreshed = []

    def refresher():
        refreshed.append(True)
        return {'success': True, 'token': 'NEW'}

    result = query_order_status_by_order_id('MERCHANT', 'ORDER1', 'OLD', 'sandbox', token_refresher=refresher)

    assert result['success'] is True
    assert refreshed == [True]
    assert request_mock.call_count == 2
    assert request_mock.call_args_list[-1][1]['headers']['Authorization'] == 'NEW'


def test_query_transaction_status_success(monkeypatch):
    response = _build_response(json_payload={'status': 'CANCELED'})
    request_mock = Mock(return_value=response)
    monkeypatch.setattr('indico_payment_niubiz.util.requests.request', request_mock)

    result = query_transaction_status('MERCHANT', 'TXN-1', 'TOKEN', 'sandbox')

    assert result['success'] is True
    assert result['status'] == 'CANCELED'
    assert request_mock.call_args[0][0] == 'GET'
    assert 'TXN-1' in request_mock.call_args[0][1]


def test_authorization_pending_triggers_status_sync(flask_app, monkeypatch):
    registration = _make_registration()
    handler = RHNiubizSuccess()
    handler.registration = registration
    handler.event = registration.event

    monkeypatch.setattr(RHNiubizSuccess, '_get_credentials', lambda self: ('access', 'secret'))
    monkeypatch.setattr(RHNiubizSuccess, '_get_endpoint', lambda self: 'sandbox')
    monkeypatch.setattr(RHNiubizSuccess, '_get_merchant_id', lambda self: 'MERCHANT')
    monkeypatch.setattr(RHNiubizSuccess, '_get_purchase_number', lambda self: '1-10')

    token_payload = {'success': True, 'token': 'SEC_TOKEN'}
    auth_payload = {
        'data': {
            'ACTION_CODE': '000',
            'TRANSACTION_ID': 'T-200',
            'STATUS': 'pending',
        }
    }

    monkeypatch.setattr('indico_payment_niubiz.controllers.get_security_token', lambda *a, **k: token_payload)
    monkeypatch.setattr('indico_payment_niubiz.controllers.authorize_transaction',
                        lambda *a, **k: {'success': True, 'data': auth_payload})
    monkeypatch.setattr('indico_payment_niubiz.indico_integration.register_transaction', lambda **kwargs: None)
    monkeypatch.setattr('indico_payment_niubiz.indico_integration.db.session.flush', lambda: None)
    monkeypatch.setattr('indico_payment_niubiz.controllers.url_for', lambda *a, **k: 'redirect-url')

    flashes = []
    monkeypatch.setattr('indico_payment_niubiz.controllers.flash',
                        lambda message, category: flashes.append((category, message)))

    sync_calls = []

    def fake_sync(**kwargs):
        sync_calls.append(kwargs)
        apply_registration_status(registration=registration, paid=True)
        return {'success': True, 'status': 'COMPLETED'}

    monkeypatch.setattr('indico_payment_niubiz.controllers._synchronise_registration_with_query', fake_sync)

    rendered = {}

    def fake_render(template_name, **context):
        rendered['template'] = template_name
        rendered['context'] = context
        return context

    monkeypatch.setattr('indico_payment_niubiz.controllers.render_template', fake_render)

    with flask_app.test_request_context('/success/10', method='POST', data={'transactionToken': 'checkout-token'}):
        handler._process()

    assert sync_calls
    registration.set_state.assert_called_with(RegistrationState.complete)
    assert flashes[-1] == ('success', '¡Tu pago ha sido procesado con éxito!')
    assert rendered['template'] == 'payment_niubiz/transaction_details.html'


def test_notify_pending_triggers_status_query(flask_app, monkeypatch):
    registration = _make_registration()

    filter_mock = Mock()
    filter_mock.first.return_value = registration
    query_mock = Mock()
    query_mock.filter_by.return_value = filter_mock

    dummy_registration_model = SimpleNamespace(query=query_mock)
    monkeypatch.setattr('indico_payment_niubiz.controllers.Registration', dummy_registration_model)
    monkeypatch.setattr('indico_payment_niubiz.indico_integration.db.session.flush', lambda: None)

    sync_calls = []

    def fake_sync(**kwargs):
        sync_calls.append(kwargs)
        apply_registration_status(registration=registration, paid=True)
        return {'success': True, 'status': 'COMPLETED'}

    monkeypatch.setattr('indico_payment_niubiz.controllers._synchronise_registration_with_query', fake_sync)

    monkeypatch.setattr('indico_payment_niubiz.controllers._', lambda value: value)

    handler = RHNiubizCallback()

    with flask_app.test_request_context('/notify', method='POST',
                                        json={'orderId': '1-10', 'statusOrder': 'PENDING',
                                              'amount': '10.00', 'currency': 'PEN'}):
        request.view_args = {'event_id': 1, 'reg_form_id': 2}
        handler._process()

    assert sync_calls
    registration.set_state.assert_called_with(RegistrationState.complete)


def test_plugin_refund_success(monkeypatch):
    plugin = _make_plugin()
    registration = _make_registration()
    transaction = SimpleNamespace(amount=50, currency='PEN',
                                  data={'transaction_id': 'T-500'}, registration=registration)

    monkeypatch.setattr('indico_payment_niubiz.plugin.get_security_token',
                        lambda *a, **k: {'success': True, 'token': 'SEC'})

    refund_calls = []

    def fake_refund_transaction(**kwargs):
        refund_calls.append(kwargs)
        return {'success': True, 'status': 'SUCCESS', 'data': {'status': 'SUCCESS'}}

    monkeypatch.setattr('indico_payment_niubiz.plugin.refund_transaction', fake_refund_transaction)

    handled = []

    def fake_handle_refund(registration, **kwargs):
        handled.append(kwargs)

    monkeypatch.setattr('indico_payment_niubiz.plugin.handle_refund', fake_handle_refund)

    result = plugin.refund(registration, transaction, amount=25, reason='requested')

    assert result['success'] is True
    assert result['status'] == 'SUCCESS'
    assert refund_calls
    assert refund_calls[0]['amount'] == 25.0
    assert handled
    assert handled[0]['success'] is True
    assert handled[0]['data']['source'] == 'refund'
    assert handled[0]['data']['transaction_id'] == 'T-500'
    assert handled[0]['summary'] == 'Se registró un reembolso de Niubiz.'


def test_plugin_refund_missing_transaction_id(monkeypatch):
    plugin = _make_plugin()
    registration = _make_registration()
    transaction = SimpleNamespace(amount=50, currency='PEN', data={}, registration=registration)

    handled = []
    monkeypatch.setattr('indico_payment_niubiz.plugin.handle_refund',
                        lambda registration, **kwargs: handled.append(kwargs))

    result = plugin.refund(registration, transaction)

    assert result['success'] is False
    assert handled
    assert handled[0]['success'] is False
    assert 'No se pudo determinar el identificador' in handled[0]['summary']
