from __future__ import annotations

import logging
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional

from indico.core.db import db
from indico.modules.events.payment.models.transactions import TransactionAction
from indico.modules.events.payment.util import register_transaction
from indico.modules.events.registration.models.registrations import RegistrationState
from indico.modules.logs.models.entries import EventLogRealm, LogKind

from indico_payment_niubiz import _
from indico_payment_niubiz.constants import CANCEL_ACTION


logger = logging.getLogger(__name__)


def parse_amount(value: Any, fallback: Optional[Decimal]) -> Optional[Decimal]:
    if value is None:
        return fallback
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return fallback


def apply_registration_status(*, registration, paid=None, cancelled=False, expired=False, refunded=False):
    if registration is None:
        return False

    changed = False

    if hasattr(registration, 'set_state'):
        if cancelled:
            registration.set_state(RegistrationState.withdrawn)
            changed = True
        elif expired or refunded:
            registration.set_state(RegistrationState.unpaid)
            changed = True
        elif paid is True:
            registration.set_state(RegistrationState.complete)
            changed = True
        elif paid is False:
            registration.set_state(RegistrationState.rejected)
            changed = True
    else:
        if cancelled:
            registration.update_state(withdrawn=True, paid=False)
            changed = True
        elif expired or refunded:
            registration.update_state(paid=False)
            changed = True
        elif paid is True:
            registration.update_state(paid=True)
            changed = True
        elif paid is False:
            registration.update_state(paid=False)
            changed = True

    if changed:
        db.session.flush()
    return changed


def log_registration_event(registration, summary: str, *, kind: LogKind, data: Optional[Dict[str, Any]] = None,
                           meta: Optional[Dict[str, Any]] = None) -> None:
    event = getattr(registration, 'event', None)
    log_method = getattr(event, 'log', None)
    if not callable(log_method):
        return
    user = getattr(registration, 'user', None)
    try:
        log_method(EventLogRealm.participants, kind, 'Niubiz', summary, user=user, data=data or {}, meta=meta or {})
    except Exception:  # pragma: no cover - we do not want logging failures to break payment flows
        logger.exception('Could not write Niubiz entry to the event log')


def build_transaction_data(*, payload: Optional[Dict[str, Any]] = None, source: Optional[str] = None,
                           status: Optional[str] = None, action_code: Optional[str] = None,
                           transaction_id: Optional[str] = None, order_id: Optional[str] = None,
                           external_id: Optional[str] = None, message: Optional[str] = None,
                           reason: Optional[str] = None) -> Dict[str, Any]:
    data: Dict[str, Any] = {'provider': 'niubiz'}
    if source:
        data['source'] = source
    if payload is not None:
        data['payload'] = payload
    if status:
        data['status'] = status
    if action_code:
        data['action_code'] = action_code
    if transaction_id:
        data['transaction_id'] = transaction_id
    if order_id:
        data['order_id'] = order_id
    if external_id:
        data['external_id'] = external_id
    if message:
        data['message'] = message
    if reason:
        data['reason'] = reason
    return data


def record_payment_transaction(*, registration, amount: Any, currency: str, action: TransactionAction,
                               data: Optional[Dict[str, Any]] = None):
    try:
        amount_value = float(amount)
    except (TypeError, ValueError):
        amount_value = float(getattr(registration, 'price', 0) or 0)
    transaction = register_transaction(registration=registration,
                                       amount=amount_value,
                                       currency=currency,
                                       action=action,
                                       provider='niubiz',
                                       data=data or {})
    return transaction


def build_log_data(*, amount: Optional[Decimal], currency: str, transaction_id: Optional[str], status: Optional[str],
                   action_code: Optional[str], state_changed: bool) -> Dict[str, Any]:
    return {
        'amount': float(amount) if amount is not None else None,
        'currency': currency,
        'transaction_id': transaction_id,
        'status': status,
        'action_code': action_code,
        'state_changed': state_changed,
    }


def handle_successful_payment(registration, *, amount: Optional[Decimal], currency: str,
                              transaction_id: Optional[str], status: Optional[str], action_code: Optional[str],
                              summary: str, data: Dict[str, Any], kind: LogKind = LogKind.positive) -> None:
    changed = apply_registration_status(registration=registration, paid=True)
    log_registration_event(registration, summary, kind=kind,
                           data=build_log_data(amount=amount, currency=currency,
                                               transaction_id=transaction_id, status=status,
                                               action_code=action_code, state_changed=changed))
    record_payment_transaction(registration=registration,
                               amount=amount if amount is not None else getattr(registration, 'price', 0),
                               currency=currency,
                               action=TransactionAction.complete,
                               data=data)


def handle_failed_payment(registration, *, amount: Optional[Decimal], currency: str,
                          transaction_id: Optional[str], status: Optional[str], action_code: Optional[str],
                          summary: str, data: Dict[str, Any], cancelled: bool = False,
                          expired: bool = False) -> None:
    if cancelled:
        changed = apply_registration_status(registration=registration, cancelled=True)
        action = CANCEL_ACTION
        log_kind = LogKind.change
    elif expired:
        changed = apply_registration_status(registration=registration, expired=True)
        action = TransactionAction.reject
        log_kind = LogKind.change
    else:
        changed = apply_registration_status(registration=registration, paid=False)
        action = TransactionAction.reject
        log_kind = LogKind.negative

    log_registration_event(registration, summary, kind=log_kind,
                           data=build_log_data(amount=amount, currency=currency,
                                               transaction_id=transaction_id, status=status,
                                               action_code=action_code, state_changed=changed))
    record_payment_transaction(registration=registration,
                               amount=amount if amount is not None else getattr(registration, 'price', 0),
                               currency=currency,
                               action=action,
                               data=data)


def handle_refund(registration, *, amount: Optional[Decimal], currency: str, transaction_id: Optional[str],
                  status: Optional[str], summary: str, data: Dict[str, Any], success: bool) -> None:
    if success:
        changed = apply_registration_status(registration=registration, refunded=True)
        log_kind = LogKind.change
        action = CANCEL_ACTION
    else:
        changed = False
        log_kind = LogKind.negative
        action = TransactionAction.reject

    log_registration_event(registration, summary, kind=log_kind,
                           data=build_log_data(amount=amount, currency=currency,
                                               transaction_id=transaction_id, status=status,
                                               action_code=None, state_changed=changed))
    record_payment_transaction(registration=registration,
                               amount=amount if amount is not None else getattr(registration, 'price', 0),
                               currency=currency,
                               action=action,
                               data=data)

