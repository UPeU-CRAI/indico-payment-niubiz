from indico_payment_niubiz.schema import StatusMapping, TransactionStatus
from indico_payment_niubiz.utils import map_niubiz_status


def test_successful_mapping_on_authorized():
    mapping = map_niubiz_status(status="AUTHORIZED", action_code="000")
    assert isinstance(mapping, StatusMapping)
    assert mapping.status == TransactionStatus.successful


def test_pending_mapping_for_yape():
    mapping = map_niubiz_status(
        status="authorized",
        action_code="123",
        payment_method="Yape",
    )
    assert mapping.status == TransactionStatus.pending


def test_failed_mapping_for_rejected():
    mapping = map_niubiz_status(status="REJECTED", action_code="116")
    assert mapping.status == TransactionStatus.failed


def test_cancelled_mapping_for_action_code():
    mapping = map_niubiz_status(status="", action_code="9997")
    assert mapping.status == TransactionStatus.cancelled
