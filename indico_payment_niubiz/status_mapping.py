from indico.modules.events.payment.models.transactions import TransactionAction

NIUBIZ_STATUS_MAP = {
    "AUTHORIZED": {
        "action": TransactionAction.complete,
        "toggle_paid": True,
        "summary": "Pago confirmado por Niubiz"
    },
    "REJECTED": {
        "action": TransactionAction.reject,
        "toggle_paid": False,
        "summary": "Pago rechazado por Niubiz"
    },
    "NOT AUTHORIZED": {
        "action": TransactionAction.reject,
        "toggle_paid": False,
        "summary": "Pago no autorizado por Niubiz"
    },
    "VOIDED": {
        "action": TransactionAction.cancel,
        "toggle_paid": False,
        "summary": "Pago anulado por Niubiz"
    },
    "CANCELLED": {
        "action": TransactionAction.cancel,
        "toggle_paid": False,
        "summary": "Pago cancelado por Niubiz"
    },
    "PENDING": {
        "action": TransactionAction.pending,
        "toggle_paid": False,
        "summary": "Pago pendiente en Niubiz"
    },
    "REFUNDED": {
        "action": TransactionAction.cancel,
        "toggle_paid": False,
        "summary": "Reembolso confirmado por Niubiz"
    },
    "EXPIRED": {
        "action": TransactionAction.reject,
        "toggle_paid": False,
        "summary": "Orden expirada en Niubiz"
    },
    "REVIEW": {
        "action": TransactionAction.pending,
        "toggle_paid": False,
        "summary": "Pago en revisión antifraude Niubiz"
    },
}

DEFAULT_STATUS = {
    "action": TransactionAction.reject,
    "toggle_paid": False,
    "summary": "Estado desconocido recibido desde Niubiz"
}
