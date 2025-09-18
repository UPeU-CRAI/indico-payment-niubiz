from indico.modules.events.payment.models.transactions import TransactionAction

# -----------------------------------------------------
# Mapeo de estados Niubiz → acciones Indico
# -----------------------------------------------------
NIUBIZ_STATUS_MAP = {
    # Pagos confirmados
    "AUTHORIZED": {
        "action": TransactionAction.complete,
        "toggle_paid": True,
        "summary": "Pago confirmado por Niubiz",
    },

    # Pagos rechazados / no autorizados
    "REJECTED": {
        "action": TransactionAction.reject,
        "toggle_paid": False,
        "summary": "Pago rechazado por Niubiz",
    },
    "NOT AUTHORIZED": {
        "action": TransactionAction.reject,
        "toggle_paid": False,
        "summary": "Pago no autorizado por Niubiz",
    },
    "NOT_AUTHORIZED": {  # alias común en payloads
        "action": TransactionAction.reject,
        "toggle_paid": False,
        "summary": "Pago no autorizado por Niubiz",
    },

    # Cancelaciones / anulaciones
    "VOIDED": {
        "action": TransactionAction.cancel,
        "toggle_paid": False,
        "summary": "Pago anulado por Niubiz",
    },
    "CANCELLED": {
        "action": TransactionAction.cancel,
        "toggle_paid": False,
        "summary": "Pago cancelado por Niubiz",
    },
    "CANCELED": {  # alias US spelling
        "action": TransactionAction.cancel,
        "toggle_paid": False,
        "summary": "Pago cancelado por Niubiz",
    },

    # Pendientes (incluye antifraude)
    "PENDING": {
        "action": TransactionAction.pending,
        "toggle_paid": False,
        "summary": "Pago pendiente en Niubiz",
    },
    "REVIEW": {
        "action": TransactionAction.pending,
        "toggle_paid": False,
        "summary": "Pago en revisión antifraude Niubiz",
    },

    # Reembolsos
    "REFUNDED": {
        "action": TransactionAction.cancel,
        "toggle_paid": False,
        "summary": "Reembolso confirmado por Niubiz",
    },

    # Expirados
    "EXPIRED": {
        "action": TransactionAction.reject,
        "toggle_paid": False,
        "summary": "Orden expirada en Niubiz",
    },
}

# Estado por defecto cuando Niubiz envía algo no reconocido
DEFAULT_STATUS = {
    "action": TransactionAction.reject,
    "toggle_paid": False,
    "summary": "Estado desconocido recibido desde Niubiz",
}
