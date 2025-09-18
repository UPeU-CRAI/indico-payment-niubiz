"""
Centraliza el mapeo de estados de Niubiz a acciones y efectos en Indico.
"""

from indico.modules.events.payment.models.transactions import TransactionAction

# Diccionario principal: estados Niubiz → configuración de Indico
NIUBIZ_STATUS_MAP = {
    # ------------------------------
    # Confirmados
    # ------------------------------
    "AUTHORIZED": {
        "action": TransactionAction.complete,
        "toggle_paid": True,
        "summary": "Pago confirmado exitosamente por Niubiz",
    },

    # ------------------------------
    # Fallidos / No autorizados
    # ------------------------------
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
    "NOT_AUTHORIZED": {
        "action": TransactionAction.reject,
        "toggle_paid": False,
        "summary": "Pago no autorizado por Niubiz",
    },

    # ------------------------------
    # Anulados / Cancelados
    # ------------------------------
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
    "CANCELED": {
        "action": TransactionAction.cancel,
        "toggle_paid": False,
        "summary": "Pago cancelado por Niubiz",
    },

    # ------------------------------
    # Pendientes
    # ------------------------------
    "PENDING": {
        "action": TransactionAction.pending,
        "toggle_paid": False,
        "summary": "Pago pendiente en Niubiz",
    },
    "REVIEW": {
        "action": TransactionAction.pending,
        "toggle_paid": False,
        "summary": "Pago en revisión antifraude",
    },

    # ------------------------------
    # Expirados
    # ------------------------------
    "EXPIRED": {
        "action": TransactionAction.reject,
        "toggle_paid": False,
        "summary": "Pago expirado en Niubiz",
    },

    # ------------------------------
    # Reembolsos
    # ------------------------------
    "REFUNDED": {
        "action": TransactionAction.cancel,
        "toggle_paid": True,  # revierte a "no pagada"
        "summary": "Pago reembolsado por Niubiz",
    },
}

# Configuración por defecto en caso de estado desconocido
DEFAULT_STATUS = {
    "action": TransactionAction.reject,
    "toggle_paid": False,
    "summary": "Estado de pago desconocido recibido desde Niubiz",
}
