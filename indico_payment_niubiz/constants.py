from indico.modules.events.payment.models.transactions import TransactionAction

# ------------------------------------------------------------------------------
# Acción de transacción para reembolsos/cancelaciones
# ------------------------------------------------------------------------------
# Algunos Indico antiguos no tienen `TransactionAction.cancel`.
# En ese caso usamos `reject` como fallback para mantener la funcionalidad.
CANCEL_ACTION = getattr(TransactionAction, "cancel", TransactionAction.reject)
