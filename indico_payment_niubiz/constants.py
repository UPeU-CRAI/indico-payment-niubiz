from indico.modules.events.payment.models.transactions import TransactionAction


#: Transaction action used when Niubiz reports a cancellation. Older
#: Indico versions do not expose the ``cancel`` action so we fall back to the
#: ``reject`` action to keep the integration functional.
CANCEL_ACTION = getattr(TransactionAction, 'cancel', TransactionAction.reject)

