# Niubiz Payment Plugin

This plugin provides a Niubiz payment option for Indico's payment module.

The plugin integrates the Niubiz web checkout. It creates the required security
and session tokens server-side and then loads the Niubiz checkout form on the
registration payment page. After the payment is processed Niubiz will send a
callback to Indico which will register the transaction and update the
registration status automatically.
