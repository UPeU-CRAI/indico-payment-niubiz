# Niubiz Payment Plugin

The Niubiz payment plugin adds support for processing Indico registration fees
through the [Niubiz web checkout](https://niubiz.com.pe/). It is a refactor of
the original PayPal plugin and exposes the Niubiz security, session and
authorization APIs required for credit and debit card payments (phase 1).

## Installation

1. Clone the repository inside the Indico plugin folder (usually
   `$INDICO_SOURCE/plugins/`).
2. Install the package in the same virtual environment that runs Indico:

   ```bash
   pip install -e indico-payment-niubiz
   ```

3. Restart the Indico web workers after the installation.

## Global configuration

Open **Administration → Customisation → Plugins → Niubiz** and fill the
following fields:

* **Merchant ID** – The Niubiz merchant identifier assigned to your commerce.
* **Access key** – The access key used to request security tokens.
* **Secret key** – The secret key paired with the access key.
* **Environment** – Choose between *Sandbox* (`apisandbox.vnforappstest.com`)
  and *Production* (`apiprod.vnforapps.com`).

All sensitive fields use masked password widgets. The values are stored in the
plugin settings and can be overridden per event if necessary.

## Event configuration

Navigate to **Management → Payments** inside the event, enable the Niubiz
payment method and optionally override the following settings for that specific
event:

* Merchant ID
* Access key
* Secret key
* Environment (leave empty to reuse the global value)

When no event override is provided the global configuration is used.

## Payment flow

1. The registrant clicks **Pay with Niubiz** on the payment page.
2. The plugin calls the Niubiz security API to obtain an access token and then
   requests a session token for the registration purchase.
3. A Niubiz checkout session is launched client-side using the token and the
   registrant completes the card payment.
4. After the checkout returns a `transactionToken`, the plugin authorises the
   transaction via the Niubiz authorization API. If the response contains
   `ACTION_CODE = 000` the registration fee is marked as paid in Indico.
5. The registrant is shown the transaction details (transaction number, amount,
   currency, status and masked card).

## Sandbox testing

Use the sandbox environment to validate the integration before going live. The
plugin automatically points to the following Niubiz endpoints when the
sandbox option is selected:

* Security token – `https://apisandbox.vnforappstest.com/api.security/v1/security`
* Session token – `https://apisandbox.vnforappstest.com/api.ecommerce/v2/ecommerce/token/session/{merchantId}`
* Authorization – `https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/ecommerce/{merchantId}`

The checkout JavaScript is loaded from `https://static-content-qas.vnforapps.com/v2/js/checkout.js`
in sandbox and from `https://static-content.vnforapps.com/v2/js/checkout.js` in
production.
