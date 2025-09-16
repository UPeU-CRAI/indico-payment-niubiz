# Niubiz Payment Plugin

The Niubiz payment plugin adds support for processing Indico registration fees
through the [Niubiz web checkout](https://niubiz.com.pe/). It is a refactor of
the original PayPal plugin and exposes the Niubiz security, session and
authorization APIs required for credit and debit card payments (phase 1).

## Prerequisites

Before installing the plugin make sure you have the following:

* Niubiz sandbox credentials (merchant ID, access key and secret key).
* Access to the Niubiz portal in order to rotate the credentials when needed.
* An Indico instance where you can install third-party plugins.

## Installation

1. Clone the repository inside the Indico plugin folder (usually
   `$INDICO_SOURCE/plugins/`).
2. Install the package in the same virtual environment that runs Indico:

   ```bash
   pip install -e indico-payment-niubiz
   ```

3. Restart the Indico web workers after the installation.

## Configuration

### Global configuration

Open **Administration → Customisation → Plugins → Niubiz** and fill the
following fields:

* **Merchant ID** – The Niubiz merchant identifier assigned to your commerce.
* **Access key** – The access key used to request security tokens.
* **Secret key** – The secret key paired with the access key.
* **Environment** – Choose between *Sandbox* (`apisandbox.vnforappstest.com`)
  and *Production* (`apiprod.vnforapps.com`).

All sensitive fields use masked password widgets. The values are stored in the
plugin settings and can be overridden per event if necessary.

### Event configuration

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

## Sandbox testing workflow

Use the sandbox environment to validate the integration before going live. The
plugin automatically points to the following Niubiz endpoints when the sandbox
option is selected:

* Security token – `https://apisandbox.vnforappstest.com/api.security/v1/security`
* Session token – `https://apisandbox.vnforappstest.com/api.ecommerce/v2/ecommerce/token/session/{merchantId}`
* Authorization – `https://apisandbox.vnforappstest.com/api.authorization/v3/authorization/ecommerce/{merchantId}`

The checkout JavaScript is loaded from `https://static-content-qas.vnforapps.com/v2/js/checkout.js`
in sandbox and from `https://static-content.vnforapps.com/v2/js/checkout.js` in
production.

### Recommended test flow

1. Configure the plugin in sandbox mode and verify that Indico can request a
   security token successfully.
2. Start a registration payment using the **Pay with Niubiz** button. The
   plugin will create a `sessionToken` and launch the Niubiz checkout.
3. Use the test card `4111111111111111` with any future expiry date and CVV
   `123` (or any other value accepted by the sandbox).
4. Use an amount of at least **10.00 PEN**. Smaller amounts can be rejected by
   antifraud rules in the sandbox.
5. Complete the checkout. The Niubiz callback should return
   `ACTION_CODE == "000"` for a successful authorization.
6. The registration is marked as paid and the transaction details page displays
   the purchase number, transaction ID, authorization code, masked card, amount
   and the final status.

### Common errors

* **Invalid credentials (HTTP 401)** – The security token request is rejected
  when the access key or secret key are wrong. Double check the values in the
  plugin settings.
* **Expired security token** – Niubiz tokens are short lived. The plugin
  automatically refreshes the token and retries the request, but repeated
  failures can indicate that the system clock is out of sync or that the
  credentials were rotated.
* **Purchase rejected (`ACTION_CODE` ≠ `000`)** – The payment was denied by
  Niubiz. Check the action description returned in the response for details and
  ensure the test amount and card number are correct.
