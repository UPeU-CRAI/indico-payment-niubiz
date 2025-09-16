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

Open **Administration → Customisation → Plugins → Niubiz** and fill in the
credentials provided by Niubiz:

* **Merchant ID** (`merchant_id`) – The store identifier assigned by Niubiz.
* **Access key** (`access_key`) – Used when requesting a security token.
* **Secret key** (`secret_key`) – The shared secret associated with the access
  key.
* **Environment** (`endpoint`) – Choose *Sandbox* (`apisandbox.vnforappstest.com`)
  while testing or *Production* (`apiprod.vnforapps.com`) for live payments.

All sensitive fields use masked password widgets. The values are stored in the
plugin settings and can be overridden per event if necessary.

### Event configuration

Navigate to **Management → Payments** inside the event, enable **Niubiz** and
specify the credentials that should be used for that specific registration
form. The per-event form allows overriding the four fields mentioned above. If
an override is left empty the value from the global plugin configuration is
used instead.

### Callback configuration

The plugin exposes a webhook endpoint at:

```
/event/<event_id>/registrations/<reg_form_id>/payment/response/niubiz/notify
```

Configure this URL in the Niubiz dashboard so that asynchronous status updates
(`COMPLETED`, `EXPIRED`, `CANCELLED`, …) are propagated back to Indico. The
endpoint expects JSON payloads with `externalId`, `orderId`, `statusOrder`,
`amount` and `currency` fields and logs every notification for traceability.

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
3. Use the test card `4111111111111111` with any future expiry date and a
   three digit CVV (for example `123`).
4. Use an amount of at least **10.00 PEN** to avoid antifraud rejections in the
   sandbox environment.
5. Complete the checkout. A successful authorization returns
   `ACTION_CODE == "000"` and marks the registration as paid in Indico. Any
   other value (for example `129` or `400`) is treated as a rejection and the
   registration remains unpaid.
6. The confirmation page shows the order number (`purchaseNumber`), transaction
   ID, authorization code, masked card, amount, currency and the status of the
   operation (Éxito, Rechazado, Cancelado o Expirado).

### Status codes

| ACTION_CODE | Meaning in Indico | Resulting state |
|-------------|-------------------|-----------------|
| `000`       | Éxito              | Registration marked as paid |
| Other       | Rechazado         | Registration remains unpaid |

The cancellation flow updates the registration to *Cancelado* (withdrawn) and
the asynchronous notifications mark it as *Expirado* when Niubiz sends an
`EXPIRED` status.

### Common errors

* **Invalid credentials (HTTP 401)** – The security token request is rejected
  when the access key or secret key are wrong. Double check the values in the
  plugin settings.
* **Expired security token** – Niubiz tokens are short lived. The plugin
  automatically refreshes the token and retries the request, but repeated
  failures can indicate that the system clock is out of sync or that the
  credentials were rotated. Regenerate the token if needed.
* **Purchase rejected / Acción denegada (`ACTION_CODE` ≠ `000`)** – The payment
  was denied by Niubiz. The plugin displays the rejection message returned by
  Niubiz so the registrant can retry the payment or contact support.
