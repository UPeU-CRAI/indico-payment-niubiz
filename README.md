# Indico Niubiz Plugin

La integración oficial de Niubiz para Indico permite cobrar inscripciones usando
`checkout.js`, Yape, PagoEfectivo y tokenización de tarjetas. Incluye manejo de
notificaciones, reembolsos y controles de seguridad basados en HMAC e IP
whitelist.

## Instalación

```bash
git clone https://github.com/UPeU-CRAI/indico-payment-niubiz.git
pip install -e indico-payment-niubiz[dev]

indico setup plugins
indico maintenance build-cache
sudo systemctl restart indico-web indico-celery
```

## Configuración inicial

1. **Administración → Plugins → Niubiz**
   - Carga `Merchant ID`, `Access key` y `Secret key`.
   - Define el **Entorno** (sandbox o producción) y la apariencia del checkout
     (logo, color del botón, MDD opcional).
   - Activa los métodos disponibles: Tarjeta, Yape, PagoEfectivo, QR y
     tokenización.
   - Configura seguridad para callbacks: token Bearer, secreto HMAC y rangos de
     IP adicionales.
2. **Evento → Pagos → Niubiz**
   - Permite sobrescribir credenciales, método por defecto y parámetros de
     seguridad por evento.
   - Cada formulario de registro puede habilitar o deshabilitar métodos
     específicos sin afectar a los demás eventos.

## Flujo NO-PCI (checkout.js)

1. **Inicio de pago**: el participante elige Niubiz; el plugin crea una sesión
   (`sessionKey`) y renderiza `checkout.js` con el resumen de la orden.
2. **Captura de tarjeta**: todo el ingreso de datos ocurre en el formulario
   embebido de Niubiz, Indico nunca procesa PANs.
3. **Respuesta inmediata**: el iframe devuelve un estado provisional (éxito,
   cancelado o error) que se refleja en `templates/niubiz/checkout.html`.
4. **Webhook NO-PCI**: Niubiz notifica el resultado definitivo mediante callbacks
   firmados (`NBZ-Signature`). Se valida token, HMAC e IP.
5. **Actualización de inscripción**: el estado del registro se sincroniza y se
   muestra un mensaje amigable en `templates/niubiz/result.html`.

## Tabla de estados

| Estado Niubiz / actionCode | Estado Indico             | Nota                                      |
|----------------------------|---------------------------|-------------------------------------------|
| `AUTHORIZED` + `000`       | `successful`              | Pago confirmado automáticamente           |
| `REFUNDED`, `VOIDED`       | `cancelled`               | Marca la inscripción como no pagada       |
| `PENDING`, `REVIEW`, CIP   | `pending`                 | Espera confirmación manual/webhook        |
| `REJECTED`, `NOT AUTHORIZED`, códigos `101`, `116`, `191` | `failed` | Se registra rechazo y no cambia la inscripción |
| actionCode `9997`, `9905`  | `cancelled`               | Cancelado por expiración o timeout        |
| Otros valores              | `pending` (seguro)        | Se requiere revisión manual               |

## Sandbox vs. Producción

| Característica              | Sandbox                                         | Producción                                      |
|-----------------------------|-------------------------------------------------|-------------------------------------------------|
| URL base API                | `https://apitestenv.vnforapps.com`             | `https://apiprod.vnforapps.com`                 |
| checkout.js                 | `https://static-content-qas.vnforapps.com/...` | `https://static-content.vnforapps.com/v2/...`   |
| Credenciales                | Provistas por Niubiz para pruebas               | Requieren alta formal con contratos vigentes    |
| IPs de callback             | Redes publicadas por Niubiz (usar whitelist)   | Mismas redes, confirmar con soporte             |
| Tokens y tarjetas           | Datos de prueba, sin cargo real                 | Datos reales; habilita tokenización segura      |

## Seguridad de callbacks

- `Authorization: Bearer <token>` configurable.
- Firma HMAC `NBZ-Signature` validada con `security.validate_nbz_signature`.
- Lista blanca de IPs usando redes oficiales + configurables.
- Datos normalizados con `utils.extract_callback_details` antes de registrar
  transacciones.

## Reembolsos

- `NiubizClient.refund_transaction` utiliza dataclasses (`RefundResponse`) para
  unificar el resultado de refund/void.
- `NiubizClient.reverse_payment` intenta `refund` y cae a `void` cuando la
  operación aún no ha sido capturada.
- El plugin registra los resultados en logs del evento y actualiza la inscripción.

## Desarrollo y pruebas

```bash
pip install -e .[dev]
ruff check .
black --check .
isort --check-only .
mypy indico_payment_niubiz
pytest -q
```

Consulta [`CHANGELOG.md`](CHANGELOG.md) para conocer la evolución del proyecto.
