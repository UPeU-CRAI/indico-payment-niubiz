# Plugin de pagos Niubiz para Indico

Extiende el módulo de pagos de Indico con la pasarela peruana **Niubiz**. El
plugin cubre cobros con tarjeta, Yape, PagoEfectivo, códigos QR y reutilización
de tokens, además de manejar automáticamente los callbacks de estado y los
reembolsos iniciados desde Indico.

La versión inicial publicada de este repositorio es la **0.0.1**. El detalle de
cambios se encuentra en [`CHANGELOG.md`](CHANGELOG.md).


## Características principales

* Creación de órdenes y carga del `checkout.js` oficial de Niubiz.
* Confirmación automática de pagos autorizados y soporte opcional para
  tokenización de tarjetas.
* Callbacks seguros con validación de token, HMAC y lista blanca de IPs.
* Registro detallado en los logs del evento y en las transacciones de Indico.
* Gestión de reembolsos (reverse/refund) con sincronización del estado de la
  inscripción.


## Requisitos

* Indico **3.3** o superior con acceso a la sección de administración.
* Credenciales válidas de Niubiz (`merchantId`, `accessKey`, `secretKey`).
* Certificado TLS público para exponer los endpoints de inicio, retorno y
  notificación.
* Whitelist de IPs que permita el tráfico desde las redes publicadas por
  Niubiz (`200.48.119.0/24`, `200.48.62.0/24`, `200.48.63.0/24`,
  `200.37.132.0/24`, `200.37.133.0/24`).


## Instalación rápida

```bash
git clone https://github.com/UPeU-CRAI/indico-payment-niubiz.git
pip install -e indico-payment-niubiz

indico setup plugins
indico maintenance build-cache
sudo systemctl restart indico-celery indico-web
```


## Configuración

### Configuración global

Desde **Administración → Plugins → Niubiz**:

* `Merchant ID`, `Access key` y `Secret key` entregados por Niubiz.
* Entorno (`sandbox` o `producción`).
* Apariencia del checkout: logo y color del botón.
* Merchant Defined Data (MDD) opcional para reglas antifraude.
* Métodos de pago habilitados (Tarjeta, Yape, PagoEfectivo, QR) y tokenización.
* Token de autorización para callbacks, secreto HMAC y whitelist de IPs
  adicionales.

### Configuración por evento

Cada formulario de registro puede sobrescribir las credenciales y parámetros
anteriores desde **Gestión del evento → Pagos → Niubiz**. Es útil cuando se
trabaja con múltiples comercios o cuando se desean métodos de pago distintos por
evento.


## Flujo resumido

1. **Inicio**: el participante selecciona Niubiz. El plugin crea la sesión en la
   API de Niubiz y renderiza el checkout con la información del registro.
2. **Checkout**: se carga `checkout.js` con el `transactionToken`. En el caso de
   Yape, PagoEfectivo o tokens reutilizados, se usan los endpoints específicos de
   la API.
3. **Autorización y confirmación**: el retorno de Niubiz se procesa con
   `authorizeTransaction` y `confirmation`. La inscripción solo se marca como
   pagada cuando Niubiz responde `CAPTURED`/`CONFIRMED`.
4. **Notificaciones**: el endpoint `/notify` recibe callbacks firmados por Niubiz
   y sincroniza el estado de la inscripción (pagado, pendiente, cancelado o
   reembolsado). Cada mensaje queda registrado en el log del evento.
5. **Reembolsos**: desde Indico se puede iniciar un reembolso. El plugin decide
   automáticamente si corresponde un `reverse` (transacción no liquidada) o un
   `refund` y actualiza el estado de la inscripción.


## Seguridad de callbacks

El endpoint público `.../payment/response/niubiz/notify` aplica las siguientes
validaciones antes de procesar el payload:

* **Token de autorización** (`Authorization: Bearer ...`).
* **Firma HMAC** (`NBZ-Signature`) usando el secreto configurado.
* **Lista blanca de IPs**, combinando las redes oficiales de Niubiz con las
  adicionales definidas en el plugin.
* Validación de monto y moneda contra la inscripción original.

Si alguno de estos chequeos falla se devuelve `403` o `400`, evitando marcar
pagos erróneos.


## Reembolsos y tokenización

* Los tokens de tarjeta se almacenan en `NiubizStoredToken` y pueden reutilizarse
  para cobros recurrentes.
* `handle_refund` registra tanto la reversa como el reembolso y marca la
  inscripción como no pagada cuando procede.
* Toda la información relevante (códigos de autorización, `transactionId`,
  `actionCode`, payloads) queda guardada para auditoría.


## Desarrollo y pruebas

Este repositorio incluye pruebas unitarias para el cliente HTTP, el mapeo de
estados y el endpoint de callbacks. Para ejecutarlas:

```bash
pytest
```

Se recomienda habilitar un entorno virtual con Indico y ejecutar las pruebas
antes de desplegar cambios en producción.


## Historial de cambios

Consulta [`CHANGELOG.md`](CHANGELOG.md) para revisar las versiones publicadas y
las novedades de cada una.

