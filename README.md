# Plugin de pagos Niubiz para Indico

Este proyecto integra la pasarela de pagos de **Niubiz** dentro del flujo de inscripciones y ventas de Indico. La implementación cubre pagos con tarjeta, Yape, PagoEfectivo, códigos QR y reutilización de tokens para cobros recurrentes, incluyendo confirmaciones, reversos, reembolsos y notificaciones seguras.

## Requisitos previos

* Instancia de Indico 3.3 o superior con acceso a la sección de administración.
* Credenciales Niubiz válidas para el comercio (`merchantId`, `accessKey`, `secretKey`).
* Certificado TLS público para exponer los endpoints `/start`, `/success` y `/notify`.
* Whitelist de IPs de Niubiz habilitada en tu firewall (`200.48.119.0/24`, `200.48.62.0/24`, `200.48.63.0/24`, `200.37.132.0/24`, `200.37.133.0/24`).
* Token de autorización o clave HMAC para validar callbacks (solicitado a Niubiz durante la certificación).

## Instalación

1. Clona el repositorio dentro del entorno virtual de Indico:
   ```bash
   git clone https://github.com/UPeU-CRAI/indico-payment-niubiz.git
   pip install -e indico-payment-niubiz
   ```
2. Registra el plugin y reinicia los servicios:
   ```bash
   indico setup plugins
   indico maintenance build-cache
   sudo systemctl restart indico-celery indico-web
   ```

## Configuración en Indico

1. Activa el plugin desde **Administración → Plugins → Niubiz**.
2. Completa los campos globales:
   * Merchant ID, Access key y Secret key.
   * Entorno (`sandbox` o `producción`).
   * Logo, color del botón y MDD (JSON) si Niubiz lo requiere.
   * Métodos de pago habilitados (Tarjeta, Yape, PagoEfectivo, QR) y tokenización.
   * Opcional: token de autorización/HMAC e IPs adicionales para callbacks.
3. En cada evento puedes sobrescribir los mismos campos en **Gestión del evento → Pagos → Niubiz**.

## Flujo de pago

1. **Inicio**: el organizador habilita Niubiz como método de pago. El participante ingresa a `/start` y el plugin solicita el *security token* y la *session key* a Niubiz (registradas en el log del evento).
2. **Checkout**: para tarjeta/QR se carga `checkout.js` con el `transactionToken`. Yape, PagoEfectivo y pagos tokenizados utilizan las APIs específicas del cliente.
3. **Autorización**: el endpoint `/success` invoca `authorizeTransaction`. El resultado almacena `actionCode`, `transactionId`, `authorizationCode`, `brand`, `maskedCard`, `eci` y el detalle antifraude.
4. **Confirmación**: inmediatamente después se llama a `confirmation` (`/api.confirmation/...`). Solo si el estado es `CONFIRMED` la inscripción pasa a pagada. Cualquier otro resultado registra la transacción como rechazada, cancelada o vencida usando `TransactionStatus` de Indico.
5. **Tokenización opcional**: si el usuario marca “guardar tarjeta”, se consume `tokenizeCard`. Los tokens se guardan en `NiubizStoredToken` y pueden reutilizarse para cobros recurrentes.

### Métodos de pago soportados

| Método          | Flujo                                                                      |
|-----------------|----------------------------------------------------------------------------|
| **Tarjeta/QR**  | Checkout web con `transactionToken`, autorización y confirmación inmediatas. |
| **Yape**        | API dedicada `authorization/yape`, registra marca `YAPE` y código OTP.      |
| **PagoEfectivo**| API `authorization/pagoefectivo`, devuelve CIP y estado `PENDING`. El estado final llega por callback. |
| **Token**       | Reutiliza `tokenId` almacenado y confirma como una operación regular.       |

## Callbacks seguros

* Endpoint público: `https://<dominio>/event/<event_id>/registrations/<reg_form_id>/payment/response/niubiz/notify`.
* Se valida automáticamente:
  * Cabecera `Authorization` contra el token configurado.
  * Firma `NBZ-Signature` mediante HMAC SHA-256.
  * IP contra la whitelist (por defecto las redes oficiales de Niubiz + configuraciones adicionales).
  * Rechazo de peticiones sin HTTPS.
* Todos los callbacks se registran en el log del evento con el payload completo. Si el estado es `CONFIRMED`, se marca la inscripción como pagada; en cancelaciones o expiraciones se actualiza el estado y se crea una transacción correspondiente.

## Reembolsos y reversos

* Desde la interfaz de Indico se puede lanzar `refund`. El plugin decide automáticamente:
  * **Reverse** (`/reverse`) si la transacción aún no ha sido liquidada.
  * **Refund** (`/refund`) cuando la confirmación indica que está capturada.
* Soporta reembolsos parciales (monto inferior al total). Se registran en los logs `authorizationCode`, `traceNumber`, `transactionId`, marca y tarjeta enmascarada.

## Auditoría y trazabilidad

Cada paso crítico queda trazado mediante `event.log()` y en la transacción de Indico:

* Obtención de *security token* y creación de sesión.
* Autorización y confirmación (con códigos y estados).
* Tokenización (éxito/fracaso).
* Callbacks externos.
* Reversos y reembolsos.

Los datos almacenados incluyen `authorizationCode`, `traceNumber`, `transactionId`, `brand`, `maskedCard`, `eci`, resultados antifraude y payloads completos para auditoría.

## Tokenización y pagos recurrentes

* `NiubizStoredToken` guarda el `tokenId`, marca, tarjeta enmascarada y fecha de expiración vinculados al usuario de Indico.
* El plugin expone métodos para listar, crear y eliminar tokens reutilizables.
* En un flujo recurrente (membresías, cuotas) solo se envía el `tokenId`; el plugin llama a `authorize_transaction` y `confirm_transaction` automáticamente, reutilizando el token guardado.

## Proceso de certificación

1. Configura y prueba todos los flujos en `sandbox` con datos de prueba oficiales (tarjeta 4111..., OTP 123456, etc.).
2. Registra evidencias de logs, callbacks y reembolsos según el checklist de Niubiz.
3. Solicita a Niubiz la ventana de certificación indicando los endpoints HTTPS y la IP pública.
4. Una vez aprobada la certificación, Niubiz habilitará el comercio en producción y entregará credenciales definitivas.
5. Cambia el entorno en el plugin a `Producción`, actualiza credenciales y reinicia Indico.

## Pruebas automatizadas

El repositorio incluye una batería de pruebas que simula:

* Generación y caché del *security token*.
* Creación de sesiones, autorizaciones y confirmaciones.
* Callbacks válidos/ inválidos (token, IP, HMAC).
* Reembolsos parciales usando la API correcta (reverse vs refund).
* Flujos Yape y PagoEfectivo.

Ejecuta las pruebas con:

```bash
pytest
```

---

Con este plugin, Indico queda listo para operación en producción con Niubiz, manteniendo trazabilidad completa, seguridad en callbacks y soporte para múltiples medios de pago.
