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

## Configuración de credenciales Niubiz

1. Activa el plugin desde **Administración → Plugins → Niubiz**.
2. Introduce las credenciales entregadas por Niubiz:
   * **Merchant ID** (identificador del comercio).
   * **Access key** y **Secret key** para generar el *security token*.
   * **Entorno** (`sandbox` o `producción`).
3. Ajusta las opciones globales del conector según tu contrato:
   * Logo, color del botón y parámetros MDD (en formato JSON) para los motores antifraude de Niubiz.
   * Métodos de pago habilitados (Tarjeta, Yape, PagoEfectivo, QR) y tokenización.
   * Token de autorización/HMAC e IPs adicionales para validar callbacks.
4. Guarda la configuración y verifica el log del sistema para confirmar que se pudo generar el *security token*.

### Configuración por evento

Cada formulario de registro puede sobrescribir las credenciales y parámetros anteriores desde **Gestión del evento → Pagos → Niubiz**. Esto permite utilizar comercios distintos por evento, habilitar o deshabilitar métodos específicos y definir MDD particulares.

## Flujos soportados

El plugin implementa los principales flujos documentados por Niubiz y normaliza las respuestas dentro de Indico:

* **Autorización** – `POST /api.authorization/v3/authorization/ecommerce/{merchantId}` autoriza pagos con tarjeta o QR y retorna `transactionId`, `actionCode`, tarjeta enmascarada y datos antifraude.
* **Confirmación** – `POST /api.confirmation/v1/confirmation/ecommerce/{merchantId}` envía el `transactionId` en el cuerpo para capturar manualmente operaciones autorizadas.
* **Reversa** – `POST /api.authorization/v3/reverse/ecommerce/{merchantId}` invierte transacciones aún no liquidadas enviando `transactionId`, monto y moneda.
* **Refund** – `POST /api.refund/v1/refund/{merchant_id}/{transaction_id}` procesa devoluciones parciales o totales de operaciones ya capturadas.
* **Yape** – `POST /api.authorization/v3/authorization/yape/{merchantId}` valida el OTP del usuario y retorna el estado de la transacción.
* **PagoEfectivo** – `POST /api.authorization/v3/authorization/pagoefectivo/{merchantId}` genera el CIP y recibe el estado final mediante webhook.

Cada invocación queda registrada en el log del evento con la respuesta normalizada, lo que facilita auditorías y conciliaciones.

## Flujo de pago

1. **Inicio**: el organizador habilita Niubiz como método de pago. El participante ingresa a `/start` y el plugin solicita el *security token* y la *session key* a Niubiz (registradas en el log del evento).
2. **Checkout**: para tarjeta/QR se carga `checkout.js` con el `transactionToken`. Yape, PagoEfectivo y pagos tokenizados utilizan las APIs específicas del cliente.
3. **Autorización**: el endpoint `/success` invoca `authorizeTransaction`. El resultado almacena `actionCode`, `transactionId`, `authorizationCode`, `brand`, `maskedCard`, `eci` y el detalle antifraude.
4. **Confirmación**: inmediatamente después se llama a `confirmation` (`POST /api.confirmation/v1/confirmation/ecommerce/{merchantId}`) enviando el `transactionId` en el cuerpo. Solo si Niubiz responde `CONFIRMED` la inscripción pasa a pagada; cualquier otro resultado se registra como rechazado, cancelado o vencido usando `TransactionStatus` de Indico.
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
* Todos los callbacks se registran en el log del evento con el payload completo. Si el estado recibido es `Authorized` o `Confirmed`, la inscripción se marca como pagada; ante `Voided`, `Cancelled` o `Refunded` el pago se revierte y se crea la transacción correspondiente.

## Integración con Indico

Cuando Niubiz envía un callback válido, el plugin sincroniza automáticamente el estado de pago del registro de Indico. Las respuestas con estado `Authorized` o `Confirmed` ejecutan `registration.set_paid(True)` y confirman la transacción en la base de datos. Si posteriormente se recibe `Voided`, `Cancelled` o `Refunded`, el mismo registro se marca como no pagado (`registration.set_paid(False)`), dejando trazabilidad en el log del evento y en el historial de transacciones. Este “toggle-payment” evita intervenciones manuales y mantiene la información visible para los organizadores y participantes.

## Reembolsos y reversos

* Desde la interfaz de Indico se puede lanzar `refund`. El plugin decide automáticamente:
  * **Reverse** (`POST /api.authorization/v3/reverse/ecommerce/{merchantId}`) si la transacción aún no ha sido liquidada.
  * **Refund** (`POST /api.refund/v1/refund/{merchant_id}/{transaction_id}`) cuando la confirmación indica que está capturada.
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

## Limitaciones conocidas

* La API pública solo permite consultar transacciones por `transactionId`; no existe un endpoint documentado para buscar por `purchaseNumber`.
* Los tokens de sesión y de seguridad tienen caducidad corta, por lo que el plugin fuerza la renovación automática al detectar respuestas 401 de Niubiz.

## Proceso de certificación

1. Configura y prueba todos los flujos en `sandbox` con datos de prueba oficiales (tarjeta 4111..., OTP 123456, etc.).
2. Registra evidencias de logs, callbacks y reembolsos según el checklist de Niubiz.
3. Solicita a Niubiz la ventana de certificación indicando los endpoints HTTPS y la IP pública.
4. Una vez aprobada la certificación, Niubiz habilitará el comercio en producción y entregará credenciales definitivas.
5. Cambia el entorno en el plugin a `Producción`, actualiza credenciales y reinicia Indico.

## Pruebas

El proyecto cuenta con pruebas unitarias que validan los flujos principales del cliente y los callbacks de Niubiz: autorización, confirmación manual, reversas, refunds, Yape, PagoEfectivo y la actualización automática del estado de pago en Indico. Para ejecutarlas utiliza:

```bash
pytest
```

Las pruebas pueden ejecutarse en cualquier entorno virtual de Indico y emplean `monkeypatch` para simular las respuestas de la API de Niubiz.

---

Con este plugin, Indico queda listo para operación en producción con Niubiz, manteniendo trazabilidad completa, seguridad en callbacks y soporte para múltiples medios de pago.
