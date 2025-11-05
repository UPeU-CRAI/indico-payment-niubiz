# Métodos de pago soportados por el plugin Niubiz

Este documento resume los requisitos de la API de Niubiz para cada canal que el
plugin debe soportar. Sirve como guía para completar las integraciones
pendientes y para validar los parámetros obligatorios del flujo PushPayment
NO-PCI.

## Tarjeta (PushPayment NO-PCI)

* **Flujo actual**: Implementado.
* **Endpoints**: `token/session`, `token/card`, `authorization/ecommerce`.
* **Datos obligatorios**:
  * `deviceFingerprintId` capturado en frontend.
  * Merchant Defined Data (MDD4, MDD32, MDD75, MDD77).
  * `antifraud.billTo` con nombre, apellido y correo cuando estén disponibles.
* **Observaciones**:
  * El `transactionToken` debe verificarse antes de autorizar.
  * El antifraud debe incluir siempre `clientIp` cuando esté disponible.

## Yape (pendiente)

* **Flujo esperado**: API `authorization` específica para billeteras Niubiz.
* **Requisitos** (según guías 2025):
  * Generar `sessionKey` con `channel = "yape"`.
  * Enviar identificador del alias Yape (`payerPhone`) en `additionalFields`.
  * Confirmar la operación vía webhook antes de liberar la inscripción.
* **Pendiente**: Implementar `process_yape_transaction` validando los mensajes
de estado `PENDING`/`APPROVED` y el manejo de QR dinámico provisto por Niubiz.

## PagoEfectivo (pendiente)

* **Flujo esperado**: Creación de CIP mediante endpoint `payment/v2/cip`.
* **Requisitos**:
  * Requiere `paymentLimitDate` y `paymentLimitTime`.
  * Debe almacenarse el CIP retornado para conciliación manual.
  * El antifraud comparte la misma estructura con tarjeta, pero el `channel`
debe enviarse como `efectivo`.
* **Pendiente**: Diseñar la pantalla de instrucciones y el callback que marca la
inscripción como pagada al confirmarse el CIP.

## QR Niubiz (pendiente)

* **Flujo esperado**: Generación de orden QR (`/qr/v1/order`) y polling de
estado.
* **Requisitos**:
  * La creación del QR exige monto exacto y número de orden (`purchaseNumber`).
  * Debe mostrarse la imagen QR al usuario y reintentar la consulta hasta
recibir `status = COMPLETED` o expirar.
* **Pendiente**: Integrar `process_qr_transaction` y manejar expiraciones con
mensajes amigables.

> Referencia: Manual de Integración Niubiz NO-PCI 2025 y anexos de canales
> alternativos. Actualizar este archivo cuando Niubiz publique cambios o cuando
> la integración pase a producción.
