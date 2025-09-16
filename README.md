# Plugin de pago Niubiz para Indico

## Descripción
Integración del checkout de Niubiz con el flujo de inscripciones de Indico. El plugin crea sesiones de pago, autoriza
transacciones y sincroniza automáticamente el estado de las inscripciones.

## Requisitos
- Instancia de Indico en funcionamiento.
- Credenciales de comercio Niubiz (`merchant_id`, `access_key`, `secret_key`).
- Certificado SSL/TLS habilitado para recibir notificaciones y usar checkout.js.

## Instalación
1. Clonar el repositorio en el entorno de plugins de Indico:
   ```bash
   git clone https://github.com/UPeU-CRAI/indico-payment-niubiz.git
   ```
2. Instalar el paquete y registrar los plugins:
   ```bash
   pip install -e indico-payment-niubiz
   indico setup plugins
   ```

## Configuración en Indico
1. Ir a **Administración → Plugins → Niubiz** (o a **Gestión del evento → Pagos → Niubiz** para ajustes por evento).
2. Completar los campos requeridos:
   - `merchant_id`
   - `access_key`
   - `secret_key`
   - `endpoint` (`sandbox` o `prod`)
3. Guardar los cambios y reiniciar los servicios de Indico si es necesario.

## Pruebas en sandbox
- Activar el plugin con endpoint `sandbox`.
- Datos de prueba Niubiz:
  - Tarjeta: `4111111111111111`
  - CVV: `123`
  - Fecha: cualquier fecha futura
  - Monto: `10.00 PEN`
- Resultados esperados:
  - `ACTION_CODE == "000"` → pago exitoso.
  - Cualquier otro código → pago rechazado.

## Estados de pago soportados
- Pagado
- Rechazado
- Cancelado
- Expirado

## Errores comunes
- Credenciales inválidas (`401 Unauthorized`).
- Token expirado (el plugin solicita uno nuevo automáticamente y reintenta).
- Transacción denegada por Niubiz (`ACTION_CODE` distinto de `000`).

## Requerimientos técnicos avanzados
Para escenarios que necesitan mayor control del ciclo de vida de una transacción, Niubiz expone APIs adicionales
que debes considerar según tu nivel de certificación y los riesgos asociados.

### 1. Seguridad avanzada y pagos cifrados
- **API de seguridad para pago cifrado**: antes de invocar cualquier transacción cifrada se debe consumir
  `https://apitestenv.vnforapps.com/api.security/v2/security/keys` para obtener las llaves de cifrado.
- **APIs de autorización cifrada**: existen variantes con petición cifrada, alcance cifrado o ambos, pensadas para
  comercios con certificación PCI DSS.
- **APIs antifraude y de validación cifradas**: replican la funcionalidad estándar, pero con intercambio de datos
  encriptados.

> **Importante**: el uso de estas APIs requiere contar con certificación PCI DSS y aprobación explícita del equipo de
> seguridad de Niubiz.

### 2. Prevención proactiva de fraude
- **API de Antifraude Standalone (`api.antifraud.standalone`)**:
  1. Genera un `deviceFingerprintId` (UUID) por transacción e inicializa el script `dfp_niubiz_prod_pasarela.js`
     en el checkout con `initDFP(sessionId)`.
  2. Captura la huella del dispositivo y envía los datos del cliente, la orden y la tarjeta a la API para recibir
     la decisión (`ACCEPT`, `REJECT`, `REVIEW`).
  3. Solo en caso `ACCEPT` continúa con la API de autorización.
- **API de Antifraudes (Ecommerce)**: alternativa al flujo anterior, reutiliza el mismo `deviceFingerprintId` y sirve
  para calificar la operación antes de autorizarla.

### 3. Cobros recurrentes y tokenización
- **Tokenización**: sustituye los datos sensibles de la tarjeta por un token reutilizable para próximos cobros.
- **APIs de recurrencia**:
  - Registro de afiliaciones.
  - Creación de cargos periódicos.
  - Desafiliación de clientes.
  - Listados y consultas de afiliaciones, cargos y lotes.
- **API de actualización de tarjetas**: sincroniza datos como la fecha de caducidad para evitar rechazos en cobros
  futuros (requiere PCI DSS).

### 4. Callbacks y notificaciones asíncronas
- **API Callback de Pago Link / PagoEfectivo**:
  - Expone un endpoint `POST` para recibir eventos `COMPLETED`, `PAID` o `EXPIRED`.
  - El endpoint debe declararse durante la certificación y puede validar firmas mediante el header `NBZ-Signature`.

## Implementación de pagos con QR
- **Botón Web**: si el comercio está habilitado para QR, la opción aparecerá automáticamente en el formulario del
  checkout. El backend continúa utilizando el `transactionToken` en la API de autorización estándar.
- **APIs QR para comercios**:
  - Generar QR simple para una transacción puntual.
  - Generar lotes de QR.
  - Consultar el estado de una transacción QR.
  - Anular pagos realizados mediante QR.
- **API Autorizador QR – HubProcess**: procesa la autorización final de operaciones iniciadas desde billeteras
  digitales (`https://apitestenv.vnforapps.com/api.qr.manager/v1/hubProcess`).

## Pruebas automáticas
Ejecutar la suite de pruebas después de cualquier cambio:
```bash
pytest
```
