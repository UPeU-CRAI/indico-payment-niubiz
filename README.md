# Plugin de pagos Niubiz para Indico

## 📖 Descripción
Este plugin permite integrar la pasarela de pagos Niubiz con Indico para procesar pagos en línea con tarjetas de débito y crédito. Una vez instalado, los formularios de inscripción pueden mostrar el botón **Pagar con Niubiz** y registrar automáticamente el estado de cada transacción.

## ⚙️ Requisitos
- Una instancia de Indico instalada y en funcionamiento.
- Credenciales de comercio Niubiz (sandbox y/o producción): `merchant_id`, `access_key` y `secret_key`.
- Certificado SSL/TLS habilitado en el servidor que ejecuta Indico para proteger las notificaciones y el checkout.

## 🛠 Instalación
1. Ubícate en la carpeta `indico-plugins/` dentro del entorno donde corre Indico.
2. Clona el repositorio del plugin:
   ```bash
   git clone https://github.com/UPeU-CRAI/indico-payment-niubiz.git
   ```
3. Instala el paquete en el entorno virtual de Indico:
   ```bash
   pip install -e indico-payment-niubiz
   indico setup plugins
   ```
4. Reinicia los procesos de Indico (web workers, Celery, etc.) para que la nueva extensión quede registrada.

## 🔑 Configuración en Indico
1. Ingresa como administrador a **Administración → Plugins → Niubiz**.
2. Completa los campos requeridos:
   - `merchant_id`
   - `access_key`
   - `secret_key`
   - `endpoint` (elige `sandbox` o `prod`)
3. Guarda los cambios. De ser necesario, estos valores pueden sobreescribirse por evento desde **Gestión del evento → Pagos → Niubiz**.

## 🧪 Pruebas en Sandbox
1. Activa el plugin en modo sandbox.
2. Crea un formulario de inscripción con un monto mínimo de 10.00 PEN.
3. Utiliza los datos de prueba proporcionados por Niubiz:
   - Tarjeta: `4111111111111111`
   - Fecha de expiración: cualquier fecha futura
   - CVV: `123`
4. Realiza el pago desde el checkout de Niubiz. Un pago exitoso devuelve `ACTION_CODE == "000"` y la inscripción se marca como pagada.
5. Consulta el historial en Indico para verificar que se registró la transacción y el estado correspondiente.

Errores comunes:
- **401 Unauthorized** → credenciales inválidas.
- **Token expirado** → el plugin solicita un nuevo token automáticamente y reintenta la operación.
- **ACTION_CODE != "000"** → transacción rechazada por Niubiz.

## 📌 Estados de pago
- **Pagado** → cuando `ACTION_CODE == "000"` o el callback `/notify` informa `statusOrder == "COMPLETED"`.
- **Rechazado** → cuando Niubiz devuelve un `ACTION_CODE` distinto de `000`.
- **Cancelado** → cuando el usuario cancela el proceso de pago desde el checkout.
- **Expirado** → cuando Niubiz envía un callback con `statusOrder == "EXPIRED"`.

## 📡 Notificaciones de Niubiz
Configura en el portal de Niubiz la URL del webhook:
```
/event/<event_id>/registrations/<reg_form_id>/payment/response/niubiz/notify
```
El endpoint recibe JSON con `externalId`, `orderId`, `statusOrder`, `amount` y `currency`. Cada notificación se registra en los logs y actualiza el estado de la inscripción en Indico para mantener la trazabilidad.

## ✅ Verificación
Ejecuta la suite de pruebas automatizadas después de realizar cambios:
```bash
pytest
```
Las pruebas incluyen mocks de las llamadas a la API de Niubiz y validan el marcado de inscripciones como pagadas, rechazadas o expiradas.
