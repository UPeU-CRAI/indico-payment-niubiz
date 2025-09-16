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

## Pruebas automáticas
Ejecutar la suite de pruebas después de cualquier cambio:
```bash
pytest
```
