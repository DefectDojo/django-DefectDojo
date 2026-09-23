---
title: "ServiceNow"
description: "Cómo configurar el Conector Downstream de ServiceNow para DefectDojo"
weight: 120
audience: pro
---
La integración con ServiceNow le permite enviar los Hallazgos de DefectDojo como Incidentes de ServiceNow.

### Configuración de la instancia

DefectDojo se autentica ante ServiceNow mediante OAuth 2.0. La forma de crear las credenciales de OAuth depende de la versión de ServiceNow: las versiones más recientes (Zurich y posteriores) usan una concesión de Client Credentials, mientras que las versiones anteriores usan un token de actualización (refresh token).

#### ServiceNow Zurich y posteriores (client credentials)

Las versiones recientes de ServiceNow han descontinuado la opción clásica "Create an OAuth API endpoint for external clients" en favor de la **New Inbound Integration Experience**, que emite una concesión OAuth de **Client Credentials** vinculada a una cuenta de servicio:

1. En la barra de navegación izquierda, busque "Application Registry" y selecciónela.
2. Haga clic en **New** y luego elija **New Inbound Integration Experience**.
3. Seleccione **New Integration → OAuth - Client credentials grant**.
4. Configure **OAuth Application User** con la cuenta de servicio que creará los Incidentes. Los roles de esa cuenta determinan lo que DefectDojo puede escribir.
5. Guarde el registro. ServiceNow genera automáticamente el **Client ID** y el **Client Secret** (deje esos campos en blanco al crear el registro).

Luego, en DefectDojo:

- **Instance Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con la URL de su servidor ServiceNow, por ejemplo `https://your-organization.service-now.com/`.
- **Client ID** debe ser el Client ID del registro de OAuth.
- **Client Secret** debe ser el Client Secret del registro de OAuth.

Deje vacíos los campos Refresh Token, Username y Password: DefectDojo solicita un token nuevo mediante client credentials en cada sincronización.

#### Versiones anteriores de ServiceNow (refresh token)

En las versiones que aún ofrecen el registro clásico, obtenga un Refresh Token asociado al Usuario o a la cuenta de servicio que enviará los Incidentes a ServiceNow:

1. En la barra de navegación izquierda, busque "Application Registry" y selecciónela.
2. Haga clic en "New".
3. Elija "Create an OAuth API endpoint for external clients".
4. Complete los campos obligatorios:
    * Name: proporcione un nombre significativo para su aplicación (por ejemplo, Vulnerability Integration Client).
    * (Opcional) Ajuste la vigencia del token:
    * Access Token Lifespan: el valor predeterminado es 1800 segundos (30 minutos).
    * Refresh Token Lifespan: el valor predeterminado es 8640000 segundos (aproximadamente 100 días).
5. Haga clic en Submit para crear el registro de la aplicación.
6. Después de enviarlo, seleccione la aplicación en la lista y anote los campos **Client ID y Client Secret**.

Luego deberá usar este registro para obtener un Refresh Token, que solo se puede obtener a través de la API de ServiceNow. Abra una ventana de terminal y pegue lo siguiente (sustituyendo las variables entre `{{}}` por la información real de su usuario)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

Si sus credenciales de ServiceNow son correctas y permiten acceso de nivel administrador a ServiceNow, debería recibir una respuesta con un RefreshToken. Necesitará ese token para completar la integración con DefectDojo.

- **Instance Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con la URL de su servidor ServiceNow, por ejemplo `https://your-organization.service-now.com/`.
- **Refresh Token** es donde debe introducirse el Refresh Token.
- **Client ID** debe ser el Client ID configurado en el OAuth App Registration.
- **Client Secret** debe ser el Client Secret configurado en el OAuth App Registration.

### Detalles del mapeo de severidad

Esto se corresponde con el campo Impact de ServiceNow.
- **Mapeo de Informativa**: `1`
- **Mapeo de Baja**: `1`
- **Mapeo de Media**: `2`
- **Mapeo de Alta**: `3`
- **Mapeo de Crítica**: `3`

### Detalles del mapeo de estado

- **Nombre del campo de estado**: `State`
- **Mapeo de Activo**: `New`
- **Mapeo de Cerrado**: `Closed`
- **Mapeo de Falso positivo**: `Resolved`
- **Mapeo de Riesgo aceptado**: `Resolved`

Cada mapeo acepta una etiqueta de estado estándar (`New`, `In Progress`, `On Hold`, `Resolved`, `Closed`, `Cancelled`) o un valor de estado numérico. En instancias con estados de Incidente personalizados, o cuando se apunta a una tabla distinta de `incident`, use el **valor de estado** numérico de la lista de opciones de su instancia; un valor numérico fuera del conjunto estándar se envía a ServiceNow exactamente como se configuró. El valor predeterminado integrado del código de resolución solo acompaña a los estados estándar de resuelto/cerrado, así que combine los valores de estado personalizados con los mapeos de campos de cierre y resolución que se describen a continuación.

### Campos de cierre y resolución

Algunas instancias de ServiceNow aplican una Data Policy que hace obligatorios campos como el **Resolution code** (`close_code`) cada vez que un Incidente pasa a un estado resuelto o cerrado. Si DefectDojo cierra un Incidente sin ellos, ServiceNow rechaza la escritura con un HTTP 403 *"Data Policy Exception"* y el motivo queda registrado en la vista de Errores de la integración.

Asocie los campos requeridos al cambio de estado mediante **Custom Field Mappings**, configurando **Apply On** con la disposición que debe incluirlos:

- **Transition to Closed**: se envía cuando un Hallazgo se mitiga o se cierra.
- **Transition to False Positive**: se envía cuando un Hallazgo se marca como falso positivo.
- **Transition to Risk Accepted**: se envía cuando un Hallazgo tiene el riesgo aceptado.

Por ejemplo, para satisfacer un Resolution code obligatorio:

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

Notas:

- Field Name es el nombre de columna de ServiceNow: `close_code`, `close_notes`, o un campo personalizado `u_...`.
- Los mapeos de transición se disparan cuando el estado del registro realmente cambia: un Hallazgo que ya está cerrado cuando se envía por primera vez, una actualización que cierra o reabre el registro, y el cierre forzado cuando se elimina un enlace de ticket. No se vuelven a enviar en actualizaciones rutinarias de un registro sin cambios, por lo que los campos de bitácora como `work_notes` reciben una entrada por cada transición.
- Los campos de referencia como `assignment_group` y `assigned_to` esperan un **sys_id**, no un nombre para mostrar.
- Los valores que se interpretan como JSON se envían tipados: `true`, `42`, `[...]`, `{...}`, y `null`, que borra el campo. Para enviar ese texto como una cadena literal, enciérrelo entre comillas dobles (por ejemplo, `"null"`).
- `short_description`, `description`, `state`, `impact`, `urgency` y `priority` pertenecen a la plantilla de descripción y a los mapeos de severidad/estado, por lo que no se pueden configurar mediante un mapeo de campo personalizado.
- En tablas distintas de `incident`, los valores de estado que coinciden con el conjunto estándar de Incidente (`1`, `2`, `3`, `6`, `7`, `8`) se siguen interpretando con la semántica de Incidente, incluido el valor predeterminado automático de Resolution code en `6`/`7`/`8`. Prefiera valores de estado fuera de ese rango en tablas personalizadas, o proporcione explícitamente los campos de cierre como se indicó anteriormente.
