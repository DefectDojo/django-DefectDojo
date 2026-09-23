---
title: "ServiceDesk Plus"
description: "Cómo configurar el Conector Downstream de ServiceDesk Plus para DefectDojo"
weight: 119
audience: pro
---
La integración con ManageEngine ServiceDesk Plus le permite enviar los Hallazgos y Grupos de Hallazgos de DefectDojo como solicitudes (requests) de ServiceDesk Plus, asignadas a un Group de soporte de su elección. La misma integración admite tanto la edición **cloud** (ServiceDesk Plus OnDemand) como la **on-premises**; las credenciales que proporcione determinan qué modo se usa.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con su URL de ServiceDesk Plus: `https://sdpondemand.manageengine.com` para la edición cloud (o su equivalente regional), o la dirección de su servidor para instalaciones on-premises.

Luego proporcione **uno** de los dos conjuntos de credenciales:

#### On-premises: Technician Key

- **Technician Key** debe ser una clave de API generada para un técnico en su servidor, en **Admin > General Settings > API**. Deje vacíos los campos de OAuth de Zoho.

#### Cloud: Zoho OAuth

La edición cloud se autentica mediante Zoho Accounts OAuth:

1. Abra la [Zoho API Console](https://api-console.zoho.com/) y cree un **Self Client**.
2. Anote el **Client ID** y el **Client Secret**.
3. En la pestaña "Generate Code" del Self Client, introduzca el alcance `SDPOnDemand.requests.ALL`, elija una duración y genere el código.
4. Intercambie el código por un refresh token:

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. Introduzca el **Client ID**, el **Client Secret** y el **Refresh Token** obtenido en el formulario de la instancia. Si su cuenta está alojada fuera del centro de datos de EE. UU., configure **Token URL** con el endpoint regional de Zoho Accounts correspondiente (por ejemplo, `https://accounts.zoho.eu/oauth/v2/token`).

### Mapeo del sistema de tickets

- **Group Name** debe ser el nombre del grupo de soporte de ServiceDesk Plus al que se asignarán las solicitudes, exactamente como aparece en **Admin > Users > Support Groups**.

### Detalles del mapeo de severidad

Esto se corresponde con el campo **Priority** de la solicitud de ServiceDesk Plus por nombre, usando los nombres de prioridad de su cuenta:

- **Nombre del campo de severidad**: `Priority`
- **Mapeo de Informativa**: `Low`
- **Mapeo de Baja**: `Normal`
- **Mapeo de Media**: `Medium`
- **Mapeo de Alta**: `High`
- **Mapeo de Crítica**: `High`

### Detalles del mapeo de estado

Esto se corresponde con el campo **Status** de la solicitud por nombre. Los valores predeterminados usan los estados integrados:

- **Nombre del campo de estado**: `Status`
- **Mapeo de Activo**: `Open`
- **Mapeo de Cerrado**: `Closed`
- **Mapeo de Falso positivo**: `Closed`
- **Mapeo de Riesgo aceptado**: `On Hold`

Algunos comportamientos específicos de ServiceDesk Plus que debe tener en cuenta:

- Las actualizaciones sincronizan el contenido completo de la solicitud: a diferencia de la mayoría de los sistemas de tickets, ServiceDesk Plus permite editar el asunto y la descripción después de la creación.
- Las solicitudes se cierran en lugar de eliminarse cuando se elimina un Hallazgo; las solicitudes ya Closed o Resolved se dejan sin modificar.
- Si su cuenta hace obligatorios ciertos campos al cerrar (por ejemplo, una resolución), un cierre enviado desde DefectDojo puede ser rechazado por esas reglas y aparecerá en la tabla de errores de la integración.
