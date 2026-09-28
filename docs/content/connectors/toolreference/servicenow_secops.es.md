---
title: "ServiceNow SecOps"
description: "Cómo configurar el Conector Downstream de ServiceNow SecOps para DefectDojo"
weight: 122
audience: pro
---
La integración de ServiceNow SecOps (también conocida como **ServiceNow SecOps / Vulnerability Response**) envía los Hallazgos y Grupos de Hallazgos de DefectDojo a una tabla de seguridad de ServiceNow —un **Security Incident** (`sn_si_incident`) o un **Vulnerable Item** (`sn_vul_vulnerable_item`)— y la mantiene sincronizada a medida que el Hallazgo cambia (creación, actualización y resolución/cierre). Es la contraparte de operaciones de seguridad de la integración de ServiceNow como sistema de tickets descrita arriba; use ServiceNow SecOps cuando ejecute las aplicaciones Security Incident Response (SIR) o Vulnerability Response (VR).

### Configuración de la instancia

- **Instance Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con la URL de su servidor ServiceNow, por ejemplo `https://your-organization.service-now.com/`.

ServiceNow SecOps admite tres métodos de autenticación; proporcione **uno**:

- **OAuth 2.0**: introduzca un **Client ID**, un **Client Secret** y un **Refresh Token**. Obténgalos exactamente como se describe en la sección [ServiceNow](/connectors/toolreference/servicenow/) anterior (cree un endpoint de API OAuth en el Application Registry y luego intercambie sus credenciales en `/oauth_token.do` por un refresh token). Alternativamente, proporcione el **Client ID** y el **Client Secret** junto con un **Username** y un **Password** para usar la concesión de contraseña de OAuth en lugar de un refresh token.
- **API Key**: introduzca una **API Key**, que se envía como el encabezado `x-sn-apikey`. La clave no autentica nada hasta que se le asocie un Inbound Authentication Profile y una REST API Access Policy en la instancia.
- **HTTP Basic**: introduzca el **Username** y el **Password** de la cuenta de servicio.

La cuenta de servicio (o el cliente OAuth) necesita acceso de escritura a la tabla de destino.

### Mapeo del sistema de tickets

- **Target Table** selecciona la tabla de ServiceNow en la que se escriben los registros: **Security Incident** (`sn_si_incident`, el valor predeterminado) o **Vulnerable Item** (`sn_vul_vulnerable_item`).

### Detalles del mapeo de severidad

Para un Security Incident, esto se corresponde con el campo **Impact**; ServiceNow deriva la Priority del incidente a partir de Impact y Urgency, por lo que Urgency refleja el Impact mapeado a menos que lo mapee usted mismo. Para un Vulnerable Item, mapee la severidad al campo de riesgo que use su instancia. Los valores predeterminados a continuación coinciden con la escala estándar de Impact de SIR (`1` Alta, `2` Media, `3` Baja) y son editables.

- **Nombre del campo de severidad**: `impact`
- **Mapeo de Informativa**: `3`
- **Mapeo de Baja**: `3`
- **Mapeo de Media**: `2`
- **Mapeo de Alta**: `1`
- **Mapeo de Crítica**: `1`

### Detalles del mapeo de estado

Esto se corresponde con el campo **State** del registro. Los valores de State son códigos numéricos que difieren entre las tablas Security Incident y Vulnerable Item y pueden personalizarse por instancia, así que revíselos contra su propia configuración. Los valores predeterminados a continuación usan los códigos de estado estándar de SIR (`16` Analysis, `3` Closed).

- **Nombre del campo de estado**: `state`
- **Mapeo de Activo**: `16`
- **Mapeo de Cerrado**: `3`
- **Mapeo de Falso positivo**: `3`
- **Mapeo de Riesgo aceptado**: `3`

Cuando se cierra un registro, DefectDojo también configura el **Close Code** y las **Close Notes** de ServiceNow (`Resolved` para los Hallazgos cerrados, `False positive` y `Risk accepted` para los estados correspondientes).

### Comportamientos específicos de ServiceNow SecOps

- **Deduplicación**: cada registro se etiqueta con el identificador de DefectDojo del Hallazgo o del Grupo de Hallazgos en su `correlation_id`. Antes de crear un registro, DefectDojo busca uno existente por `correlation_id`; si hay coincidencia, se adopta y se actualiza en lugar de duplicarse, de modo que las resincronizaciones son idempotentes.
- Las **actualizaciones** se publican en la bitácora **Work notes** del registro (interna), nunca en los Comments visibles para el cliente.
- **Resolver al eliminar**: eliminar un Hallazgo en DefectDojo resuelve/cierra el registro de ServiceNow (State + Close Code) en lugar de eliminarlo; los registros nunca se eliminan de forma permanente.
- **Campos de referencia**: los valores opcionales `cmdb_ci`, `assignment_group` y `assigned_to` pueden proporcionarse como nombres para mostrar; DefectDojo resuelve cada uno a su `sys_id`. Un nombre que no se resuelve se descarta con una advertencia en lugar de hacer fallar el envío.
