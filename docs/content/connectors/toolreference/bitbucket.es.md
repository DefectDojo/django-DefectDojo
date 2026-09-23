---
title: "Bitbucket"
description: "Configuración de los Conectores Upstream y Downstream de Bitbucket"
weight: 25
audience: pro
---
## Conector Upstream

El conector de Bitbucket es un **Conector de activos**: enumera los repositorios de los workspaces de Bitbucket Cloud que usted indique y crea un Activo de DefectDojo para cada repositorio, agrupados en Organizaciones según el proyecto de Bitbucket. No se importa ningún hallazgo.

#### Prerrequisitos

Bitbucket Cloud requiere un token de API de Atlassian **con ámbitos (scoped)** — los tokens de API de Atlassian clásicos (sin ámbitos) son rechazados por Bitbucket con un error "API Token provided has no Bitbucket scopes".

1. Vaya a [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) y elija **Create API token with scopes**.
2. Seleccione la aplicación **Bitbucket** y, a continuación, otorgue los ámbitos de lectura: `read:account:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket` y `read:project:bitbucket`.

Solo se admite Bitbucket Cloud (bitbucket.org). Bitbucket Server llegó a su fin de vida en 2024, y Bitbucket Data Center no es compatible.

#### Asignaciones del conector

1. Ingrese `https://bitbucket.org` en el campo **Location**.
2. Ingrese el correo de la cuenta de Atlassian a la que pertenece el token en el campo **Email**.
3. Ingrese el token de API con ámbitos en el campo **Secret**.
4. Ingrese uno o más slugs de workspace (separados por comas) en el campo **Workspace Slugs**. Este campo es obligatorio: los tokens de API con ámbitos de Bitbucket no pueden listar workspaces automáticamente, por lo que hay que indicarle a DefectDojo qué workspaces leer.

Cada repositorio se convierte en un Registro con el nombre del repositorio, agrupado por su **proyecto** de Bitbucket.

## Conector Downstream

La integración de Bitbucket le permite enviar incidencias al [rastreador de incidencias](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/) de un repositorio de Bitbucket Cloud.

El rastreador de incidencias es opcional en Bitbucket y debe habilitarse en el repositorio antes de que DefectDojo pueda crear incidencias en él. Para habilitarlo, abra el repositorio en Bitbucket y seleccione **Repository settings**, luego habilite el rastreador de incidencias en **Features**.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en `https://bitbucket.org`.
- **Email** debe ser la dirección de correo electrónico de la cuenta de Atlassian a la que pertenece el token de la API.
- **API Token** debe establecerse en un token de API de Atlassian con alcance limitado (scoped).

Atlassian ha declarado obsoletas las contraseñas de aplicación de Bitbucket y no funcionarán con esta integración. Para crear un token de API:

1. Abra la [configuración de la cuenta de Atlassian](https://id.atlassian.com/manage-profile/security/api-tokens) y elija **Security**, luego **Create and manage API tokens**.
2. Elija **Create API token with scopes**, asigne un nombre al token y establezca una fecha de vencimiento.
3. Seleccione **Bitbucket** como la aplicación.
4. Otorgue al token permiso para leer repositorios y para leer y escribir incidencias.

### Mapeo del Issue Tracker

- **Workspace** debe ser el slug del espacio de trabajo que contiene el repositorio, tal como aparece en las URL de bitbucket.org.
- **Repository Slug** debe ser el slug del repositorio en el que desea crear incidencias.

### Detalles del mapeo de severidad

Esto se mapea al campo Priority de la incidencia de Bitbucket. Los atributos del formulario se proporcionan como valores predeterminados, y cada valor debe ser una de las prioridades de Bitbucket: `trivial`, `minor`, `major`, `critical` o `blocker`.

- **Severity Field Name**: `priority`
- **Info Mapping**: `trivial`
- **Low Mapping**: `minor`
- **Medium Mapping**: `major`
- **High Mapping**: `critical`
- **Critical Mapping**: `blocker`

### Detalles del mapeo de estado

Esto se mapea al campo State de la incidencia de Bitbucket. Cada valor debe ser uno de los estados de incidencia de Bitbucket: `new`, `open`, `resolved`, `on hold`, `invalid`, `duplicate`, `wontfix` o `closed`.

- **Status Field Name**: `state`
- **Active Mapping**: `new`
- **Closed Mapping**: `resolved`
- **False Positive Mapping**: `invalid`
- **Risk Accepted Mapping**: `wontfix`
