---
title: "GitHub"
description: "Configuración de los Conectores Upstream y Downstream de GitHub"
weight: 63
audience: pro
---
## Conector Upstream

El conector de GitHub es un **Asset Connector**: enumera los repositorios a los que su token tiene acceso y crea un Activo de DefectDojo para cada uno, agrupados en Organizaciones según el propietario de GitHub (organización o usuario). No se importa ningún hallazgo.

**Tenga en cuenta:** este conector importa únicamente el **inventario** de sus repositorios. Para importar las alertas de seguridad de GitHub (code scanning, Dependabot y secret scanning) como hallazgos, utilice el conector independiente **GitHub Advanced Security** que se describe más adelante. Ambos son independientes y pueden ejecutarse juntos.

#### Requisitos previos

El conector se autentica con un **personal access token** de GitHub y solo lee los **metadatos** del repositorio (nombre, descripción, URL y propietario); no accede a su código, incidencias ni alertas de seguridad. Importa todos los repositorios que la cuenta del token posee, en los que colabora, o de cuya organización es miembro, así que confirme que la cuenta del token puede ver los repositorios que desea reflejar. Recomendamos una cuenta de servicio dedicada.

El token solo necesita acceso de solo lectura a los metadatos del repositorio:

- Un token *fine-grained* necesita **Repository permissions → Metadata: Read-only**, otorgado a los repositorios (o a toda la organización) que desea importar.
- Un token *classic* necesita el scope **`repo`** para incluir repositorios privados (use **`public_repo`** si solo necesita los públicos), además de **`read:org`** para que se resuelvan los repositorios propiedad de la organización.

Solo se admite GitHub.com (incluido GitHub Enterprise Cloud). GitHub Enterprise **Server** no está soportado actualmente por este conector.

#### Asignaciones del conector

1. Introduzca `https://api.github.com` en el campo **Location**.
2. Introduzca el personal access token en el campo **Secret**.

No es necesario introducir ninguna lista de organizaciones ni de repositorios: DefectDojo importa todos los repositorios que el token puede ver. Cada repositorio se convierte en un Registro con el nombre del repositorio, agrupado por su **owner** de GitHub (organización o usuario). Si un repositorio se elimina más adelante, o el token pierde el acceso a él, su Registro asignado se marca como `MISSING` en la siguiente sincronización en lugar de eliminarse: DefectDojo nunca elimina un Producto de forma silenciosa.

## Conector Downstream

La integración de GitHub le permite añadir incidencias a un [GitHub Project](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects), que también abre incidencias en un Repo asociado. Estos Repos/Proyectos pueden asociarse tanto a una organización de GitHub como a una cuenta personal de GitHub.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en la URL de su usuario u organización de GitHub, según dónde desee crear las incidencias. por ejemplo `https://github.com/{your-organization}`
- **Token** debe establecerse en un token de acceso personal de GitHub.

Los tokens de acceso personal para GitHub pueden crearse en https://github.com/settings/tokens. El token debe tener los alcances (scopes) Repo y Project.

### Mapeo del Issue Tracker

- **Issue Tracker Mapping Label** debe establecerse para identificar el Proyecto o Repo en el que desea crear incidencias.
- **Project Number** debe ser el ID de un proyecto de GitHub al que desea enviar los elementos. Puede obtenerlo de la URL al ver un Proyecto, por ejemplo `https://github.com/orgs/{your-org}/projects/{project number}`.
- **Repository Name** debe ser el nombre de un repositorio asociado a su organización (o usuario) al que desea enviar las incidencias.


### Detalles del mapeo de severidad

**Para configurar la integración, el proyecto DEBE tener un campo personalizado creado para representar la prioridad de la incidencia; de lo contrario, la severidad no se mapeará correctamente y las incidencias no se enviarán a GitHub.**

Siga esta guía para crear un [campo personalizado](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority).
Cada severidad necesitará tener una opción de selección única correspondiente disponible. Por ejemplo, de forma predeterminada DefectDojo sugiere P0, P1, P2, P3, P4 como posibles valores de Priority, y cada uno de ellos deberá añadirse al campo personalizado Priority.

- **Severity Field Name**: `Priority`
- **Info Mapping**: `P0`
- **Low Mapping**: `P1`
- **Medium Mapping**: `P2`
- **High Mapping**: `P3`
- **Critical Mapping**: `P4`

### Detalles del mapeo de estado

De forma predeterminada, los nuevos proyectos de GitHub tendrán estados para las incidencias de "In Progress" y "Done". Se pueden añadir estados adicionales al proyecto para rastrear el estado Falso positivo o Riesgo aceptado si lo desea. Una de las formas de hacerlo es añadiendo una nueva columna de estado al tablero del proyecto.

- **Status Field Name**: `Status`
- **Active Mapping**: `In Progress`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`
