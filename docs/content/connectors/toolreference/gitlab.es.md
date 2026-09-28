---
title: "GitLab"
description: "Configuración de los Conectores Upstream y Downstream de GitLab"
weight: 65
audience: pro
---
## Conector Upstream

El conector de GitLab es un **Asset Connector**: enumera todos los proyectos (repositorios) a los que su token tiene acceso y crea un Activo de DefectDojo para cada uno, agrupados en Organizaciones según el namespace de GitLab (grupo o usuario). No se importa ningún hallazgo.

#### Requisitos previos

Necesitará un Personal Access Token con el scope **read_api**. Recomendamos crear el token desde una cuenta de servicio dedicada; el conector enumera los proyectos de los que esa cuenta es miembro.

#### Asignaciones del conector

1. Introduzca su URL de GitLab en el campo **Location**: `https://gitlab.com`, o la URL base de su instancia autoalojada.
2. Introduzca el Personal Access Token en el campo **Secret**.

Cada proyecto se convierte en un Registro con el nombre del proyecto, agrupado por su **namespace**. Los proyectos pendientes de eliminación en GitLab (eliminados por un usuario, pero aún no purgados por el trabajo en segundo plano de GitLab) se excluyen automáticamente, de modo que eliminar un proyecto marca su Registro como `MISSING` en la siguiente sincronización en lugar de dejar un activo fantasma renombrado.

## Conector Downstream

La integración de GitLab le permite añadir incidencias a un [Proyecto de GitLab](https://docs.gitlab.com/ee/user/project/).

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en el enlace de su servidor de GitLab, por ejemplo `https://gitlab.com/`.
- **Token** debe establecerse en un token de acceso personal de GitLab. El token debe tener alcances de API. Consulte la [guía de GitLab para crear un token de acceso personal](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token).

### Mapeo del Issue Tracker

- **Project Name**: el nombre del proyecto en GitLab al que desea enviar incidencias.

### Detalles del mapeo de severidad

Esto se mapea al campo Priority de GitLab.
- **Severity Field Name**: `Priority`
- **Info Mapping**: `1`
- **Low Mapping**: `2`
- **Medium Mapping**: `3`
- **High Mapping**: `4`
- **Critical Mapping**: `5`

### Detalles del mapeo de estado

De forma predeterminada, GitLab tiene los estados 'opened' y 'closed'. Se pueden añadir etiquetas de estado adicionales si desea rastrear el estado Falso positivo o Riesgo aceptado. Consulte la [documentación de GitLab](https://docs.gitlab.com/user/work_items/status/) para más detalles.

- **Status Field Name**: `Status`
- **Active Mapping**: `opened`
- **Closed Mapping**: `closed`
- **False Positive Mapping**: `closed`
- **Risk Accepted Mapping**: `closed`
