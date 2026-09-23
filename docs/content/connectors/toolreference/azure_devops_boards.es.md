---
title: "Azure DevOps Boards"
description: "Cómo configurar el Conector Downstream de Azure DevOps Boards para DefectDojo"
weight: 21
audience: pro
---
### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en su URL de Azure - por ejemplo `https://dev.azure.com/{your organization}`
- **Token** debe establecerse en un token de acceso personal de Azure.

La autenticación con Azure DevOps requiere un [token de acceso personal](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)
con permisos establecidos en "Read, Write and Manage" para "Work Items" en el proyecto de Azure con el que desea trabajar.

### Mapeo del Issue Tracker

Estos detalles determinan cómo DefectDojo mapeará los atributos de un Hallazgo o Grupo de Hallazgos a un Proyecto dado en Azure DevOps:

#### Detalles del mapeo del Issue Tracker

El campo `Project ID` corresponde al nombre o al ID del proyecto en Azure.

#### Detalles del mapeo de severidad

Los atributos del formulario se proporcionan como valores predeterminados y son los siguientes:

- **Severity Field Name**: `/fields/Microsoft.VSTS.Common.Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

#### Detalles del mapeo de estado

Los atributos del formulario se proporcionan como valores predeterminados y son los siguientes:

- **Status Field Name**: `/fields/System.State`
- **Active Mapping**: `To Do`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`
