---
title: "Jira Service Management Assets"
description: "Cómo configurar el Conector Upstream de Jira Service Management Assets para DefectDojo"
weight: 83
audience: pro
---
El conector JSM Assets es un **conector de activos**: enumera los objetos de su espacio de trabajo de Jira Service Management Assets (anteriormente Insight) y crea un Activo de DefectDojo para cada objeto, agrupados en Organizaciones según el esquema del objeto. No se importa ningún hallazgo.

#### Requisitos previos

* Assets requiere un plan **Jira Service Management Premium o Enterprise**. En los planes Free o Standard, la API de Assets responde con `403 "Access to Assets API was denied"`, aunque el resto del sitio funcione con normalidad.
* La cuenta de Atlassian utilizada debe tener **acceso de producto a Jira Service Management** (una plaza de agente) en el sitio — el acceso al sitio por sí solo no es suficiente.
* Cree un token de API clásico de Atlassian en [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens). Recomendamos una cuenta de servicio dedicada.

#### Asignaciones del conector

1. Introduzca la URL de su sitio de Atlassian en el campo **Location**: `https://{your-site}.atlassian.net`.
2. Introduzca el correo electrónico de la cuenta de Atlassian al que pertenece el token en el campo **Email**.
3. Introduzca el token de API en el campo **Secret**.

Cada objeto de Assets se convierte en un Registro con el nombre de la etiqueta del objeto, agrupado por su **esquema de objeto**.
