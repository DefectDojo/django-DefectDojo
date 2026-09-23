---
title: "GitGuardian"
description: "Cómo configurar el Conector Upstream de GitGuardian para DefectDojo"
weight: 62
audience: pro
---
El conector de GitGuardian utiliza la API REST de GitGuardian para importar **incidentes de secretos**: credenciales expuestas que GitGuardian ha detectado en sus fuentes monitorizadas. DefectDojo crea un Registro para cada fuente monitorizada (repositorio o perímetro) que actualmente tenga incidentes abiertos, e importa cada incidente abierto como un hallazgo.

Por su seguridad, el conector importa únicamente los **metadatos** del incidente: el detector, la severidad, la validez, el estado y un enlace de vuelta a GitGuardian. El propio valor del secreto expuesto nunca se recupera ni se almacena en DefectDojo; siga el enlace de cada hallazgo para revisar las ubicaciones afectadas en GitGuardian.

#### Requisitos previos

Necesitará una clave de API de GitGuardian. Recomendamos un **Service Account token** (en lugar de un personal access token) para que la actividad automatizada se distinga fácilmente. Créelo en **API** en el panel de GitGuardian y otorgue estos scopes de lectura:

* `incidents:read`
* `sources:read`

#### Asignaciones del conector

1. Introduzca la URL de la API de GitGuardian en el campo **Location**: `https://api.gitguardian.com` para la plataforma SaaS, o la URL de la API de su instancia autoalojada.
2. Introduzca la clave de API en el campo **Secret**.

Solo se importan los incidentes **open** (con estado `TRIGGERED` o `ASSIGNED`); los incidentes que resuelva o ignore en GitGuardian se mitigan automáticamente en DefectDojo en la siguiente sincronización. Un secreto confirmado como activo (validez *valid*) se importa como un hallazgo verificado.
