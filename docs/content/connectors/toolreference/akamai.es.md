---
title: "Akamai API Security"
description: "Cómo configurar el Conector Upstream de Akamai API Security para DefectDojo"
weight: 13
audience: pro
---
El conector de Akamai API Security usa una clave de API para extraer hallazgos de seguridad desde la API de Akamai. DefectDojo descubrirá su entorno de Akamai y creará Registros independientes para cada **Application** y **Host** configurados en su cuenta.

#### Prerrequisitos

Necesitará una clave de API con acceso a la API de Akamai. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que se distinga claramente la actividad automatizada de las acciones manuales del equipo.

#### Asignaciones del conector

1. Ingrese la URL base de la API de Akamai en el campo **Location**. Esta URL es específica de su instancia de Akamai: por ejemplo
2. Ingrese una **API Key** válida en el campo **Secret**.

DefectDojo asignará las **Applications** y los **Hosts** como Registros independientes. Cada Application aparecerá como `{name} (application)` y cada Host como `{name} (host)` en su lista de Registros.
