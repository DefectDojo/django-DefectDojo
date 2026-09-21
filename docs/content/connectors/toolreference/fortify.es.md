---
title: "Fortify"
description: "Cómo configurar el Conector Upstream de Fortify para DefectDojo"
weight: 59
audience: pro
---
El conector de Fortify importa resultados SAST/DAST de Fortify (OpenText/Micro Focus), abarcando las dos ediciones que comparten la plataforma: **SSC** (Software Security Center, autoalojado) y **Fortify on Demand (FoD)** (SaaS). Sincroniza toda la cuenta: DefectDojo detecta todas las aplicaciones (project version de SSC / release de FoD) y crea un Registro para cada una; a continuación, importa las incidencias de esa aplicación como hallazgos.

#### Requisitos previos

- **SSC**: un **FortifyToken**; créelo en la interfaz de SSC en **Administration → Token Management** (un CIToken/UnifiedLoginToken).
- **FoD**: una **OAuth2 API key**; un Client ID y un Client Secret desde **Settings → API** (con el scope `api-tenant`).

El token y el secret de OAuth nunca se registran en los logs.

#### Asignaciones del conector

1. Introduzca la URL base de Fortify en el campo **Location**: para SSC, el host de su servidor (el conector añade `/ssc/api/v1`); para FoD, el host de la API de su región, por ejemplo, `https://api.ams.fortify.com`.
2. Defina **Edition** en `SSC` o `FoD`.
3. Para **FoD**, introduzca el **Client ID** de OAuth; déjelo en blanco para SSC.
4. En **Token / Client Secret**, introduzca el FortifyToken de SSC o el client secret de OAuth de FoD.
5. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **aplicación** de Fortify a un Registro y cada **issue** a un hallazgo: la severidad proviene de la propia calificación de **friority** de Fortify (Crítica/Alta/Media/Baja), el título combina la categoría de la incidencia con su archivo y línea, y se trasladan la ruta del archivo, la línea, el kingdom, el analizador y el tipo de motor. Las incidencias de los motores de análisis estático (SCA) se registran como hallazgos estáticos y las incidencias de WebInspect (DAST) como hallazgos dinámicos; las incidencias suprimidas, eliminadas u ocultas se omiten, las incidencias auditadas como "Not an Issue" se marcan como falso positivo, y las incidencias "Exploitable" o revisadas se marcan como verificadas.

Consulte la documentación de la API de [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) y de [Fortify on Demand](https://api.ams.fortify.com/swagger/ui) para obtener más información.
