---
title: "Bright Security"
description: "Cómo configurar el Conector Upstream de Bright Security para DefectDojo"
weight: 28
audience: pro
---
El conector de Bright Security usa la API de [Bright](https://brightsec.com) (anteriormente NeuraLegion) para importar **hallazgos DAST**. DefectDojo descubre todos los scans a los que el token tiene acceso y crea un Registro para cada scan completado, e importa luego los issues de ese scan como hallazgos.

#### Prerrequisitos

Necesitará una **API key** de Bright, creada en la aplicación Bright en **User settings → API keys** (una clave `Org` o personal). La clave se envía en el encabezado `Authorization: Api-Key` y nunca se registra en logs.

#### Asignaciones del conector

1. Conserve el valor ya rellenado en **Location**, `https://app.brightsec.com`, o ingrese explícitamente su host de Bright.
2. Ingrese la API key de Bright en el campo **Secret**.
3. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **scan** completado a un Registro y cada **issue** a un hallazgo: la severidad proviene de la propia calificación de Bright (Crítica/Alta/Media/Baja), se trasladan el puntaje CVSS, el CWE y la remediación, el punto de entrada afectado se convierte en el endpoint, y la evidencia de la solicitud/respuesta se incluye en la descripción. Los hallazgos se registran como hallazgos dinámicos y se deduplican según el id de issue de Bright.

Consulte la [documentación de la API de Bright](https://docs.brightsec.com/) para obtener más información.
