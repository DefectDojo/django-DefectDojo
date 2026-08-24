---
title: "Intigriti"
description: "Cómo configurar el Conector Upstream de Intigriti para DefectDojo"
weight: 78
audience: pro
---
El conector Intigriti usa la API externa de empresa de Intigriti para importar **envíos** de bug bounty / pentest a DefectDojo. Sincroniza toda la cuenta de la empresa: DefectDojo detecta todos los programas a los que el token puede acceder y crea un Registro para cada uno, luego importa los envíos de ese programa como hallazgos.

#### Requisitos previos

Necesitará un **token de API de empresa** de Intigriti. En el portal de empresa de Intigriti, en **Company Settings > API** (el ámbito `company_external_api`), genere un token de acceso con acceso de lectura a sus programas y envíos. Se recomienda un token dedicado para DefectDojo. El token se envía como Bearer token y nunca se registra en los logs.

#### Asignaciones del conector

1. Introduzca la URL base de la API externa de empresa de Intigriti en el campo **Location**: `https://api.intigriti.com/external/company`. La URL debe ser HTTPS.
2. Introduzca el token de API de empresa en el campo **Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **programa** de Intigriti a un Registro y cada **envío** a un hallazgo, identificado por el código del envío. La severidad del hallazgo sigue la calificación de Intigriti (Exceptional/Critical → Crítica, luego Alta/Media/Baja, o en caso contrario Informational), y el estado del ciclo de vida del envío se asigna al estado del hallazgo: los envíos open/triage están activos, los envíos accepted están verificados, y los envíos closed pasan a ser duplicado, fuera de alcance, falso positivo o riesgo aceptado según su motivo de cierre. La descripción del hallazgo incluye el tipo de vulnerabilidad del reporte, el activo afectado, la prueba de concepto y las respuestas del investigador.

Consulte la [documentación de la API de Intigriti](https://kb.intigriti.com/en/articles/6117846-intigriti-api) para obtener más información.
