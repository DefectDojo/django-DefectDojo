---
title: "Escape"
description: "Cómo configurar el Conector Upstream de Escape para DefectDojo"
weight: 55
audience: pro
---
El conector de Escape utiliza la API de [Escape](https://escape.tech) para importar **hallazgos de seguridad de API (DAST)**. DefectDojo enumera todas las organizaciones a las que el token tiene acceso y todas las aplicaciones de cada una, crea un Registro para cada aplicación que tenga un escaneo, e importa como hallazgos las incidencias del escaneo más reciente de esa aplicación. No existe configuración por aplicación.

#### Requisitos previos

Necesitará una **API key** de Escape, creada en la aplicación de Escape en **Settings → API keys**. La clave se envía en el encabezado `Authorization: Key` y nunca se registra en los logs.

#### Asignaciones del conector

1. Conserve el valor ya rellenado en **Location**, `https://public.escape.tech/v2`, o introduzca explícitamente el host de la API de Escape.
2. Introduzca la clave de API de Escape en el campo **Secret**.
3. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **aplicación** a un Registro y cada **issue** del escaneo a un hallazgo: la severidad proviene de la calificación de Escape (Crítica/Alta/Media/Baja), se traslada el CWE, la categoría OWASP y el método HTTP se convierten en etiquetas, la URL afectada se convierte en el endpoint, y se incluye la guía de remediación. Los hallazgos se registran como hallazgos dinámicos y se deduplican según el id de la issue de Escape.

Consulte la [documentación de la API de Escape](https://docs.escape.tech/) para obtener más información.
