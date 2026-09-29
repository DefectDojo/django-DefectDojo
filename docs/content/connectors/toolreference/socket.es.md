---
title: "Socket"
description: "Cómo configurar el Conector Upstream de Socket para DefectDojo"
weight: 126
audience: pro
---
El conector de Socket usa la API de [Socket.dev](https://socket.dev) para importar **hallazgos de la cadena de suministro de software** — las alertas de Socket sobre sus dependencias (malware, typosquatting, scripts de instalación, vulnerabilidades conocidas y más de 70 categorías adicionales). DefectDojo descubre todos los repositorios de las organizaciones a las que su token tiene acceso y crea un Record para cada uno, luego importa las alertas del análisis completo más reciente de ese repositorio.

#### Prerrequisitos

Necesitará un **token de API** de Socket — un token de organización creado en el panel de Socket en **Settings → API Tokens** (con los alcances `repo:list` y de lectura de full-scan). El token se envía como bearer token y nunca se registra en los logs.

#### Asignaciones del conector

1. Conserve el valor ya rellenado en **Location**, `https://api.socket.dev/v0`, o introdúzcalo explícitamente.
2. Introduzca el token de API de Socket en el campo **Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **repositorio** a un Record e importa las alertas de su análisis completo más reciente. Cada alerta se convierte en un hallazgo: la severidad proviene de la propia calificación de Socket (low, medium, high, critical), el paquete afectado se convierte en el componente y en un PURL, la categoría de la alerta (riesgo de cadena de suministro, calidad, mantenimiento, vulnerabilidad, licencia) se registra como etiquetas, y los detalles de la alerta se incorporan a la descripción. Los hallazgos se registran como hallazgos estáticos y se deduplican según la clave de alerta de Socket.

Consulte la [documentación de la API de Socket](https://docs.socket.dev/reference) para más información.
