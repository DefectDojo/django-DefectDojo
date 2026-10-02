---
title: "NeuVector"
description: "Cómo configurar el Conector Upstream de NeuVector para DefectDojo"
weight: 93
audience: pro
---
El conector de NeuVector usa la API REST del controlador de [NeuVector](https://github.com/neuvector/neuvector) para importar **escaneos de vulnerabilidades de imágenes** de contenedor. DefectDojo descubre cada imagen que NeuVector ha escaneado y crea un Record para cada una, y luego importa el informe de escaneo de esa imagen como hallazgos.

#### Requisitos previos

Necesitará un **nombre de usuario y contraseña** de NeuVector para una cuenta del controlador con permiso para leer los resultados de los escaneos. El conector inicia sesión con estas credenciales para obtener un token de sesión; la contraseña y el token nunca se registran en los logs.

#### Asignaciones del conector

1. Ingrese la URL del controlador de NeuVector en el campo **Location**, incluyendo el puerto de la API REST; por ejemplo, `https://neuvector.example.com:10443`.
2. Ingrese el **Username** y **Password** del controlador.
3. Si su controlador usa un certificado autofirmado, establezca **Skip TLS Verification** en `true`.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **imagen** escaneada a un Record y cada **CVE** de su informe de escaneo a un hallazgo. La severidad proviene de la propia calificación de NeuVector, y se trasladan el paquete y la versión afectados, la puntuación y el vector CVSSv3, la versión de corrección (como mitigación) y el enlace de referencia. Los hallazgos se deduplican por la imagen, el CVE, el paquete, la versión y la severidad.

Consulte la [documentación de la API de NeuVector](https://open-docs.neuvector.com/automation/automation) para más información.
