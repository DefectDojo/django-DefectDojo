---
title: "Lacework / FortiCNAPP"
description: "Cómo configurar el Conector Upstream de Lacework / FortiCNAPP para DefectDojo"
weight: 86
audience: pro
---
El conector Lacework / FortiCNAPP usa la API v2 de Lacework para importar **vulnerabilidades de hosts y contenedores** de toda su cuenta de Lacework.

#### Requisitos previos

Necesitará una **API key** de Lacework — un ID de clave de API y un secreto, creados en la consola de Lacework en **Settings → API keys**. El conector los intercambia por un token de acceso de corta duración en cada sincronización; el ID de clave, el secreto y el token nunca se registran en los logs.

#### Asignaciones del conector

1. Introduzca la URL de su cuenta de Lacework en el campo **Location** — por ejemplo `https://YOUR-ACCOUNT.lacework.net` (también se acepta un nombre de cuenta simple).
2. Introduzca el **API Key ID** y el **API Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna la **cuenta** de Lacework a un Registro (el ámbito de toda la cuenta). Cada vulnerabilidad de **contenedor** y de **host** se convierte en un hallazgo: la severidad proviene de la propia calificación de Lacework, el paquete y la versión afectados se convierten en el componente, la versión de corrección se convierte en la mitigación, y la imagen/host afectado se registra como etiquetas. Las vulnerabilidades de contenedor se registran como hallazgos estáticos (escaneos de imagen) y las vulnerabilidades de host como hallazgos dinámicos (escaneos de host en ejecución).

Consulte la [documentación de la API de Lacework](https://docs.lacework.net/api/v2/docs) para obtener más información.
