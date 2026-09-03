---
title: "MobSF"
description: "Cómo configurar el Conector Upstream de MobSF para DefectDojo"
weight: 91
audience: pro
---
El conector de MobSF usa la API REST de [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) para importar resultados de análisis estático de aplicaciones móviles (APK/IPA). DefectDojo descubre cada app que se ha escaneado en su instancia de MobSF y crea un Record para cada una, y luego importa los hallazgos de análisis estático de esa app.

#### Requisitos previos

Necesitará su **REST API key** de MobSF. Encuéntrela en la página de inicio de MobSF, en **API** (también se muestra en la documentación de MobSF como el valor `Authorization`). La clave se envía en cada solicitud y nunca se registra en los logs.

#### Asignaciones del conector

1. Ingrese la URL base de MobSF en el campo **Location** (por ejemplo, `https://mobsf.example.com`).
2. En el campo **Secret**, ingrese la REST API key de MobSF.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **app** escaneada a un Record e importa sus hallazgos del informe JSON de MobSF en varias secciones: permisos de la aplicación, análisis de código, el certificado de firma, el manifiesto de Android, el uso de la API de Android y el análisis binario. Cada hallazgo se etiqueta con **CWE 919** (móvil), y su severidad proviene de la propia calificación de MobSF (high, warning, info, secure/good); un permiso *dangerous* se trata como Alta. Los hallazgos se registran como hallazgos estáticos y se deduplican por el scan, la sección, el título, la severidad y la ruta del archivo.

Consulte la [documentación de la API REST de MobSF](https://mobsf.github.io/docs/#/rest_api) para más información.
