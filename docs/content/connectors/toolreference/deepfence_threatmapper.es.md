---
title: "Deepfence ThreatMapper"
description: "Cómo configurar el Conector Upstream de Deepfence ThreatMapper para DefectDojo"
weight: 46
audience: pro
---
El conector de Deepfence ThreatMapper utiliza la API REST de la consola de administración de [ThreatMapper](https://github.com/deepfence/ThreatMapper) para importar resultados de **escaneos de vulnerabilidades**. DefectDojo detecta todos los nodos que ThreatMapper ha escaneado (una imagen de contenedor, un host o un contenedor) y crea un Registro para cada uno; a continuación, importa como hallazgos el escaneo completado más reciente de ese nodo.

#### Requisitos previos

Necesitará un **API token** de ThreatMapper, disponible en la consola en **Settings → User Management** (la clave de API de su usuario). El conector lo intercambia por un token de acceso de corta duración en cada sincronización; el API token nunca se registra en los logs.

#### Asignaciones del conector

1. Introduzca la URL de la consola de ThreatMapper en el campo **Location** (por ejemplo, `https://threatmapper.example.com`).
2. En el campo **Secret**, introduzca el API token de ThreatMapper.
3. Si su consola utiliza un certificado autofirmado, defina **Skip TLS Verification** en `true`.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **nodo** escaneado a un Registro y cada **CVE** de su escaneo de vulnerabilidades completado más reciente a un hallazgo. La severidad proviene de la propia calificación de ThreatMapper, y se trasladan el paquete afectado, la puntuación CVSS, la versión de corrección (como mitigación), los enlaces de referencia y un bloque de detalles. Los hallazgos se registran como hallazgos dinámicos y se deduplican según el nodo, el CVE, el paquete y la ruta del paquete.

Consulte la [documentación de ThreatMapper](https://community.deepfence.io/threatmapper/docs/v2.5/) para obtener más información.
