---
title: "Tenable Web App Scanning"
description: "Cómo configurar el Conector Upstream de Tenable Web App Scanning para DefectDojo"
weight: 132
audience: pro
---
El conector de Tenable Web App Scanning importa **hallazgos de aplicaciones web (DAST)** desde Tenable Web App Scanning. Es un conector independiente de Tenable (Vulnerability Management): los dos productos cubren activos diferentes y se configuran de forma independiente, por lo que puede usar uno u otro, o ambos.

DefectDojo crea un Record para cada **aplicación web escaneada**. Las aplicaciones se descubren a partir de sus configuraciones de análisis de Web App Scanning; una configuración que nunca se ha ejecutado no genera un Record hasta que se complete su primer análisis. Cuando más de una configuración analiza la misma aplicación, comparten un único Record.

#### Prerrequisitos

**API keys** de Tenable (una access key y una secret key) para un usuario con permisos de Web App Scanning. En Tenable, vaya a **My Account > API Keys** para generarlas, y confirme que el usuario puede ver los análisis que desea importar — las keys limitadas a Vulnerability Management no pueden leer datos de Web App Scanning.

Los conectores de Tenable on-premise no están disponibles por el momento.

#### Asignaciones del conector

1. Introduzca <https://cloud.tenable.com> en el campo **Location**.
2. Introduzca su **Access Key** y **Secret Key**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Los hallazgos se importan con la severidad que Tenable reporta para su cuenta, incluida cualquier severidad que su equipo haya reclasificado. Cada hallazgo incluye la URL afectada como endpoint, el parámetro de solicitud y el payload que lo desencadenó, y la prueba y el resultado de Tenable como pasos para reproducirlo, junto con los valores de CWE, CVE, CVSS y EPSS cuando el plugin de detección los proporciona.

Solo se importan los hallazgos que están actualmente abiertos o reabiertos. Un hallazgo que Tenable ha marcado como corregido se cierra en DefectDojo en la siguiente sincronización.
