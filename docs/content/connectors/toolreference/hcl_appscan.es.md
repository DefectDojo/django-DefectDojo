---
title: "HCL AppScan"
description: "Cómo configurar el Conector Upstream de HCL AppScan para DefectDojo"
weight: 73
audience: pro
---
El conector HCL AppScan usa la API REST v4 de AppScan para importar incidencias de **AppScan on Cloud (ASoC)** o de una instancia autoalojada de **AppScan 360°** (ambas comparten la API). Sincroniza toda la cuenta: DefectDojo detecta todas las aplicaciones y crea un Registro para cada una, y luego importa las incidencias de esa aplicación (DAST, SAST e IAST) como hallazgos.

#### Requisitos previos

Necesitará una **API key** de AppScan — un Key ID y un Key Secret generados en la configuración de su cuenta de AppScan (API Key). El conector los intercambia por un token de sesión de corta duración en cada ejecución; el Key ID, el Key Secret y el token nunca se registran en los logs.

#### Asignaciones del conector

1. Introduzca la URL de la consola de AppScan en el campo **Location**: para ASoC use `https://cloud.appscan.com` (o `https://eu.cloud.appscan.com` para la región de la UE); para AppScan 360° use el host de su instancia.
2. Establezca **Provider** en `ASOC` para AppScan on Cloud, o en `A360` para una instancia autoalojada de AppScan 360°.
3. Introduzca el **API Key ID** y el **API Key Secret**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **aplicación** de AppScan a un Registro (VEP) y cada **incidencia** a un hallazgo: el título es el tipo de incidencia con su dominio/entidad/cause-id/URL/ruta añadidos; la severidad asigna Informational a Info (Low/Medium/High/Critical se transfieren sin cambios); se incluyen el CWE, una descripción etiquetada, la corrección y el aviso, y el endpoint de host/puerto. Las incidencias de análisis estático se registran como hallazgos estáticos y las incidencias dinámicas/interactivas como hallazgos dinámicos; las incidencias abiertas quedan activas y las corregidas/aprobadas quedan mitigadas.

Consulte la [documentación de la API REST de AppScan](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html) para obtener más información.
