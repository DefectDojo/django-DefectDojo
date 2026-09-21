---
title: "runZero"
description: "Cómo configurar el Conector Upstream de runZero para DefectDojo"
weight: 115
audience: pro
---
El conector de runZero usa la Export API de runZero para sincronizar el inventario de activos de toda su organización en DefectDojo. Es principalmente un conector de **activos**: DefectDojo descubre cada activo y crea un Record para cada uno, agrupados en un Product Type según su **site** de runZero. Opcionalmente, también puede importar las vulnerabilidades de runZero como hallazgos.

#### Requisitos previos

Necesitará un **Export Token** de organización de runZero (Account → API), con el prefijo `XT`. El token tiene alcance de organización (la organización está codificada en el token), es de solo lectura, y se envía como un Bearer token; nunca se registra en los logs. Hay disponible un nivel community/starter.

#### Asignaciones del conector

1. Ingrese la URL de la consola de runZero en el campo **Location**, por ejemplo `https://console.runzero.com`. La URL debe ser HTTPS.
2. Ingrese el Export Token en el campo **Secret**.
3. Opcionalmente, establezca **Import Vulnerabilities** en `true` para importar también las vulnerabilidades de runZero como hallazgos; déjelo en blanco para sincronizar solo los activos.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos de vulnerabilidades se importan (aplica solo cuando se importan vulnerabilidades).

DefectDojo asigna cada **activo** de runZero a un Record (VEP): el nombre visible proviene del nombre o la dirección del activo, y su site, tipo, SO, direcciones y etiquetas se adjuntan como atributos; el **site** del activo se convierte en su Product Type. Los activos se sincronizan mediante una exportación completa que DefectDojo concilia (agrega/elimina). Cuando **Import Vulnerabilities** está habilitado, cada vulnerabilidad de runZero se convierte en un hallazgo en su activo, asignando la severidad, la puntuación CVSS, el CVE, el endpoint del servicio afectado (`protocol://address:port`) y la remediación.

Consulte la [documentación de la API de runZero](https://help.runzero.com/) para más información.
