---
title: "Qualys"
description: "Cómo configurar el Conector Upstream de Qualys para DefectDojo"
weight: 109
audience: pro
---
El conector de Qualys importa **detecciones de vulnerabilidades de hosts de VMDR** —cada una combinada con sus metadatos de Qualys KnowledgeBase (QID)— desde Qualys Cloud Platform. DefectDojo crea un Record para cada **host** de Qualys en su suscripción.

#### Requisitos previos

Una cuenta de usuario de Qualys con **acceso a la API de VMDR**, y la **URL del servidor de API (platform)** de su suscripción, que difiere según la suscripción. Encuéntrela en la interfaz de Qualys, en **Help > About**, o en la página de [Platform Identification](https://www.qualys.com/platform-identification/) de Qualys (por ejemplo, `https://qualysapi.qualys.com` para US Platform 1, o `https://qualysapi.qg2.apps.qualys.com` para US Platform 2).

#### Asignaciones del conector

1. Ingrese la URL del servidor de API de Qualys en el campo **Location** (por ejemplo, `https://qualysapi.qualys.com`).
2. Ingrese el nombre de usuario de la API de Qualys en el campo **Username**.
3. Ingrese la contraseña de la API de Qualys en el campo **Secret**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada host de Qualys se convierte en un Record. Las detecciones que Qualys ha marcado como **Fixed** se excluyen, por lo que reimportar cierra los hallazgos remediados.
