---
title: "CrowdStrike Falcon"
description: "Cómo configurar el Conector Upstream de CrowdStrike Falcon para DefectDojo"
weight: 41
audience: pro
---
El conector de CrowdStrike Falcon importa **vulnerabilidades de Spotlight** y **detecciones de EDR** de la plataforma Falcon, como dos tipos de hallazgo independientes (`CrowdStrike:Spotlight` y `CrowdStrike:Detections`). DefectDojo crea un Registro para cada **host** de Falcon.

#### Requisitos previos

Un **API client** de Falcon (Client ID y secret), creado en la consola de Falcon en **Support \> API Clients and Keys**. Otórguele los scopes correspondientes a los datos que desea importar: **Hosts: Read** (obligatorio, para la detección de hosts), **Vulnerabilities (Spotlight): Read** (para los hallazgos de Spotlight) y **Alerts: Read** (para las detecciones de EDR). Los dos tipos de hallazgo son independientes: si al cliente le falta un scope, ese tipo de hallazgo se omite en lugar de hacer fallar la sincronización, por lo que un cliente sin **Alerts: Read** sigue importando las vulnerabilidades de Spotlight.

#### Asignaciones del conector

1. Introduzca la URL base de la API de su nube de Falcon en el campo **Location**, según la región de su consola; por ejemplo, `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1) o `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Introduzca el Client ID del API client en el campo **Client ID**.
3. Introduzca el secret del API client en el campo **Client Secret**.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

Cada host de Falcon se convierte en un Registro, nombrado según su hostname, sistema operativo y tipo. Solo se importan las vulnerabilidades de Spotlight **open** y **reopened**, por lo que una nueva importación cierra los hallazgos ya remediados.
