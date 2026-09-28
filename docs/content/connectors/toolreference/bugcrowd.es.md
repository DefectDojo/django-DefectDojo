---
title: "Bugcrowd"
description: "Cómo configurar el Conector Upstream de Bugcrowd para DefectDojo"
weight: 29
audience: pro
---
El conector de Bugcrowd usa la REST API de Bugcrowd para importar submissions de sus programas de bug bounty y de divulgación de vulnerabilidades. DefectDojo descubre los programas a los que su token de API tiene acceso y crea un Registro para cada uno, importando las submissions de ese programa como hallazgos.

#### Prerrequisitos

Necesitará un **token de API** de Bugcrowd con acceso a los programas que desea importar. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que la actividad automatizada se distinga fácilmente de las acciones manuales del equipo. Genere el token en Bugcrowd en **Organization settings \> API credentials**; basta con acceso de lectura a submissions, programs y targets.

#### Asignaciones del conector

1. Ingrese `https://api.bugcrowd.com` en el campo **Location**.
2. Ingrese su token de API de Bugcrowd en el campo **Secret**. Se envía como encabezado `Authorization: Token`.
3. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

Cada **program** de Bugcrowd se convierte en un Registro, y sus submissions se importan como hallazgos conservando la severidad de Bugcrowd. Las submissions duplicadas se excluyen, por lo que volver a importar no crea hallazgos repetidos para el mismo problema.
