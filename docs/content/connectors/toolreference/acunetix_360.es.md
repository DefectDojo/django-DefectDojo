---
title: "Acunetix 360"
description: "Cómo configurar el Conector Upstream de Acunetix 360 para DefectDojo"
weight: 12
audience: pro
---
El conector de Acunetix 360 importa **hallazgos de vulnerabilidades DAST** desde la plataforma en la nube de Acunetix 360 (la plataforma Invicti). DefectDojo descubre los sitios web escaneados de su cuenta y crea un Registro para cada **sitio web**; los hallazgos de un sitio web provienen de su último análisis completado.

**Tenga en cuenta:** este conector es para **Acunetix 360** (el producto en la nube en `online.acunetix360.com`). No es para el escáner local Acunetix Standard/Premium, que tiene una API diferente.

#### Requisitos previos

Una cuenta de Acunetix 360 y una **credencial de API**: en Acunetix 360, abra el menú de su cuenta \> **API Settings**, anote el **API User ID** y genere un **API Token**. El conector se autentica con estos valores como credenciales HTTP Basic, por lo que se recomienda una cuenta de servicio dedicada para distinguir la actividad automatizada de las acciones manuales del equipo.

#### Asignaciones del conector

1. Ingrese la URL de su Acunetix 360 en el campo **Location**: `https://online.acunetix360.com`.
2. Ingrese el API User ID en el campo **API User ID**.
3. Ingrese el API Token en el campo **API Token**.
4. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

Cada sitio web escaneado se convierte en un Registro. Los hallazgos provienen del último análisis completado del sitio web; las vulnerabilidades que Acunetix 360 ha marcado como **Riesgo aceptado** o **Falso positivo** igualmente se importan, pero se marcan como inactivas (riesgo aceptado o falso positivo) para que el producto de DefectDojo refleje la clasificación del proveedor.
