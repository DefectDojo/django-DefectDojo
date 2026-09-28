---
title: "Intruder"
description: "Cómo configurar el Conector Upstream de Intruder para DefectDojo"
weight: 79
audience: pro
---
El conector Intruder usa la [API REST de Intruder](https://developers.intruder.io/) para importar la postura de toda su cuenta a DefectDojo. Cada **destino** de Intruder se detecta como un Registro (Producto); cada **aparición** de una incidencia en un destino se convierte en un Hallazgo.

#### Asignaciones del conector

1. Deje el campo **Location** como `https://api.intruder.io/` (el servidor de API predeterminado de Intruder).
2. Introduzca un **token de acceso de API** de Intruder en el campo **Secret**.

Genere un token de acceso en Intruder en **My account > API Access Tokens** (necesitará la contraseña de su cuenta para crearlo, y el token solo se muestra una vez). Consulte la [documentación de la API de Intruder](https://developers.intruder.io/docs/creating-an-access-token) para más detalles.

Los hallazgos se derivan por aparición: la severidad proviene de la severidad de la incidencia, los CVE y CVSS de la aparición, la ubicación del destino/puerto, y una aparición en estado "snoozed" se importa como un hallazgo inactivo (falso positivo o riesgo aceptado).
