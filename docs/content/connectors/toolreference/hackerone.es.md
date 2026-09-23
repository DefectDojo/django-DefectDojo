---
title: "HackerOne"
description: "Cómo configurar el Conector Upstream de HackerOne para DefectDojo"
weight: 69
audience: pro
---
El conector HackerOne usa la API REST de HackerOne para importar reportes de su programa de recompensas por errores (bug bounty) o de divulgación de vulnerabilidades. DefectDojo crea un Registro para cada programa al que el token pueda acceder e importa sus reportes como hallazgos.

#### Requisitos previos

El conector usa la API **customer** de HackerOne, que requiere un **token de API de la organización**; un token personal de la configuración de su usuario solo funciona con la API de hacker y no se autenticará aquí.

1. En HackerOne, vaya a **Organization Settings > API Tokens**.
2. Cree un token y anote tanto el **identifier** como el valor del **token**. El acceso de lectura al programa es suficiente.

#### Asignaciones del conector

1. Introduzca `https://api.hackerone.com` en el campo **Location**.
2. Introduzca el **identifier** del token en el campo **API Token Identifier**.
3. Introduzca el valor del token en el campo **API Token**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada programa se convierte en un Registro, y sus reportes se importan como hallazgos conservando la calificación de severidad de HackerOne.
