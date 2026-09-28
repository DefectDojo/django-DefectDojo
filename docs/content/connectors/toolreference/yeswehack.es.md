---
title: "YesWeHack"
description: "Cómo configurar el Conector Upstream de YesWeHack para DefectDojo"
weight: 143
audience: pro
---
El conector de YesWeHack usa la API REST de YesWeHack para importar informes de sus programas de bug bounty y divulgación de vulnerabilidades. DefectDojo crea un Record para cada programa al que su token pueda acceder e importa sus informes como hallazgos.

#### Prerrequisitos

Necesitará un **Personal Access Token (PAT)** de YesWeHack. Es suficiente con acceso de lectura a sus programas. Algunas cuentas requieren TOTP/MFA al crear un token; una vez creado, el conector usa el valor del token en sí.

1. En YesWeHack, abra la configuración de su cuenta y vaya a **API / Personal Access Tokens**.
2. Cree un token y copie su valor. Solo se muestra una vez.

#### Asignaciones del conector

1. Introduzca `https://api.yeswehack.com/` en el campo **Location**.
2. Introduzca su Personal Access Token en el campo **Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importarán.

DefectDojo crea un Record independiente para cada programa al que su token pueda acceder, e importa cada informe como un hallazgo. La severidad del hallazgo se toma de la calificación CVSS del informe (recurriendo a la prioridad de triaje si no está disponible), y su estado refleja el estado del flujo de trabajo del informe — por ejemplo, los informes resueltos se importan como Mitigado, y los informes marcados como inválidos o fuera de alcance se importan como inactivos.
