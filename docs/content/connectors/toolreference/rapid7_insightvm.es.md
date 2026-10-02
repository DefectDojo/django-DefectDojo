---
title: "Rapid7 InsightVM"
description: "Cómo configurar el Conector Upstream de Rapid7 InsightVM para DefectDojo"
weight: 113
audience: pro
---
El conector de Rapid7 InsightVM importa hallazgos de vulnerabilidades de activos desde su **Security Console** de InsightVM (API v3), enriquecidos con el catálogo global de vulnerabilidades de la consola. DefectDojo crea un Record para cada **site** de InsightVM.

#### Requisitos previos

Acceso de red desde DefectDojo hasta su Security Console, y una **cuenta de usuario** de la consola; su inicio de sesión se usa para la autenticación HTTP Basic. La API de la consola se sirve por defecto en el puerto **3780**.

#### Asignaciones del conector

1. Ingrese la URL de su Security Console, incluyendo el puerto, en el campo **Location**; por ejemplo, `https://console.example.com:3780`.
2. Ingrese el nombre de usuario de la consola en el campo **Username**.
3. Ingrese la contraseña de la consola en el campo **Secret**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada site de InsightVM se convierte en un Record; el conector recorre los activos del site e importa sus hallazgos de vulnerabilidades.
