---
title: "Contrast"
description: "Cómo configurar el Conector Upstream de Contrast para DefectDojo"
weight: 39
audience: pro
---
El conector de Contrast utiliza la API REST de Contrast Assess para importar vulnerabilidades de aplicaciones. DefectDojo detecta las aplicaciones de su organización de Contrast y crea un Registro para cada una.

#### Requisitos previos

Necesitará cuatro valores de Contrast. Recomendamos crear una cuenta de servicio dedicada para que la actividad automatizada se distinga fácilmente de las acciones manuales de su equipo. En la interfaz de Contrast, en **User Settings > Profile > Your Keys**, encontrará:

* La **API Key** de su organización.
* Su **Service Key** personal.
* El **username** al que pertenecen las credenciales (el correo electrónico de inicio de sesión de la cuenta).
* Su **Organization ID**: el UUID de la organización desde la que importar, que también se muestra en **Organization Settings**.

#### Asignaciones del conector

1. Introduzca la URL base que utiliza para acceder a Contrast en el campo **Location**; para el producto alojado, suele ser `https://app.contrastsecurity.com` (o la URL de su Team Server regional o autoalojado).
2. Introduzca el correo electrónico de inicio de sesión de la cuenta en el campo **Username**.
3. Introduzca la **API Key** de la organización en el campo **API Key**.
4. Introduzca la **Service Key** personal en el campo **Service Key**.
5. Introduzca el **Organization ID** (UUID) en el campo **Organization ID**.
6. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

Cada aplicación de Contrast se convierte en un Registro, y sus vulnerabilidades se importan como hallazgos.
