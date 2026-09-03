---
title: "GitHub Advanced Security"
description: "Cómo configurar el Conector Upstream de GitHub Advanced Security para DefectDojo"
weight: 64
audience: pro
---
El conector de GitHub Advanced Security importa alertas de **code scanning**, **Dependabot** y **secret scanning** de GitHub, como tres tipos de hallazgo independientes (`GitHub:CodeScanning`, `GitHub:Dependabot` y `GitHub:SecretScanning`). DefectDojo detecta todos los repositorios no archivados de la organización configurada y crea un Registro para cada uno.

#### Requisitos previos

Las funciones de GitHub Advanced Security deben estar habilitadas en los repositorios que desea importar. El conector se autentica con un **personal access token** de GitHub:

1. En GitHub, abra **Settings \> Developer settings \> Personal access tokens** y cree un token propiedad de (o con acceso a) la organización de destino.
2. Otórguele acceso de lectura a las alertas de seguridad: un token *fine\-grained* necesita acceso **Read\-only** a **Code scanning alerts**, **Dependabot alerts** y **Secret scanning alerts** en los repositorios de la organización; un token *classic* necesita los scopes **`repo`** y **`security_events`**.
3. Confirme que el propietario del token puede ver los repositorios que pretende importar: el conector solo ve los repositorios a los que el token tiene acceso.

#### Asignaciones del conector

1. Introduzca `https://api.github.com` en el campo **Location**. Para GitHub Enterprise Server, utilice `https://<your-host>/api/v3`.
2. Introduzca el login de la organización en el campo **Organization**.
3. Introduzca el personal access token en el campo **Secret**.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

Cada repositorio no archivado se convierte en un Registro, consultado en las tres familias de alertas en busca de alertas abiertas. Una familia de alertas que no esté habilitada para un repositorio se omite en lugar de reportarse como resuelta, de modo que las funciones deshabilitadas no provocan cierres falsos.
