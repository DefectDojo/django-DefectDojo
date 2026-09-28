---
title: GitHub Enterprise
description: Configure el SSO de GitHub Enterprise en DefectDojo Pro
weight: 7
audience: pro
---

DefectDojo Pro admite el inicio de sesión mediante GitHub Enterprise. DefectDojo de código abierto no incluye SSO — consulte [Authorized Users](/admin/user_management/os__authorized_users/) para el control de acceso de código abierto.

## Requisitos previos

Complete los siguientes pasos en GitHub Enterprise antes de configurar DefectDojo:

1. [Cree una nueva OAuth App](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app) en su GitHub Enterprise Server.

2. Elija un nombre para la aplicación, por ejemplo `DefectDojo`.

3. Configure el **Redirect URI**:
   `https://your-instance.cloud.defectdojo.com/complete/github-enterprise/`

4. Anote el **Client ID** y el **Client Secret** de la aplicación.

## Configuración

En DefectDojo, vaya a **Enterprise Settings > OAuth Settings**, seleccione **GitHub Enterprise** y complete el formulario:

- **GitHub Enterprise OAuth Key** — introduzca su **Client ID**
- **GitHub Enterprise OAuth Secret** — introduzca su **Client Secret**
- **GitHub Enterprise URL** — introduzca la URL de GitHub de su organización, por ejemplo `https://github.yourcompany.com/`
- **GitHub Enterprise API URL** — introduzca la URL de la API de GitHub de su organización, por ejemplo `https://github.yourcompany.com/api/v3/`

Marque **Enable GitHub Enterprise OAuth** y envíe el formulario. Aparecerá un botón **Login With GitHub** en la página de inicio de sesión.
