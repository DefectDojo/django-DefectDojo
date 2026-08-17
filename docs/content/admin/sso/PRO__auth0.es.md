---
title: Auth0
description: Configure el SSO de Auth0 en DefectDojo Pro
weight: 3
audience: pro
---

DefectDojo Pro admite el inicio de sesión mediante Auth0. DefectDojo de código abierto no incluye SSO — consulte [Authorized Users](/admin/user_management/os__authorized_users/) para el control de acceso de código abierto.

## Requisitos previos

Complete los siguientes pasos en su panel de Auth0 antes de configurar DefectDojo:

1. Cree una nueva aplicación: **Applications > Create Application > Single Page Web Application**.

2. Configure la aplicación:
   - **Name:** `DefectDojo`
   - **Allowed Callback URLs:** `https://your-instance.cloud.defectdojo.com/complete/auth0/`

3. Anote los siguientes valores — los necesitará en DefectDojo:
   - **Domain**
   - **Client ID**
   - **Client Secret**

## Configuración

En DefectDojo, vaya a **Enterprise Settings > OAuth Settings**, seleccione **Auth0** y complete el formulario:

- **Auth0 OAuth Key** — introduzca su **Client ID**
- **Auth0 OAuth Secret** — introduzca su **Client Secret**
- **Auth0 Domain** — introduzca su **Domain**

Marque **Enable Auth0 OAuth** para añadir un botón **Login With Auth0** a la página de inicio de sesión de DefectDojo.
