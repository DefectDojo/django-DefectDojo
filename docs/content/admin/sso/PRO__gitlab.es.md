---
title: GitLab
description: Configure el SSO de GitLab en DefectDojo Pro
weight: 9
audience: pro
---

DefectDojo Pro admite el inicio de sesión mediante GitLab. DefectDojo de código abierto no incluye SSO — consulte [Authorized Users](/admin/user_management/os__authorized_users/) para el control de acceso de código abierto.

## Requisitos previos

Complete los siguientes pasos en GitLab antes de configurar DefectDojo:

1. Navegue a la página de Applications de su perfil de GitLab:
   - GitLab.com: `https://gitlab.com/profile/applications`
   - Autoalojado: `https://your-gitlab-host/profile/applications`

2. Cree una nueva aplicación:
   - **Name:** `DefectDojo`
   - **Redirect URI:** `https://your-dojo-instance.cloud.defectdojo.com/complete/gitlab/`

3. Anote el **Application ID** y el **Secret** de la aplicación.

## Configuración

En DefectDojo, vaya a **Enterprise Settings > OAuth Settings**, seleccione **GitLab** y complete el formulario:

- **GitLab OAuth Key** — introduzca su **Application ID**
- **GitLab OAuth Secret** — introduzca su **Secret**
- **GitLab API URL** — introduzca la URL base de su instancia de GitLab, por ejemplo `https://gitlab.com`

Marque **Enable GitLab OAuth** y envíe el formulario. Aparecerá un botón **Login With GitLab** en la página de inicio de sesión.
