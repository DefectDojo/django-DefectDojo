---
title: Google Auth
description: Configure el OAuth de Google en DefectDojo Pro
weight: 11
audience: pro
---

DefectDojo Pro admite el inicio de sesión mediante cuentas de Google. Los usuarios nuevos se crean automáticamente en el primer inicio de sesión si aún no existen. Los usuarios ya existentes de DefectDojo se emparejan con las cuentas de Google por nombre de usuario (la parte anterior a la `@` en su correo de Google). DefectDojo de código abierto no incluye SSO — consulte [Authorized Users](/admin/user_management/os__authorized_users/) para el control de acceso de código abierto.

## Requisitos previos

Complete los siguientes pasos en Google Cloud Console antes de configurar DefectDojo:

1. Inicie sesión en [Google Developers Console](https://console.developers.google.com).

2. Vaya a **Credentials > Create Credentials > OAuth Client ID**.

   ![imagen](images/google_1.png)

3. Seleccione **Web Application** y asígnele un nombre descriptivo (por ejemplo, `DefectDojo`).

4. En **Authorized Redirect URIs**, añada:
   `https://your-instance.cloud.defectdojo.com/complete/google-oauth2/`

5. Anote el **Client ID** y la **Client Secret Key**.

## Configuración

En DefectDojo, vaya a **Enterprise Settings > OAuth Settings**, seleccione **Google** y complete el formulario:

- **Google OAuth Key** — introduzca su **Client ID**
- **Google OAuth Secret** — introduzca su **Client Secret Key**
- **Whitelisted Domains** — introduzca el dominio de su organización (por ejemplo, `yourcompany.com`) para permitir que inicie sesión cualquier usuario con ese dominio
- **Whitelisted E-mail Addresses** — alternativamente, introduzca direcciones de correo específicas para permitir (por ejemplo, `user1@yourcompany.com, user2@yourcompany.com`)

Debe establecer al menos un dominio o dirección de correo en la lista blanca, o ningún usuario podrá iniciar sesión mediante Google.

Marque **Enable Google OAuth** y envíe el formulario. Aparecerá un botón **Login With Google** en la página de inicio de sesión.
