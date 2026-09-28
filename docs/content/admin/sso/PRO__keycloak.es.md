---
title: KeyCloak
description: Configure el SSO de KeyCloak en DefectDojo Pro
weight: 13
audience: pro
---

DefectDojo Pro admite el inicio de sesión mediante KeyCloak. DefectDojo de código abierto no incluye SSO — consulte [Authorized Users](/admin/user_management/os__authorized_users/) para el control de acceso de código abierto.

Esta guía asume que ya tiene un Realm de KeyCloak configurado. Si no es así, consulte la [documentación de KeyCloak](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/realms/create.html).

## Requisitos previos

Complete los siguientes pasos en su realm de KeyCloak antes de configurar DefectDojo:

1. Añada un nuevo cliente de tipo `openid-connect`. Anote el ID de cliente.

2. En la configuración del cliente:
   - Establezca **Access Type** en `confidential`
   - En **Valid Redirect URIs**, añada la URL de su DefectDojo, por ejemplo `https://yourorganization.cloud.defectdojo.com` o `https://your-dojo-host/*`
   - En **Web Origins**, añada la misma URL (o `+`)
   - En **Fine Grained OpenID Connect Configuration**:
     - Establezca **User Info Signed Response Algorithm** en `RS256`
     - Establezca **Request Object Signature Algorithm** en `RS256`
   - Guarde la configuración.

3. En **Scope**, establezca **Full Scope Allowed** en `off`.

4. En **Mappers**, añada un mapper personalizado:
   - **Name:** `aud`
   - **Mapper Type:** `audience`
   - **Included Audience:** seleccione su ID de cliente
   - **Add ID to Token:** `off`
   - **Add Access to Token:** `on`

5. En **Credentials**, copie el **Secret**.

6. En **Realm Settings > Keys**, copie la **Public Key** (clave de firma).

7. En **Realm Settings > General > Endpoints**, abra la configuración del endpoint de OpenID y copie las URL de los endpoints **Authorization** y **Token**.

## Configuración

En DefectDojo, vaya a **Enterprise Settings > OAuth Settings**, seleccione **KeyCloak** y complete el formulario:

- **KeyCloak OAuth Key** — introduzca el nombre de su cliente (del paso 1)
- **KeyCloak OAuth Secret** — introduzca el secreto de credenciales de su cliente (del paso 5)
- **KeyCloak Public Key** — introduzca la Public Key de la configuración de su realm (del paso 6)
- **KeyCloak Resource** — introduzca la URL del Authorization Endpoint (del paso 7)
- **KeyCloak Group Limiter** — introduzca la URL del Token Endpoint (del paso 7)
- **KeyCloak OAuth Login Button Text** — elija el texto para el botón de inicio de sesión de DefectDojo

Marque **Enable KeyCloak OAuth** y envíe el formulario. Aparecerá un botón de inicio de sesión en la página de inicio de sesión con el texto que haya configurado.
