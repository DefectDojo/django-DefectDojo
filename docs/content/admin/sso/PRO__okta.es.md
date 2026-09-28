---
title: Okta
description: Configura el SSO de Okta en DefectDojo Pro
weight: 15
audience: pro
---

DefectDojo Pro admite el inicio de sesión mediante Okta. DefectDojo de código abierto no incluye SSO — consulte [Usuarios autorizados](/admin/user_management/os__authorized_users/) para conocer el control de acceso en código abierto.

## Requisitos previos

Complete los siguientes pasos en Okta antes de configurar DefectDojo:

1. Inicie sesión o cree una cuenta en [Okta](https://www.okta.com/developer/signup/).

2. Vaya a **Applications** y haga clic en **Add Application**.

   ![image](images/okta_1.png)

3. Seleccione **Web Applications**.

   ![image](images/okta_2.png)

4. En **Login Redirect URLs**, agregue la URL de retorno (callback) de su DefectDojo. Marque también la casilla **Implicit**.

   ![image](images/okta_3.png)

5. Haga clic en **Done**.

6. En el **Dashboard**, anote la **Org-URL**.

   ![image](images/okta_4.png)

7. Abra la aplicación recién creada y anote el **Client ID** y el **Client Secret**.

   ![image](images/okta_5.png)

## Configuración

En DefectDojo, vaya a **Enterprise Settings > OAuth Settings**, seleccione **Okta** y complete el formulario:

- **Okta OAuth Key** — ingrese su **Client ID**
- **Okta OAuth Secret** — ingrese su **Client Secret**
- **Okta Tenant ID** — ingrese su Org-URL con el formato `https://your-org-url/oauth2`

Marque **Enable Okta OAuth** y envíe el formulario. Aparecerá un botón **Login With Okta** en la página de inicio de sesión.
