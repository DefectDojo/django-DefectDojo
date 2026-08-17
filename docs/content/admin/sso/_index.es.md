---
title: Inicio de sesión único
description: DefectDojo Pro admite SAML y una variedad de proveedores de OAuth para
  el inicio de sesión único
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2026-04-30 00:00:00+00:00
draft: false
weight: 8
collapsed: true
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
pro-feature: true
aliases:
- /es/admin/user_management/configure_sso/
- /es/admin/sso/os__saml/
- /es/admin/sso/os__auth0/
- /es/admin/sso/os__azure_ad/
- /es/admin/sso/os__github_enterprise/
- /es/admin/sso/os__gitlab/
- /es/admin/sso/os__google/
- /es/admin/sso/os__keycloak/
- /es/admin/sso/os__oidc/
- /es/admin/sso/os__okta/
- /es/admin/sso/os__remote_user/
---

El inicio de sesión único es una función de **DefectDojo Pro**. A partir de DefectDojo 3.0, la superficie de SSO — SAML, OIDC y los proveedores de OAuth incluidos — está disponible únicamente en DefectDojo Pro. DefectDojo de código abierto usa el inicio de sesión local con nombre de usuario/contraseña y el flujo de restablecimiento de contraseña.

Si está ejecutando DefectDojo de código abierto y desea SSO, deberá cambiar a [DefectDojo Pro](https://defectdojo.com); la migración se describe en las [notas de actualización de la versión 3.0](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only). Las cuentas de usuario y las membresías de grupo existentes se conservan durante la actualización. Para conocer el control de acceso en DefectDojo de código abierto, consulte la página [Usuarios autorizados](/admin/user_management/os__authorized_users/).

## Ver lo que está configurado

**[Authorization Connectors](/admin/sso/pro__authorization_connectors/)** enumera todos los proveedores compatibles en una sola página — cuáles están configurados, cuáles están habilitados y qué protocolo habla cada uno — y lo lleva directamente al formulario de configuración de cualquiera de ellos. Comience allí si desea conocer el estado de esta instancia en lugar de configurar un proveedor específico.

## Proveedores de SSO compatibles (DefectDojo Pro)

DefectDojo Pro admite SAML y los siguientes proveedores de OAuth. Cada guía explica la configuración del lado del proveedor y la configuración correspondiente en la interfaz de **Enterprise Settings** de Pro.

* **[Auth0](/admin/sso/pro__auth0/)**
* **[Azure Active Directory](/admin/sso/pro__azure_ad/)**
* **[GitHub Enterprise](/admin/sso/pro__github_enterprise/)**
* **[GitLab](/admin/sso/pro__gitlab/)**
* **[Google](/admin/sso/pro__google/)**
* **[KeyCloak](/admin/sso/pro__keycloak/)**
* **[Okta](/admin/sso/pro__okta/)**
* **[OIDC (OpenID Connect)](/admin/sso/pro__oidc/)**
* **[SAML](/admin/sso/pro__saml/)**
* **[LDAP](/admin/sso/pro__ldap/)**

## Aprovisionamiento de usuarios desde su directorio (DefectDojo Pro)

Los proveedores anteriores deciden quién puede iniciar sesión. **[SCIM Provisioning](/admin/sso/pro__scim/)** mantiene la lista de cuentas en sí sincronizada con su directorio, de modo que los usuarios se crean cuando se incorporan, se actualizan cuando cambian sus datos, y se desactivan (junto con sus tokens de API) cuando se van.

La configuración de SSO en DefectDojo Pro solo puede realizarla un **Superusuario**.

**Usuarios de DefectDojo Pro:** agregue las direcciones IP de sus servicios SAML o SSO a la lista blanca del firewall antes de configurar SSO. Consulte [Reglas de firewall](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings) para obtener más información.

## Deshabilitar el inicio de sesión con nombre de usuario/contraseña

Una vez que SSO esté configurado en DefectDojo Pro, es posible que desee deshabilitar el formulario tradicional de inicio de sesión con nombre de usuario/contraseña. Desmarque **Allow Login via Username and Password** en **Enterprise Settings > Login Settings**.

![image](images/pro_login_settings.png)

### Alternativa de inicio de sesión

Si su integración de SSO deja de funcionar, siempre puede volver al formulario de inicio de sesión estándar agregando lo siguiente a la URL de su DefectDojo:

`/login?force_login_form`

Recomendamos mantener al menos una cuenta de administrador con un nombre de usuario y una contraseña configurados como alternativa.
