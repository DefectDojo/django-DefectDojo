---
title: Authorization Connectors
description: 'Vea todos los proveedores de identidad en una sola página: cuáles están
  configurados, cuáles están activados y qué protocolo utiliza cada uno'
weight: 1
audience: pro
---

Authorization Connectors es una única página que enumera todos los proveedores de identidad que admite DefectDojo Pro, en qué estado se encuentra cada uno y qué protocolo utiliza. Antes de que existiera, cada proveedor vivía en su propio formulario de configuración y no había forma de responder a "¿qué está configurado en esta instancia?" sin abrirlos todos.

Authorization Connectors es una función de **DefectDojo Pro**. Encuéntrela en **Connect > Authorization**. Solo un **Superuser** puede ver o cambiar la configuración de los proveedores de identidad.

![Conectores de autorización](images/authorization_connectors.png)

## Cómo está organizada la página

Los proveedores se dividen en dos secciones, y cada sección aparece en orden alfabético con un contador junto a su encabezado:

* **Configured Providers** — proveedores que se han configurado en esta instancia, estén o no activados actualmente.
* **Available Providers** — proveedores que son compatibles pero que aún no se han configurado.

La división se hace deliberadamente según lo *configurado*, no lo *activado*. Un proveedor que se configuró y después se desactivó permanece en Configured Providers, porque ahí es donde lo buscará la persona que lo configuró. Su estado se muestra en la propia tarjeta.

Cada tarjeta muestra:

| | |
| --- | --- |
| **Logotipo y nombre** | El proveedor, indicado sin su protocolo |
| **Etiqueta de protocolo** | `SAML 2.0`, `OAuth 2.0`, `OpenID Connect`, o `LDAP` |
| **Etiqueta de estado** | `Enabled`, `Disabled`, o `Not configured` |
| **Etiqueta `BETA`** | Presente en proveedores que aún están en fase beta |
| **Acción** | **Manage Configuration** para un proveedor configurado, **Configure** para uno disponible |

Ambas secciones tienen un cuadro de búsqueda que coincide con el nombre del proveedor y con el protocolo, de modo que buscar `oauth` reduce la página a los proveedores OAuth.

![Proveedores disponibles](images/authorization_available.png)

## Una configuración por proveedor

La configuración del proveedor de identidad es un único conjunto de valores por proveedor y por instancia — una aplicación de Okta, un proveedor de identidad SAML, un directorio LDAP. Las tarjetas lo indican así, y no existe la opción de "añadir otro": para cambiar cómo está configurado un proveedor, se edita la configuración que ya existe.

Esto es lo que diferencia a Authorization Connectors de las [galerías de conectores](/connectors/upstream/about/), donde una herramienta puede tener muchas configuraciones en paralelo.

## Los tres estados, y qué significan

| Status | Meaning | What to do next |
| --- | --- | --- |
| **Enabled** | Configurado y aceptando inicios de sesión | Nada |
| **Disabled** | Configurado, pero desactivado — su botón no aparecerá en la página de inicio de sesión | Vuelva a activarlo desde su configuración cuando quiera recuperarlo |
| **Not configured** | Compatible, pero aún no se ha rellenado nada | **Configure** para configurarlo |

Al seleccionar un proveedor se abre directamente el propio formulario de configuración de ese proveedor. No hay un selector de proveedores intermedio.

## Proveedores compatibles

| Provider | Protocol | Setup guide |
| --- | --- | --- |
| Auth0 | OAuth 2.0 | [Auth0](/admin/sso/pro__auth0/) |
| GitHub Enterprise | OAuth 2.0 | [GitHub Enterprise](/admin/sso/pro__github_enterprise/) |
| GitLab | OAuth 2.0 | [GitLab](/admin/sso/pro__gitlab/) |
| Google | OAuth 2.0 | [Google](/admin/sso/pro__google/) |
| Keycloak | OAuth 2.0 | [KeyCloak](/admin/sso/pro__keycloak/) |
| LDAP | LDAP | [LDAP](/admin/sso/pro__ldap/) |
| Microsoft Entra ID | OAuth 2.0 | [Azure Active Directory](/admin/sso/pro__azure_ad/) |
| Okta | OAuth 2.0 | [Okta](/admin/sso/pro__okta/) |
| OpenID Connect | OpenID Connect | [OIDC](/admin/sso/pro__oidc/) |
| SAML | SAML 2.0 | [SAML](/admin/sso/pro__saml/) |

La página informa de cuál es el *estado* de configuración de un proveedor. Nunca devuelve los secretos de la configuración — los secretos de cliente, las contraseñas de bind y los certificados no forman parte de los datos que hay detrás de esta página, y no se pueden extraer de ella.

## Cuando un proveedor no se conecta

Authorization Connectors le indica qué está configurado; no le muestra los inicios de sesión fallidos. Estos quedan registrados en [Diagnostics](/admin/diagnostics/pro__diagnostics/), donde SSO, SAML y LDAP informan cada uno de sus propios intentos con el motivo por el que fueron rechazados — una firma de aserción incorrecta, un bind rechazado, un atributo no coincidente. Esas filas son a nivel de instancia y, por tanto, exclusivas para superusuarios.

Mantenga al menos una cuenta de superusuario con nombre de usuario y contraseña como respaldo, y recuerde que `/login?force_login_form` devuelve el formulario de inicio de sesión estándar si un proveedor de identidad deja de funcionar. Consulte [Single Sign-On](/admin/sso/) para ambos casos.

## Relacionado

* [Single Sign-On](/admin/sso/) — las guías de configuración por proveedor y la configuración de inicio de sesión
* [Diagnostics](/admin/diagnostics/pro__diagnostics/) — por qué falló un intento de inicio de sesión
* [Connectors](/connectors/upstream/about/) — la galería de conectores upstream en la que se basa esta página
