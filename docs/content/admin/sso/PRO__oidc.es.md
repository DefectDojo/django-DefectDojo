---
title: OIDC
description: Configura el inicio de sesión único (SSO) mediante OpenID Connect (OIDC)
  en DefectDojo Pro
weight: 17
audience: pro
---

DefectDojo Pro admite el inicio de sesión mediante un proveedor genérico de OpenID Connect (OIDC). DefectDojo de código abierto no incluye SSO — consulte [Usuarios autorizados](/admin/user_management/os__authorized_users/) para conocer el control de acceso en código abierto.

## Configuración

En DefectDojo, vaya a **Enterprise Settings > OIDC Settings**.

![image](images/oidc_pro.png)

Complete el formulario:

1. **Endpoint** — la URL base de su proveedor de OIDC. No incluya `/.well-known/openid-configuration`.
2. **Client ID** — el ID de cliente de su OIDC.
3. **Client Secret** — el secreto de cliente de su OIDC.
4. Opcionalmente, configure **Claim Mapping** y **Group Mapping** — consulte a continuación.
5. Marque **Enable OIDC**.

Envíe el formulario. Aparecerá un botón **Log In With OIDC** en la página de inicio de sesión de DefectDojo.

Use **Validate Config** en cualquier momento para comprobar la configuración sin guardarla. Obtiene el documento de descubrimiento, verifica las claves de firma y el emisor, muestra el URI de redirección exacto que debe registrarse en su proveedor, y contrasta sus asignaciones de notificaciones y de grupos con las notificaciones que anuncia el proveedor.

## Asignación de notificaciones

Cada fila asigna una **OIDC Claim** al **DefectDojo Field** que debe completar. Use **Add Claim Mapping** para agregar más filas y el icono de papelera para eliminar una.

![image](images/sso_oidc_claim_mapping.png)

Un campo sin fila conserva su notificación estándar, por lo que esta sección solo es necesaria cuando su proveedor nombra las cosas de forma diferente. Las notificaciones estándar son:

| DefectDojo Field | Standard claim |
| --- | --- |
| Nombre de usuario | `preferred_username` |
| Correo electrónico | `email` |
| Nombre | `given_name` |
| Apellido | `family_name` |

Notas:

- Una instancia sin configurar se abre con esas cuatro filas ya completadas, para que pueda ver qué hace OIDC antes de cambiar nada.
- La misma notificación puede alimentar más de un campo. Cada campo de DefectDojo solo puede asignarse desde una notificación.
- Las notificaciones se leen tanto del token de ID como de la respuesta de userinfo, por lo que una notificación que su proveedor solo entrega en una de las dos sigue funcionando.
- Si a una notificación asignada le falta valor o está vacía para un usuario determinado, ese campo conserva su valor estándar en lugar de quedar en blanco.

## Asignación de grupos

DefectDojo puede reflejar los grupos que reporta su proveedor en grupos de DefectDojo en cada inicio de sesión. Marque **Enable Group Mapping** para mostrar la configuración.

![image](images/sso_oidc_group_mapping.png)

- **Group Claim Name** — la notificación que contiene los grupos del usuario. **La mayoría de los proveedores no emiten una por defecto** y necesitan un mapper configurado explícitamente; en Keycloak, por ejemplo, agregue un mapper de *Group Membership* al cliente. Tenga en cuenta que un mapper de *User Realm Role* envía **roles** del realm, no grupos.
- **Group Limiter Regex Expression** — solo se reflejan los grupos que coinciden con esta expresión. Use `.*` para permitir todos.
- **Remove Stale Group Memberships** — cuando está habilitado, las membresías en grupos aprovisionados por OIDC que el proveedor ya no reporta se eliminan en el siguiente inicio de sesión. Solo se ven afectados los grupos creados por OIDC; los grupos que usted asignó manualmente, y los grupos aprovisionados por otro proveedor como SAML, nunca se modifican.

Los grupos se crean en el primer uso y se nombran exactamente como los reporta el proveedor. Si su proveedor envía rutas de grupo completas (el mapper *Group Membership* de Keycloak hace esto cuando **Full group path** está habilitado), el grupo de DefectDojo se llama `/Group A` en lugar de `Group A`. Desactive esa opción si desea que los nombres coincidan con los grupos que llegan de otro proveedor; de lo contrario, terminará con dos grupos de DefectDojo para el mismo grupo lógico.

Si la asignación de grupos parece no hacer nada, ejecute **Validate Config**: indica si la notificación que usted indicó es una de las que anuncia el proveedor.
