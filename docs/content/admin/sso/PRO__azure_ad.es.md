---
title: Azure Active Directory
description: Configure el SSO de Azure AD y la asignación de grupos en DefectDojo
  Pro
weight: 5
audience: pro
---

DefectDojo Pro admite el inicio de sesión mediante Azure Active Directory (Azure AD), incluida la sincronización automática de Grupos de usuarios. DefectDojo de código abierto no incluye SSO — consulte [Authorized Users](/admin/user_management/os__authorized_users/) para el control de acceso de código abierto.

## Requisitos previos

Complete los siguientes pasos en el portal de Azure antes de configurar DefectDojo:

1. [Registre una nueva aplicación](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) en Azure Active Directory.

2. Anote los siguientes valores de la aplicación registrada:
   - **Application (client) ID**
   - **Directory (tenant) ID**
   - En **Certificates & Secrets**, cree un nuevo **Client Secret** y anote su valor
   - **Application ID URI**

3. En **Authentication > Redirect URIs**, añada un URI de tipo **Web**:
   `https://your-instance.cloud.defectdojo.com/complete/azuread-tenant-oauth2/`

## Configuración

En DefectDojo, vaya a **Enterprise Settings > OAuth Settings**, seleccione **Azure AD** y complete el formulario:

- **Azure AD OAuth Key** — introduzca su **Application (client) ID**
- **Azure AD OAuth Secret** — introduzca su **Client Secret**
- **Azure AD Resource** — el valor predeterminado es `https://graph.microsoft.com/`. Este es el URI que utiliza DefectDojo para leer información adicional (como los nombres de grupo) de la [Microsoft Graph Web API](https://docs.azure.cn/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-id-uri). Cambie esto solo si los nombres de sus grupos se almacenan en un recurso de API diferente.
- **Azure AD Tenant ID** — introduzca su **Directory (tenant) ID**
- **Azure AD Groups Filter** — opcionalmente, introduzca una expresión regular para restringir qué Grupos de usuarios se importan (consulte [Group Mapping](#group-mapping) más abajo)

Marque **Enable Azure AD OAuth** y envíe el formulario. Aparecerá un botón **Login With Azure AD** en la página de inicio de sesión.

## Group Mapping

La asignación de grupos permite que DefectDojo importe la pertenencia a [User Group](../../user_management/create_user_group/) desde Azure AD. Los Grupos de usuarios en DefectDojo rigen el acceso a productos y tipos de producto mediante [RBAC](../../user_management/set_user_permissions/).

Marque **Enable Azure AD OAuth Grouping** para activar esta función. Al iniciar sesión, DefectDojo hará coincidir los grupos de Azure AD del usuario con los grupos existentes en DefectDojo. Cualquier grupo que no se encuentre en DefectDojo se creará automáticamente.

Para importar solo un subconjunto de grupos, introduzca una expresión regular en el campo **Azure AD Groups Filter**. Por ejemplo:
- `^team-.*` — coincide con cualquier grupo que empiece por `team-`
- `teamA|teamB|groupC` — coincide con grupos concretos por nombre

### Configurar Azure AD para enviar grupos

El token de Azure AD debe configurarse para incluir los ID de grupo. Sin esto, no habrá información de grupo presente en el token.

Para configurarlo:
1. Añada un [Group Claim](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims) en la configuración del token de Azure AD. Si no está seguro de qué tipo de grupo seleccionar, elija **All Groups**.
2. **No** habilite **Emit groups as role claims**.
3. Actualice los permisos de la API de la aplicación para incluir `GroupMember.Read.All` o `Group.Read.All`. Se recomienda `GroupMember.Read.All`, ya que concede menos permisos.

### Limpieza de grupos

Si **Enable Azure AD OAuth Group Cleaning** está habilitado, los grupos de DefectDojo creados mediante la sincronización de Azure AD se eliminarán automáticamente cuando no les queden miembros. Cuando se elimina a un usuario de un grupo en Azure AD, también se le elimina del grupo correspondiente en DefectDojo.
