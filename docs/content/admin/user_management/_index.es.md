---
title: Gestión de usuarios
description: Gestione usuarios, control de acceso y autenticación en DefectDojo
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 5
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

La superficie de gestión de usuarios de DefectDojo difiere según la edición. Elija la sección que corresponda a su instalación.

## DefectDojo de código abierto

DefectDojo de código abierto usa el modelo de **Usuarios Autorizados**: se otorga acceso a un usuario a un Producto o un Tipo de Producto al agregarlo a la lista de Usuarios Autorizados de ese registro. Los Superusuarios y el personal pueden ver todo.

* [Usuarios Autorizados](./os__authorized_users/) — cómo otorgar acceso a Productos y Tipos de Producto

La autenticación en DefectDojo de código abierto se basa en usuario/contraseña local, junto con el flujo de restablecimiento de contraseña.

## DefectDojo Pro

DefectDojo Pro usa un sistema basado en roles con Miembros, Grupos y Roles Globales. Los usuarios también pueden recibir acceso SSO mediante SAML o uno de los proveedores de OAuth compatibles.

* [Permisos en DefectDojo](./about_perms_and_roles/) — resumen de Roles, Membresías, Roles Globales y Permisos de Configuración
* [Establecer los permisos de un usuario](./set_user_permissions/) — asignación de Roles, Roles Globales y Permisos de Configuración
* [Compartir permisos: Grupos de usuarios](./create_user_group/) — asignar permisos a muchos usuarios a la vez
* [Establecer permisos en Pro](./pro_permissions_overhaul/) — interfaz específica de Pro para gestionar Miembros y Permisos
* [Restablecimiento masivo de credenciales de usuario](./pro__resetting_user_credentials/) — rotar tokens de API y forzar el restablecimiento de contraseña de muchos usuarios a la vez
* [Tablas de permisos por acción](./user_permission_chart/) — referencia completa de cada permiso para cada Rol integrado
* [Roles RBAC personalizados](./pro__custom_rbac_roles/) — cree sus propios roles eligiendo permisos individuales
* [Inicio de sesión único](/admin/sso/) — configuración de SAML y OAuth para Pro

## Migración entre ediciones

Si está pasando de los Usuarios Autorizados de código abierto al RBAC de Pro, o si está actualizando desde una versión de código abierto anterior a la 3.0 que usaba RBAC hacia el modelo actual de Usuarios Autorizados, consulte las [notas de actualización de la versión 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization). El acceso existente se conserva automáticamente.
