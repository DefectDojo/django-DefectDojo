---
title: Permisos en DefectDojo
description: Resumen detallado de todas las opciones de permisos de DefectDojo Pro
weight: 2
audience: pro
aliases:
- /es/en/customize_dojo/user_management/about_perms_and_roles
---

> **Función de DefectDojo Pro.** El sistema RBAC de Miembros / Grupos / Roles Globales descrito en esta página forma parte de DefectDojo Pro. DefectDojo de código abierto usa el modelo de [Usuarios Autorizados](../os__authorized_users/); consulte esa página para conocer el control de acceso de código abierto, y las [notas de actualización de la versión 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) si está migrando entre ediciones.

Si cuenta con un equipo de usuarios trabajando en DefectDojo, es importante configurar adecuadamente el Control de Acceso Basado en Roles (RBAC) para que los usuarios solo puedan acceder a datos específicos. Los datos de seguridad son muy sensibles, y las opciones de control de acceso de DefectDojo le permiten ser específico sobre el acceso de cada miembro del equipo a la información.

Este artículo ofrece un resumen de cómo funcionan los permisos en DefectDojo. Si prefiere ver un desglose detallado de **cada acción** que puede controlarse mediante Permisos, consulte nuestro artículo **[Tabla de permisos](../user_permission_chart/)**.

## Tipos de permisos

DefectDojo gestiona cuatro tipos diferentes de permisos:

* Los usuarios pueden asignarse como **Miembros** de **Productos o Tipos de Producto**. Una Membresía de Producto viene acompañada de un **Rol** que permite a sus usuarios ver e interactuar con los Tipos de Dato (Tipos de Producto, Productos, Compromisos, Tests y Hallazgos) en DefectDojo. Los usuarios pueden tener varias membresías de Producto o Tipo de Producto, con distintos niveles de acceso.

* Los usuarios también pueden tener asignados **Permisos de Configuración**, que les permiten acceder a las páginas de configuración de DefectDojo. Los Permisos de Configuración no están relacionados con Productos o Tipos de Producto, ni se asocian a Roles.

* A los usuarios se les pueden asignar **Roles Globales**, que les otorgan un nivel de acceso estandarizado a todos los Productos y Tipos de Producto.

* Los usuarios pueden configurarse como **Superusuarios**: roles de nivel administrador que les otorgan control y acceso a todos los datos y la configuración de DefectDojo.

Cada uno de estos tipos de Permisos también puede asignarse a un **Grupo** de **Usuarios**. Si tiene una gran cantidad de usuarios en DefectDojo, como un equipo de testing dedicado a un Producto en particular, los Grupos le permiten configurar y mantener los permisos rápidamente.

## Membresía de Producto/Tipo de Producto y Roles

Cuando los usuarios se asignan como miembros de un Producto o Tipo de Producto, también reciben un rol que controla cómo interactúan con los datos de Hallazgos asociados.

### Resumen de roles

DefectDojo Pro incluye cinco **roles integrados**: Reader, Writer, Maintainer, Owner y API Importer. Cualquiera de ellos puede asignarse de forma global o dentro de un Producto / Tipo de Producto.

Los roles integrados son ajustes preestablecidos y bloqueados. No se pueden editar ni eliminar, y sus permisos son los mismos en todas las instancias de DefectDojo Pro. Si ninguno de ellos se ajusta a la forma de trabajar de su equipo, puede crear un rol que sí lo haga, eligiendo permisos individuales o clonando un rol integrado y ajustándolo. Consulte [Roles RBAC personalizados](../pro__custom_rbac_roles/).

«Datos subyacentes» hace referencia a todos los Productos, Compromisos, Tests, Hallazgos o Endpoints anidados bajo un Producto o Tipo de Producto.

* Los **usuarios Reader** pueden ver los datos subyacentes de cualquier Producto o Tipo de Producto al que estén asignados, y agregar comentarios. No pueden editar, agregar ni modificar de ninguna otra forma los datos subyacentes, pero sí pueden exportar Informes y agregar Notas a los datos.

* Los **usuarios Writer** tienen todas las capacidades de Reader, además de la capacidad de Agregar o Editar Compromisos, Tests y Hallazgos. No pueden agregar nuevos Productos ni Eliminar ningún dato subyacente.

* Los **usuarios Maintainer** tienen todas las capacidades de Writer, además de la capacidad de editar Productos o Tipos de Producto. Pueden agregar nuevos Miembros con Roles al Producto o Tipo de Producto, y también pueden Eliminar Compromisos, Tests y Hallazgos.

* Los **usuarios Owner** tienen el mayor nivel de control sobre un Producto o Tipo de Producto. Pueden designar a otros Owners, y también pueden Eliminar los Productos o Tipos de Producto a los que están asignados.

* Los **usuarios API Importer** tienen capacidades limitadas. Este Rol permite un acceso limitado a la API sin exponer la mayoría de los endpoints de la API, por lo que resulta útil para la automatización o para usuarios que deben ser «externos» a DefectDojo. Pueden ver datos subyacentes, Agregar / Editar Compromisos, e Importar Datos de Escaneo.

Para obtener información detallada sobre los Roles integrados, consulte nuestra **[Tabla de permisos por rol](../user_permission_chart/)**. Para ver la lista completa de permisos que se pueden otorgar a un rol, y cómo crear el suyo propio, consulte **[Roles RBAC personalizados](../pro__custom_rbac_roles/)**.

### Roles Globales

Los usuarios con **Roles Globales** pueden ver e interactuar con cualquier Tipo de Dato (Tipos de Producto, Productos, Compromisos, Tests y Hallazgos) en DefectDojo, según el Rol que tengan asignado.

### Membresías de Grupo

Los Grupos de Usuarios pueden agregarse como Miembros de un Producto o Tipo de Producto. Los usuarios que forman parte del Grupo heredarán el acceso a todos los Productos o Tipos de Producto asociados, y heredarán el Rol asignado al Grupo.

#### Usuarios con varios roles

* Si un Usuario se asigna como miembro de un Producto, no se le otorgan por defecto los permisos asociados del Tipo de Producto.

* Si un Usuario termina teniendo más de un rol en el mismo Producto o Tipo de Producto (por ejemplo, uno asignado directamente y otro heredado de un Grupo), recibe los permisos **combinados** de todos los roles que posee allí.

* El Rol de Producto de un Usuario siempre prevalece sobre su Rol de Tipo de Producto «predeterminado».

* El Rol de Producto / Tipo de Producto de un Usuario siempre prevalece sobre su Rol Global dentro del Producto o Tipo de Producto subyacente. Por ejemplo, si un Usuario tiene un Rol de Tipo de Producto Reader, pero también está asignado como Owner en un Producto anidado bajo ese Tipo de Producto, tendrá permisos adicionales de Owner agregados únicamente para ese Producto.

* Los Roles no pueden quitar permisos, solo pueden agregar otros adicionales. Por ejemplo, si un Usuario tiene un Rol de Tipo de Producto o Rol Global de Owner, asignarle un rol Reader en un Producto en particular no le quitará sus permisos de Owner sobre ese Producto.

* El estado de Superusuario siempre prevalece sobre cualquier Rol asignado.

## Superusuarios

Los Superusuarios (Administradores) no tienen limitaciones en el sistema. Pueden cambiar todas las configuraciones, gestionar usuarios y tienen acceso de lectura / escritura a todos los datos. También pueden cambiar las reglas de acceso de todos los usuarios en DefectDojo. Además, los Superusuarios reciben notificaciones de todos los problemas y alertas del sistema.

De forma predeterminada, la primera cuenta creada en una nueva instancia de DefectDojo tendrá permisos de Superusuario. Ese usuario podrá editar los permisos de todos los usuarios de DefectDojo que se creen posteriormente. Solo un Superusuario existente puede agregar otro superusuario, o agregar un Rol Global a un usuario.


## Permisos de Configuración

Los Permisos de Configuración, aunque similares, no están relacionados con Productos o Roles. Deben asignarse de forma independiente a los Roles. **Los usuarios regulares no tienen ningún Permiso de Configuración de forma predeterminada, y la asignación de estos permisos de configuración debe realizarse con cuidado.**

Los usuarios pueden tener Permisos de Configuración asignados de diferentes formas:

1. Los Permisos de Configuración se pueden asignar directamente a los usuarios. Los permisos específicos pueden configurarse directamente en la página de un Usuario.

2. Los Grupos de Usuarios pueden tener Permisos de Configuración asignados. Al igual que con los Roles, se pueden agregar Permisos de Configuración específicos a los Grupos, lo que otorgará estos permisos a todos los miembros del Grupo.

Los Superusuarios tienen todos los Permisos de Configuración, por lo que no cuentan con una sección de Permisos de Configuración en su página de Usuario.

### Permisos de Configuración de Grupo

Si los usuarios forman parte de un Grupo, también cuentan con Permisos de Configuración de Grupo que controlan su nivel de acceso a la configuración del Grupo. Los Permisos de Grupo no corresponden a la membresía de Producto o Tipo de Producto del Grupo.

Si los usuarios crean un nuevo Grupo, se les otorgará por defecto el rol Owner de ese nuevo Grupo.

Para obtener más información sobre los Permisos de Configuración, consulte nuestra **[Tabla de Permisos de Configuración](../user_permission_chart/#configuration-permission-chart)**.

## Gestionar los permisos predeterminados

Cuando se crea un usuario completamente nuevo en DefectDojo — ya sea manualmente, mediante SAML / SSO, o a través de cualquier proveedor de autenticación social — **no tiene ningún permiso de forma predeterminada**. Al iniciar sesión por primera vez, verá cero Tipos de Producto, cero Productos y cero Compromisos. No podrá ver ni interactuar con ningún dato hasta que un Superusuario le otorgue acceso (directamente, mediante un Rol Global, mediante una membresía de Producto / Tipo de Producto, o agregándolo a un Grupo).

Si desea que todo usuario recién aprovisionado reciba automáticamente un nivel de acceso base — por ejemplo, "todo nuevo usuario SSO debe ser Reader en un grupo en particular" — puede configurar un **Grupo predeterminado** en la página de Configuración del sistema.

1. Abra **⚙️ Configuración → Configuración del sistema** (solo Superusuario).
2. Configure **Grupo predeterminado** con el [Grupo de Usuarios](../create_user_group/) al que deben unirse los usuarios recién creados.
3. Configure **Rol de grupo predeterminado** con el rol que deben tener en ese grupo (por ejemplo, **Reader**).
4. Opcionalmente, configure **Patrón de correo electrónico de grupo predeterminado** con una expresión regular (por ejemplo, `.*@yourcompany\.com$`) para que el grupo predeterminado se aplique solo a los usuarios cuyo correo electrónico coincida.
5. Guarde los cambios.

Tanto **Grupo predeterminado** como **Rol de grupo predeterminado** deben estar configurados; si alguno de los dos está vacío, el grupo predeterminado no se aplicará.

Esta configuración se aplica a todas las vías de creación de usuarios: creación manual, SAML, OAuth y otros proveedores de autenticación social. No se aplica de forma retroactiva: los usuarios existentes conservarán sus membresías de grupo actuales aunque cambie esta configuración más adelante.

Para obtener orientación específica sobre SSO, consulte [Configuración de SAML](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users) o la sección de su proveedor en [Configuración de SSO](../configure_sso/).
