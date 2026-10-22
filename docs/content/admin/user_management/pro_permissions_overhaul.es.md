---
title: Establecer permisos en Pro
description: Renovación, función de Pro
weight: 3
audience: pro
aliases:
- /es/en/customize_dojo/user_management/pro_permissions_overhaul
---

## Introducción a los Tipos de Permisos

Los usuarios individuales pueden tener asignados cuatro tipos diferentes de permisos:

* Los usuarios pueden asignarse como **Miembros de Productos o Tipos de Producto**. Esto les permite ver e interactuar con los Tipos de Dato (Tipos de Producto, Productos, Compromisos, Tests y Hallazgos) en DefectDojo, según el rol que tengan asignado en el Producto específico. Los usuarios pueden tener varias membresías de Producto o Tipo de Producto, con distintos niveles de acceso.

* Los usuarios también pueden tener asignados **Permisos de Configuración**, que les permiten acceder a las páginas de configuración de DefectDojo. Los Permisos de Configuración no están relacionados con Productos o Tipos de Producto.

* A los usuarios se les pueden asignar **Roles Globales**, que les otorgan un nivel de acceso estandarizado a todos los Productos y Tipos de Producto.

* Los usuarios pueden configurarse como **Superusuarios**: roles de nivel administrador que les otorgan control y acceso a todos los datos y la configuración de DefectDojo.

También puede crear Grupos si desea asignar Membresía de Producto, Permisos de Configuración o Roles Globales a un grupo de usuarios al mismo tiempo. Si tiene una gran cantidad de usuarios en DefectDojo, como un equipo de testing dedicado a un Producto en particular, los Grupos pueden ser una función más útil.

## Superusuarios y Roles Globales

Parte de la configuración de su Control de Acceso Basado en Roles (RBAC) puede requerir que cree Superusuarios adicionales, o usuarios con Roles Globales.

* Los Superusuarios (Administradores) no tienen limitaciones en el sistema. Pueden cambiar todas las configuraciones, gestionar usuarios y tienen acceso de lectura / escritura a todos los datos. También pueden cambiar las reglas de acceso de todos los usuarios en DefectDojo. Además, los Superusuarios reciben notificaciones de todos los problemas y alertas del sistema.
* Los usuarios con Roles Globales pueden ver e interactuar con cualquier Tipo de Dato (Tipos de Producto, Productos, Compromisos, Tests y Hallazgos) en DefectDojo, según el Rol que tengan asignado. Para obtener más información sobre cada Rol y los privilegios asociados, consulte nuestro artículo Introducción a los Roles.
* Los usuarios también pueden tener Permisos de Configuración específicos asignados, lo que les permite acceder a ciertas páginas de configuración de DefectDojo. Los usuarios no tienen Permisos de Configuración de forma predeterminada.

De forma predeterminada, la primera cuenta creada en una nueva instancia de DefectDojo tendrá permisos de Superusuario. Ese usuario podrá editar los permisos de todos los usuarios de DefectDojo que se creen posteriormente. Solo un Superusuario existente puede agregar otro superusuario, o agregar un Rol Global a un usuario.

Los permisos en <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> se han simplificado, para facilitar la asignación de acceso a los objetos. Esta función puede accederse a través de la [interfaz Pro](/get_started/about/ui_pro_vs_os/).

### Abrir la ventana de Permisos

![image](images/pro_permissions.png)

Al ver un Tipo de Producto o Producto, puede abrir la ventana de Permisos para establecer permisos rápidamente. Este menú se encuentra en una Tabla al hacer clic en los puntos horizontales **"⋮"**. Si está viendo una página individual de **Producto** o **Tipo de Producto**, este menú se encuentra bajo el engranaje azul "⚙️".

## Establecer permisos a través de la ventana de permisos

![image](images/pro_permissions_2.png)

1. En la parte superior de esta ventana, puede elegir gestionar los permisos de un usuario individual o de un [grupo de usuarios](../create_user_group).
2. Aquí puede seleccionar un usuario o grupo para agregar al Producto, y seleccionar el [Rol](../about_perms_and_roles) que desea que tenga ese usuario.
3. En la tabla inferior, puede ver una lista de todos los usuarios o grupos que tienen acceso a este objeto. También puede asignar rápidamente un nuevo rol a uno de estos usuarios o grupos desde el menú desplegable.

## Establecer Permisos de Configuración a través de la vista de Usuario

Ahora los permisos de configuración de un usuario pueden establecerse de una forma más sencilla. Desde la Vista de Usuarios, todos los permisos de configuración se muestran en un menú desplegable, agrupados por tipo de permiso. Si la selección de permisos de configuración difiere de su valor actual, se muestra un botón "Actualizar Permisos de Configuración". Al hacer clic en él, se le pedirá al usuario que confirme si desea actualizar los permisos del grupo seleccionado antes de realizar la actualización.

![image](images/pro_user_view.png)
