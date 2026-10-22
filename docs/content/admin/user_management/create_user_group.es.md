---
title: 'Compartir permisos: Grupos de usuarios'
description: Comparta y mantenga permisos para muchos usuarios en DefectDojo Pro
weight: 3
audience: pro
aliases:
- /es/en/customize_dojo/user_management/create_user_group
---

> **Función de DefectDojo Pro.** Los Grupos de Usuarios y el sistema RBAC subyacente forman parte de DefectDojo Pro. DefectDojo de código abierto usa el modelo de [Usuarios Autorizados](../os__authorized_users/); consulte esa página para conocer el control de acceso de código abierto, y las [notas de actualización de la versión 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) si está migrando entre ediciones.

Si tiene una cantidad significativa de usuarios de DefectDojo, es posible que desee crear uno o más **Grupos**, con el fin de establecer las mismas reglas de Control de Acceso Basado en Roles (RBAC) para muchos usuarios simultáneamente. Solo los Superusuarios pueden crear Grupos de Usuarios.

Los Grupos pueden funcionar de varias formas:

* Establecer uno o varios Roles a nivel de Producto o Tipo de Producto para todos los Miembros del Grupo, lo que permite un control específico sobre qué Productos o Tipos de Producto puede acceder y editar el Grupo.
* Establecer un Rol Global para todos los Miembros del Grupo, otorgándoles visibilidad y acceso a todos los Productos o Tipos de Producto.
* Establecer Permisos de Configuración para un Grupo, permitiéndoles cambiar funcionalidades específicas de DefectDojo.

Para obtener más información sobre los Roles, consulte nuestro artículo **Introducción a los Roles**.

## La página Todos los Grupos

Desde la barra lateral, navegue a 👤**Usuarios > Grupos** para ver una lista de todos los grupos de usuarios activos e inactivos.

![image](images/Create_a_User_Group_for_shared_permissions.png)
Desde aquí, puede crear, eliminar o ver sus páginas de Grupo individuales.

Para los usuarios de <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>, la página Todos los Grupos de la interfaz Pro cuenta con algunas opciones adicionales.
* Puede filtrar esta tabla por Nombre de Grupo, Descripción, Dirección de correo electrónico, Rol Global, así como por el número total de Usuarios, Tipos de Producto y Productos asociados al Grupo.
* También puede ajustar los Permisos u otras configuraciones de un Grupo haciendo clic en el botón "⋮" junto al Grupo que desea editar.

![image](images/all_groups_pro.png)

## Ver un Grupo

Al ver un grupo se muestra toda la información del Grupo, como ID, nombre, descripción, rol global, etc. También se muestran los Miembros del Grupo, los Tipos de Producto y los Productos asociados al grupo. Además, los permisos de configuración vinculados a un Grupo pueden actualizarse directamente desde la página "Ver Grupo".

Para los usuarios de <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>, la vista de Grupo de la interfaz Pro permite asignar ajustes de Permisos de Configuración de una forma ligeramente distinta.

![image](images/group_view_pro_ui.png)

* Todos los permisos de configuración se muestran en un menú desplegable agrupado en subcategorías. Si la selección de permisos de configuración difiere de su valor actual, se muestra un botón "Actualizar Permisos de Configuración".

![image](images/groups_pro_configuration_permissions.png)

* Una vez seleccionados algunos permisos adicionales, se le pedirá al usuario que confirme si desea actualizar los permisos del grupo seleccionado antes de realizar la actualización.

## Crear/Editar un Grupo de Usuarios

1. Navegue a la página 👤**Usuarios > Grupos** en la barra lateral. Verá una lista de todos los Grupos de Usuarios existentes, incluyendo su Nombre, Descripción, Número de Usuarios, Rol Global (si corresponde) y Correo electrónico.

![image](images/Create_a_User_Group_for_shared_permissions_2.png)

2. Haga clic en el **botón 🛠️** junto al encabezado Todos los Grupos, y seleccione **+ Nuevo Grupo.**

![image](images/Create_a_User_Group_for_shared_permissions_3.png)

3. Esto lo llevará a una página donde puede crear un nuevo Grupo. Establezca el Nombre de este Grupo y agregue una Descripción si lo desea.

También puede seleccionar un Rol Global que desee aplicar a este Grupo, si lo desea. Agregar un Rol Global al Grupo otorgará a todos los Miembros del Grupo acceso a todos los datos de DefectDojo, junto con una cantidad limitada de acceso de edición según el Rol Global que elija. Consulte nuestro artículo **Introducción a los Roles** para obtener más información.

La cuenta que crea inicialmente un Grupo tendrá, por defecto, el Rol Owner para ese Grupo.

### Establecer una dirección de correo electrónico para recibir informes

El Resumen Semanal es un informe sobre todos los Productos / Tipos de Producto asignados al Grupo. Para que se envíe un Resumen semanal, ingrese la dirección de correo electrónico de destino que desea usar en el formulario Crear/Editar Grupo. Los miembros del Grupo seguirán recibiendo notificaciones como de costumbre.

### Ver una página de Grupo

Una vez que haya creado un Grupo, puede acceder a él seleccionándolo en el menú que se encuentra en **Usuarios > Grupos.**

La página del Grupo puede personalizarse con una **Descripción**. Incluye una lista de todos los **Miembros del Grupo**, así como los **Productos y Tipos de Producto** asignados, y el **Rol** asociado a cada uno de ellos.

Aquí también puede ver los **Permisos de Configuración** del Grupo.

## Gestionar los Usuarios de un Grupo

La Membresía del Grupo se gestiona desde la página individual del Grupo, que puede seleccionar en la lista de la página **Usuarios > Grupos**. Haga clic en el Nombre del Grupo resaltado para acceder a la página del Grupo que desea editar.

Para ver o editar la Membresía de un Grupo, un Usuario debe tener habilitados los permisos de Configuración correspondientes, además de ser Miembro del Grupo (o tener estado de Superusuario).

### **Agregar un Usuario a un Grupo**

Los Grupos de Usuarios pueden tener tantos Usuarios asignados como desee. Todos los Usuarios de un Grupo recibirán el Rol asociado en cada Producto o Tipo de Producto listado, pero los Usuarios también pueden tener Roles Individuales que prevalecen sobre el rol del Grupo.

1. Desde la página del Grupo, seleccione **+ Agregar Usuarios** en el botón **☰** ubicado en el extremo del encabezado **Miembros**.

![image](images/Create_a_User_Group_for_shared_permissions_4.png)

2. Esto lo llevará a la pantalla **Agregar algunos Miembros del Grupo**. Abra el menú desplegable de Usuarios y marque cada usuario que desee agregar al Grupo.

![image](images/Create_a_User_Group_for_shared_permissions_5.png)

3. Seleccione el Rol de Grupo que desea asignar a estos Usuarios. Esto determina su capacidad para configurar el Grupo.

Tenga en cuenta que agregar un miembro a un Grupo no le otorgará, por defecto, acceso a su propia página de Grupo. Se trata de un permiso de Configuración independiente que debe habilitarse primero.

### **Editar o Eliminar un Miembro de un Grupo de Usuarios**

1. Desde la página del Grupo, seleccione el ⋮ junto al Nombre del Usuario que desea Editar o Eliminar del Grupo.

**📝 Edit** lo llevará a la pantalla Editar Miembro, donde puede cambiar el Rol de este usuario (de Reader, Maintainer u Owner a otra opción).

**🗑️ Delete** elimina por completo la Membresía de un Usuario. No eliminará ninguna contribución ni cambio que el Usuario haya realizado en el Producto o Tipo de Producto.

![image](images/Create_a_User_Group_for_shared_permissions_6.png)

## Gestionar los Permisos de un Grupo

Los Permisos del Grupo se gestionan desde la página individual del Grupo, que puede seleccionar en la lista de la página **Usuarios > Grupos**. Haga clic en el Nombre del Grupo resaltado para acceder a la página del Grupo que desea editar.

Tenga en cuenta que solo los Superusuarios pueden editar los permisos de un Grupo (de Producto / Tipo de Producto, o de Configuración).

### **Agregar Roles de Producto o Roles de Tipo de Producto para un Grupo**

Puede registrar tantos Roles de Producto o Roles de Tipo de Producto como desee en cada Grupo.

1. Desde la página del Grupo, seleccione **+ Agregar Tipos de Producto**, o **+ Agregar Producto** en el encabezado correspondiente (Grupos de Tipo de Producto o Grupos de Producto).

![image](images/Create_a_User_Group_for_shared_permissions_7.png)

2. Esto lo llevará a una página **Registrar nuevos Productos / Tipos de Producto**, donde puede seleccionar un Producto o Tipo de Producto para agregar desde el menú desplegable.

![image](images/Create_a_User_Group_for_shared_permissions_8.png)

3. Seleccione el Rol que desea que tengan todos los miembros del Grupo respecto a este Producto o Tipo de Producto en particular.

Los Grupos no pueden asignarse a Productos o Tipos de Producto sin un Rol. Si no está seguro de qué Rol desea que tenga un Grupo, Reader es una buena opción "predeterminada". Esto mantendrá el estado de su Producto seguro hasta que tome la decisión final sobre el Rol del Grupo.

### **Asignar Permisos de Configuración a un Grupo**

Si desea que los Miembros de su Grupo accedan a funciones de Configuración y controlen ciertos aspectos de DefectDojo, puede asignar estas responsabilidades desde la página del Grupo.

Asigne los roles Ver, Agregar, Editar o Eliminar desde el menú en la esquina inferior derecha. Marcar un Permiso de Configuración otorgará de inmediato al Grupo acceso a esa función en particular.

![image](images/Create_a_User_Group_for_shared_permissions_9.png)
