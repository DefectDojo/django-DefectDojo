---
title: Configurar los permisos de un usuario
description: Cómo otorgar Roles y Permisos a un usuario, así como el estado de superusuario
weight: 2
audience: pro
aliases:
- /es/en/customize_dojo/user_management/set_user_permissions
---

> **Función de DefectDojo Pro.** El sistema RBAC de Miembros / Grupos / Roles Globales descrito en esta página forma parte de DefectDojo Pro. DefectDojo de código abierto utiliza el modelo de [Usuarios Autorizados](../os__authorized_users/) — consulte esa página para el control de acceso de código abierto, y las [notas de actualización a 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) si está migrando entre ediciones.

## Introducción a los tipos de permisos

Los usuarios individuales tienen cuatro tipos diferentes de permisos que se les pueden asignar:

* Los usuarios pueden asignarse como **Miembros de Productos o Tipos de Producto**. Esto les permite ver e interactuar con Tipos de Datos (Tipos de Producto, Productos, Compromisos, Tests y Hallazgos) en DefectDojo según el rol que se les asigne en el Producto específico. Los usuarios pueden tener varias membresías de Producto o Tipo de Producto, con distintos niveles de acceso.
​
* Los usuarios también pueden tener asignados **Permisos de Configuración**, que les permiten acceder a páginas de configuración en DefectDojo. Los Permisos de Configuración no están relacionados con Productos ni Tipos de Producto.
​
* A los usuarios se les pueden asignar **Roles Globales**, que les otorgan un nivel de acceso estandarizado a todos los Productos y Tipos de Producto.
​
* Los usuarios pueden configurarse como **Superusuarios**: roles de nivel administrador que les dan control y acceso a todos los datos y la configuración de DefectDojo.

También puede crear Grupos si desea asignar Membresía de Producto, Permisos de Configuración o Roles Globales a un grupo de usuarios al mismo tiempo. Si tiene un gran número de usuarios en DefectDojo, como un equipo de testing dedicado a un Producto en particular, los Grupos pueden ser una función más útil.

## Superusuarios \& Roles Globales

Parte de su configuración de Control de Acceso Basado en Roles (RBAC) puede requerir que cree Superusuarios adicionales, o usuarios con Roles Globales.

* Los Superusuarios (Administradores) no tienen limitaciones en el sistema. Pueden cambiar toda la configuración, gestionar usuarios y tienen acceso de lectura/escritura a todos los datos. También pueden cambiar las reglas de acceso de todos los usuarios en DefectDojo. Los Superusuarios también recibirán notificaciones de todos los problemas y alertas del sistema.
* Los usuarios con Roles Globales pueden ver e interactuar con cualquier Tipo de Dato (Tipos de Producto, Productos, Compromisos, Tests y Hallazgos) en DefectDojo según el Rol que tengan asignado. Para más información sobre cada Rol y los privilegios asociados, consulte nuestro artículo de Introducción a los Roles.
* Los usuarios también pueden tener Permisos de Configuración específicos asignados, lo que les permite acceder a determinadas páginas de configuración de DefectDojo. Por defecto, los usuarios no tienen ningún Permiso de Configuración.

Por defecto, la primera cuenta creada en una nueva instancia de DefectDojo tendrá permisos de Superusuario. Ese usuario podrá editar los permisos de todos los usuarios de DefectDojo que se creen posteriormente. Solo un Superusuario existente puede añadir otro superusuario, o añadir un Rol Global a un usuario.

### Añadir el estado de Superusuario o Rol Global a un usuario existente

1. Vaya a la página 👤 Users \> Users en la barra lateral. Verá una lista de todas las cuentas registradas en DefectDojo, junto con el estado Activo de cada cuenta, sus Roles Globales y otros datos relevantes del Usuario.
​
![image](images/Set_a_User's_Permissions.png)
​
2. Haga clic en el nombre de la cuenta a la que desea otorgar privilegios de Superusuario. Esto le llevará a su página de Usuario.
​
3. En la sección Información Predeterminada de su página de Usuario, abra el menú ☰ y seleccione Editar.
​
![image](images/Set_a_User's_Permissions_2.png)

4. En la página Editar Usuario:
​
Para el Estado de Superusuario, marque la casilla ☑️ Estado de Superusuario, ubicada en la Información Predeterminada del usuario.
​
Para asignar un Rol Global, seleccione uno en el menú desplegable Rol Global, en la parte inferior de la página.
​
![image](images/Set_a_User's_Permissions_3.png)
​
5. Haga clic en Enviar para aceptar estos cambios.

## Membresía de Producto \& Tipo de Producto

Por defecto, ninguna cuenta nueva creada en DefectDojo tendrá permiso para ver ningún Dato de nivel de Producto. Será necesario asignarles membresía a cada Producto que quieran ver y con el que quieran interactuar.

* La membresía de Producto \& Tipo de Producto solo puede configurarla **Superusuarios, Maintainers u Owners**.
* Los **Maintainers \& Owners** solo pueden configurar la membresía en Productos / Tipos de Producto a los que ya estén asignados.
* Los **Global Maintainers \& Owners** pueden configurar la membresía en cualquier Producto o Tipo de Producto, al igual que los **Superusuarios**.

Los usuarios pueden tener dos tipos de membresía simultáneamente a nivel de **Producto**:

* El Rol conferido por su membresía subyacente de Tipo de Producto, si corresponde
* Su Rol específico de Producto, si existe alguno.

Si un usuario ya se ha añadido como miembro de un Tipo de Producto, y no necesita un nivel de permisos adicional en un Producto específico, no es necesario añadirlo como Miembro del Producto.

### Añadir un nuevo Miembro

1. Vaya al Producto o Tipo de Producto al que desea asignar un usuario. Puede seleccionar el Producto de la lista en **Products \> All Products**.

![image](images/Set_a_User's_Permissions_4.png)

2. Localice el encabezado **Members**, haga clic en el menú **☰** y seleccione **\+ Add Users**.
3. Esto le llevará a una página donde puede **registrar nuevos Miembros**. Seleccione un Usuario en el menú desplegable Users.
4. Seleccione el Rol que desea que tenga ese Usuario en este Producto o Tipo de Producto: **API Importer, Reader, Writer, Maintainer** u **Owner.**
​
![image](images/Set_a_User's_Permissions_5.png)

Los usuarios no pueden asignarse como Miembros de un Producto o Tipo de Producto sin tener también un Rol. Si no está seguro de qué Rol desea dar a un nuevo usuario, **Reader** es una buena opción "por defecto". Esto mantendrá el estado de su Producto seguro hasta que tome su decisión final sobre su Rol.

### Editar o eliminar un Miembro

Los Miembros pueden tener su Rol modificado dentro de un Producto o Tipo de Producto.

Dentro de la página de **Producto** o **Tipo de Producto**, vaya al encabezado **Members** y haga clic en el botón **⋮** junto al Usuario que desea Editar o Eliminar.

![image](images/Set_a_User's_Permissions_6.png)

📝 **Edit** le llevará a la pantalla **Edit Member**, donde puede cambiar el **Rol** de este usuario (de **API Importer, Reader, Writer, Maintainer** u **Owner** a otra opción).

🗑️ **Delete** elimina por completo la Membresía de un Usuario. No eliminará ninguna contribución ni cambio que el Usuario haya realizado en el Producto o Tipo de Producto.

* Si no puede Editar ni Eliminar la Membresía de un usuario (el **⋮** no es visible) es porque esta Membresía le fue conferida a nivel de **Tipo de Producto**.
* Un usuario puede tener dos niveles de membresía dentro de un Producto: uno asignado a nivel de **Tipo de Producto** y otro asignado a nivel de **Producto**.

#### Añadir un Rol de Producto adicional a un usuario con un Rol de Tipo de Producto relacionado

Si un Usuario tiene un Rol a nivel de Tipo de Producto, también se le asignará Membresía con ese Rol en todos los Productos subyacentes dentro de esa categoría. Sin embargo, si desea que este Usuario tenga un Rol especial en un Producto específico dentro de ese Tipo de Producto, puede darle un Rol adicional a nivel de Producto.

1. Desde la página del Producto, vaya al encabezado **Members**, haga clic en el menú **☰** y seleccione **\+ Add Users** (como si estuviera añadiendo un nuevo Usuario al Producto).
2. Seleccione el nombre del Usuario en el menú desplegable, y seleccione el Rol de Producto que desea asignar a ese Usuario.

Un Rol de Producto tendrá prioridad sobre el Rol estándar de Tipo de Producto o el Rol Global de un usuario. Por ejemplo, si un Usuario tiene un Rol de Tipo de Producto de **Reader**, pero también está asignado como **Owner** en un Producto anidado bajo ese Tipo de Producto, tendrá permisos adicionales de **Owner** añadidos únicamente para ese Producto.

Sin embargo, esto no funciona a la inversa. Si un Usuario tiene un Rol de Tipo de Producto o Rol Global de **Owner**, asignarle un rol de **Reader** en un Producto en particular no le quitará sus permisos de **Owner**. **Los Roles no pueden quitar permisos otorgados a un Usuario por otros Roles, solo pueden añadir permisos adicionales.**

## Permisos de Configuración

Muchos cuadros de diálogo de configuración y endpoints de la API pueden habilitarse para usuarios o grupos de usuarios, independientemente de su estado de superusuario. Estos Permisos de Configuración permiten a los usuarios habituales acceder y contribuir a partes de DefectDojo fuera de su asignación estándar de Producto o Rol de Producto.

Los Permisos de Configuración no están relacionados con un Producto o Tipo de Producto específico: los usuarios pueden tener permisos de configuración asignados sin necesidad de otros estados o de Membresía de Producto / Tipo de Producto.
​
### Lista de Permisos de Configuración

* **Credential Manager:** Acceso a la página ⚙️Configuration \> Credential Manager
* **Development Environments:** Gestionar la lista Engagements \> Environments
* **Finding Templates:** Acceso a la página Findings \> Finding Templates
* **Groups**: Acceso a la página 👤Users \> Groups
* **Jira Instances:** Acceso a la página ⚙️Configuration \> JIRA
* **Language Types**: Acceso al endpoint de la API [Language Types](/automation/api/languages/)
* **Login Banner**: Editar la página ⚙️Configuration \> Login Banner
* **Announcements**: Acceso a ⚙️Configuration \> Announcements
* **Note Types:** Acceso a la página ⚙️Configuration \> Note Types
* **Product Types:** n/a
* **Questionnaires**: Acceso a la página Questionnaires \> All Questionnaires
* **Questions**: Acceso a la página Questionnaires \> Questions
* **Regulations**: Acceso a la página ⚙️Configuration \> Regulations
* **SLA Configuration:** Acceso a la página ⚙️Configuration \> SLA Configuration
* **Test Types:** Añadir o editar un Test Type (en Engagements \> Test Types)
* **Tool Configuration:** Acceso a la página **⚙️Configuration \> Tool Types**
* **Tool Types:** Acceso a la página ⚙️Configuration \> Tool Types
* **Users:** Acceso a la página 👤Users \> Users

### Añadir Permisos de Configuración a un Usuario

**Solo los Superusuarios pueden añadir Permisos de Configuración a un Usuario**.

1. Vaya a la página 👤 Users \> Users en la barra lateral. Verá una lista de todas las cuentas registradas en DefectDojo, junto con el estado Activo de cada cuenta, sus Roles Globales y otros datos relevantes del Usuario.
​
![image](images/Set_a_User's_Permissions_7.png)

2. Haga clic en el nombre de la cuenta que desea editar.
​
3. Vaya a la Lista de Permisos de Configuración. Se encuentra en el lado derecho de la página del Usuario.
​
4. Seleccione los Permisos de Configuración de Usuario que desea añadir.
​
Para un desglose detallado de los Permisos de Configuración de Usuario, consulte nuestro [Cuadro de Permisos](../user_permission_chart/).
