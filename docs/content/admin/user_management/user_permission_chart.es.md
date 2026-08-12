---
title: Cuadros de permisos por acción
description: Todos los permisos de usuario de DefectDojo Pro en detalle
weight: 4
audience: pro
aliases:
- /es/en/customize_dojo/user_management/user_permission_chart
---

> **Función de DefectDojo Pro.** El sistema RBAC de Miembros / Grupos / Roles Globales descrito en esta página forma parte de DefectDojo Pro. DefectDojo de código abierto utiliza el modelo de [Usuarios Autorizados](../os__authorized_users/) — consulte esa página para el control de acceso de código abierto, y las [notas de actualización a 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) si está migrando entre ediciones.

## Cuadro de permisos por Rol

Este cuadro pretende enumerar todos los permisos relacionados con un Producto o Tipo de Producto, así como qué permisos están disponibles para cada rol.

Los cinco roles siguientes son los **roles integrados** de DefectDojo Pro. Son preajustes fijos: sus permisos son los mismos en cada instancia y no se pueden modificar. Si ha creado sus propios roles, este cuadro describe los roles integrados a partir de los cuales se clonaron, no los roles en sí. Para ver el catálogo completo de permisos que se le pueden otorgar a un rol, consulte [Roles RBAC personalizados](../pro__custom_rbac_roles/#choosing-permissions).

| **Sección** | **Permiso** | Reader | Writer | Maintainer | Owner | API Importer |
| --- | --- | --- | --- | --- | --- | --- |
| **Acceso a Producto / Tipo de Producto** | Ver el Producto o Tipo de Producto asignado ¹ | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Ver los Productos, Compromisos, Tests, Hallazgos y Endpoints anidados | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Añadir nuevos Productos (dentro del Tipo de Producto asignado) ² |  |  | ☑️ | ☑️ |  |
|  | Eliminar los Productos o Tipos de Producto asignados |  |  |  | ☑️ |  |
| **Membresía de Producto / Tipo de Producto** | Añadir Usuarios como Miembros (excluyendo el Rol Owner) |  |  | ☑️ | ☑️ |  |
|  | Editar Roles de miembros (excluyendo el Rol Owner) |  |  | ☑️ | ☑️ |  |
|  | Editar Roles de miembros (incluyendo el Rol Owner) |  |  |  | ☑️ |  |
|  | Eliminarse a sí mismo de la membresía de Producto / Tipo de Producto | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Añadir un Rol Owner a otro Usuario |  |  |  | ☑️ |  |
|  | Editar una Membresía de Producto/Tipo de Producto asociada dentro de un Grupo³ |  |  |  | ☑️ |  |
|  | Eliminar una Membresía de Producto/Tipo de Producto asociada dentro de un Grupo³ |  |  |  |  |  |
| **Compromisos** (dentro de un Producto) | Añadir, Editar Compromisos |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Ver Aceptaciones de Riesgo ⁴ |  | ☑️ | ☑️ | ☑️ |  |
|  | Añadir, Editar Aceptaciones de Riesgo |  | ☑️ | ☑️ | ☑️ |  |
|  | Eliminar Compromisos |  |  | ☑️ | ☑️ |  |
| **Tests** (dentro de un Producto) | Añadir Tests |  | ☑️ | ☑️ | ☑️ |  |
|  | Editar Tests |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Eliminar Tests |  |  | ☑️ | ☑️ |  |
| **Hallazgos** (dentro de un Producto) | Añadir Hallazgos |  | ☑️ | ☑️ | ☑️ |  |
|  | Editar Hallazgos |  | ☑️ | ☑️ | ☑️ |  |
|  | Importar, Reimportar Resultados de Escaneo |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Eliminar Hallazgos |  |  | ☑️ | ☑️ |  |
|  | Añadir, Editar, Eliminar Grupos de Hallazgos |  | ☑️ | ☑️ | ☑️ |  |
| **Otros Datos** (dentro de un Producto) | Añadir, Editar Endpoints |  | ☑️ | ☑️ | ☑️ |  |
|  | Eliminar Endpoints |  |  | ☑️ | ☑️ |  |
|  | Editar Benchmarks |  | ☑️ | ☑️ | ☑️ |  |
|  | Eliminar Benchmarks |  |  | ☑️ | ☑️ |  |
|  | Ver el Historial de Notas | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Añadir, Editar, Eliminar Notas propias | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Editar Notas de otros |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Eliminar Notas de otros |  |  | ☑️ | ☑️ |  |

1. Un usuario al que se le asignan permisos únicamente a nivel de Producto no puede ver el Tipo de Producto que lo contiene.
2. Cuando se añade un nuevo Producto bajo un Tipo de Producto, todos los Usuarios a nivel de Tipo de Producto se añadirán como Miembros del nuevo Producto con su Rol de nivel de Tipo de Producto.
3. El usuario que desee realizar cambios en un Grupo también debe tener **Permisos de Configuración de Edición de Grupo**, y un **Rol de Configuración de Grupo de Maintainer u Owner** en el Grupo que desea editar.
4. La visibilidad de las Aceptaciones de Riesgo está controlada por un permiso mínimo distinto al de la visibilidad de Hallazgos: un Reader en el Producto puede ver los Hallazgos subyacentes, pero **no puede** ver las Aceptaciones de Riesgo a las que pertenecen esos Hallazgos. Para más detalles sobre los permisos de Aceptación de Riesgo, el comportamiento de la fecha de expiración y los flujos de reinstauración, consulte [Aceptaciones de Riesgo (Pro)](/triage_findings/findings_workflows/pro__risk_acceptance/#risk-acceptance-permissions-and-visibility).

## Cuadro de Permisos de Configuración

Cada Permiso de Configuración se refiere a una función particular del software, y tiene asociado un conjunto de acciones que un usuario puede realizar relacionadas con esa función.

La mayoría de los Permisos de Configuración dan a los usuarios acceso a determinadas páginas de la interfaz.

| **Permiso de Configuración** | **Ver ☑️** | **Añadir ☑️** | **Editar ☑️** | **Eliminar ☑️** |
| --- | --- | --- | --- | --- |
| Credential Manager | Acceso a la página **⚙️Configuration \> Credential Manager** | Añadir nuevas entradas al Credential Manager | Editar entradas del Credential Manager | Eliminar entradas del Credential Manager |
| Development Environments | n/a | Añadir nuevos Entornos de Desarrollo a la lista 🗓️**Engagements \> Environments** | Editar Entornos de Desarrollo en la lista 🗓️**Engagements \> Environments** | Eliminar Entornos de Desarrollo de la lista **🗓️Engagements \> Environments** |
| Finding Templates¹ | Acceso a la página **Findings \> Finding Templates** | Añadir una Plantilla de Hallazgo | Editar una Plantilla de Hallazgo | Eliminar una Plantilla de Hallazgo |
| Groups | Acceso a la página **👤Users \> Groups** | Añadir un nuevo Grupo de Usuarios | Solo Superusuario | Solo Superusuario |
| Jira Instances | Acceso a la **página ⚙️Configuration \> JIRA** | Añadir una nueva Configuración de JIRA | Editar una Configuración de JIRA existente | Eliminar una Configuración de JIRA |
| Language Types |  |  |  |  |
| Login Banner | n/a | n/a | Editar el banner de inicio de sesión, ubicado en **⚙️Configuration \> Login Banner** | n/a |
| Announcements | n/a | n/a | Configurar los Anuncios, ubicados en **⚙️Configuration \> Announcements** | n/a |
| Note Types | Acceso a la página ⚙️Configuration \> Note Types | Añadir un Tipo de Nota | Editar un Tipo de Nota | Eliminar un Tipo de Nota |
| Prioritization Engines | Acceso a la página de configuración de Prioritization Engine | Añadir un nuevo Prioritization Engine | Editar un Prioritization Engine existente | Eliminar un Prioritization Engine |
| Product Types | n/a | Añadir un nuevo Tipo de Producto (en Products \> Product Type) | n/a | n/a |
| Questionnaires | Acceso a la página **Questionnaires \> All Questionnaires** | Añadir un nuevo Cuestionario | Editar un Cuestionario existente | Eliminar un Cuestionario |
| Questions | Acceso a la página **Questionnaires \> Questions** | Añadir una nueva Pregunta | Editar una Pregunta existente | n/a |
| Regulations | n/a | Añadir una Regulación a la página **⚙️Configuration \> Regulations** | Editar una Regulación existente | Eliminar una Regulación |
| Scheduling Service Schedule | Acceso a la página **Scheduling** | Solo Superusuario | Editar una Programación existente (cambiar el disparador, habilitar/deshabilitar) | Eliminar una Programación |
| SLA Configuration | Acceso a la página **⚙️Configuration \> SLA Configuration** | Añadir una nueva Configuración de SLA | Editar una Configuración de SLA existente | Eliminar una Configuración de SLA |
| Test Types | n/a | Añadir un nuevo Test Type (en **Engagements \> Test Types**) | Editar un Test Type existente | n/a |
| Tool Configuration | Acceso a la página **⚙️Configuration \> Tool Configuration** | Añadir una nueva Configuración de Herramienta | Editar una Configuración de Herramienta existente | Eliminar una Configuración de Herramienta |
| Tool Types | Acceso a la página **⚙️Configuration \> Tool Types** | Añadir un nuevo Tipo de Herramienta | Editar un Tipo de Herramienta existente | Eliminar un Tipo de Herramienta |
| Users | Acceso a la página **👤Users \> Users** | Añadir un nuevo Usuario a DefectDojo | Editar un Usuario existente | Eliminar un Usuario |

1. El acceso a la página Finding Templates también requiere el Rol Global **Writer, Maintainer** u **Owner** para este usuario.

## Permisos de Configuración de Grupo

| Permiso de Configuración | **Reader** | **Maintainer** | **Owner** |
| --- | --- | --- | --- |
| Ver Grupo | ☑️ | ☑️ | ☑️ |
| Eliminarse a sí mismo del Grupo | ☑️ | ☑️ | ☑️ |
| Editar el rol de un Miembro en un Grupo |  | ☑️ | ☑️ |
| Editar o Eliminar una Membresía de Producto o Tipo de Producto de un Grupo¹ |  | ☑️ | ☑️ |
| Cambiar el rol de un Miembro del Grupo a Owner |  |  | ☑️ |
| Eliminar Grupo |  |  | ☑️ |

1. Esto también requiere que el Usuario tenga al menos un Rol de Maintainer en el Producto o Tipo de Producto que desea editar.
