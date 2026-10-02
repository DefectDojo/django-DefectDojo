---
title: Roles RBAC personalizados
description: Cree sus propios roles eligiendo permisos individuales, utilizando los
  cinco roles integrados como puntos de partida clonables
weight: 5
audience: pro
---

> **Función de DefectDojo Pro.** El sistema RBAC de Members / Groups / Global Roles descrito en esta página forma parte de DefectDojo Pro. La versión de código abierto de DefectDojo utiliza el modelo de [Usuarios autorizados](../os__authorized_users/). Consulte esa página para conocer el control de acceso en la versión de código abierto, y las [notas de actualización a 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) si está migrando entre ediciones.

DefectDojo Pro incluye cinco roles: **Reader**, **Writer**, **Maintainer**, **Owner** y **API Importer**. Si ninguno de ellos se ajusta a sus necesidades, ahora puede crear su propio rol eligiendo exactamente qué permisos otorga.

Un rol personalizado funciona en cualquier lugar donde funcione un rol integrado: como Rol global, como rol de un Grupo, como rol de grupo predeterminado, y como rol de miembro en una Organization o Asset individual.

Los cinco roles integrados se convierten en **ajustes preestablecidos bloqueados y clonables**. Sus permisos no cambian (consulte las [tablas de permisos de acciones](../user_permission_chart/) para ver qué otorga cada uno), no se pueden editar ni eliminar, y clonar uno de ellos es la forma recomendada de crear un nuevo rol.

## Antes de empezar

La gestión de roles personalizados está desactivada de forma predeterminada. Un **superuser** la activa desde **Settings > Feature Flags**, habilitando **Custom Roles**. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/) para saber cómo funciona esa página.

Mientras la función esté desactivada, la página Roles se puede seguir consultando: puede ver los roles integrados y sus permisos, pero no puede crear, editar, clonar ni eliminar nada.

Gestionar roles requiere el estado de **superuser** o el Rol global integrado **Owner**. Esto es intencional y no se puede delegar a un rol personalizado: consulte [Qué desbloquea un Rol global personalizado](#what-a-custom-global-role-unlocks).

## Apertura de la página Roles

Vaya a **👤 Users > Roles** en la barra lateral izquierda. Esta entrada de menú es visible para los superusuarios y para quienes tienen el Rol global integrado Owner.

![La página Roles con la lista de roles integrados y personalizados](images/pro_roles_list.png)

La tabla enumera todos los roles de su instancia:

| Column | What it shows |
| --- | --- |
| **ID** | El id numérico del rol. Útil al filtrar la tabla Users o al llamar a la API. |
| **Name** | El nombre del rol. |
| **Description** | Su propia nota sobre para qué sirve el rol. Es opcional, y queda vacía a menos que alguien la complete. Los roles integrados no incluyen ninguna. |
| **Permissions** | Un conteo de los permisos otorgados. Haga clic para abrir una vista de solo lectura de la cuadrícula completa. |
| **Users** | Cuántos usuarios tienen este rol como su Rol global. Haga clic para verlos en la tabla Users. |
| **Type** | **Built-in** para los cinco ajustes preestablecidos, **Custom** para los roles que usted creó. |

Todas las columnas se pueden ordenar y filtrar, y la búsqueda por palabra clave coincide con el nombre y la descripción.

## Creación de un rol

### Clonar un rol integrado (recomendado)

Clonar le permite partir de un conjunto de permisos ya probado en lugar de una cuadrícula vacía, lo que hace mucho más difícil olvidar por accidente un permiso que el rol necesita.

1. Busque el rol más cercano a lo que necesita.
2. Abra su menú **⋮** y seleccione **Clone Role**.
3. Se crea una copia de inmediato, llamada `<original> (copy)`, con los mismos permisos y la misma descripción que el rol del que proviene.
4. Abra el menú **⋮** de la copia, seleccione **Edit Role**, luego cambie su nombre y ajuste sus permisos.

Los roles integrados se pueden clonar aunque no se puedan editar. El clon registra de qué rol proviene.

### Empezar desde cero

1. Haga clic en **New Role**.
2. Asígnele un **Name** (obligatorio) y, opcionalmente, una **Description**.
3. Elija sus permisos en la cuadrícula a continuación (consulte la siguiente sección).
4. Haga clic en **Save Role**.

Los nombres de los roles deben ser únicos, y la verificación no distingue mayúsculas de minúsculas: si `Triage Lead` ya existe, `triage lead` será rechazado.

## Elección de permisos

![La cuadrícula de permisos en el formulario de rol](images/pro_role_permission_grid.png)

Los permisos se agrupan en tres tablas más una lista de verificación.

**Object Permissions** se aplican a las Organizations y Assets a las que se asigna el rol, y a todo lo anidado dentro de ellas.

| Row | View | Add | Edit | Delete |
| --- | --- | --- | --- | --- |
| Organization | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset | ☑️ | ☑️ ¹ | ☑️ | ☑️ |
| Compromiso | ☑️ | ☑️ | ☑️ | ☑️ |
| Test | ☑️ | ☑️ | ☑️ | ☑️ |
| Hallazgo | ☑️ | ☑️ | ☑️ | ☑️ |
| Grupo de hallazgos | ☑️ | ☑️ | ☑️ | ☑️ |
| Aceptación de riesgo | ☑️ | ☑️ | ☑️ | ☑️ |
| Location | ☑️ | ☑️ | ☑️ | ☑️ |
| Component | ☑️ | | | |
| Nota | ² | ☑️ | ☑️ | ☑️ |
| Benchmark | ² | | ☑️ | ☑️ |
| Language | ☑️ | ☑️ | ☑️ | ☑️ |
| Technology | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset API Scan Configuration | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset Tracking Files | ☑️ | ☑️ | ☑️ | ☑️ |
| Grupo | ☑️ | | ☑️ | ☑️ |

1. **Asset > Añadir** significa crear un nuevo Asset dentro de una Organization a la que está asignado el rol.
2. El permiso Ver para Notas y Benchmarks se hereda: un rol que puede ver el Compromiso, Test, Hallazgo o Asset superior puede ver sus Notas y Benchmarks. Estas celdas muestran un ícono **?** en lugar de una casilla de verificación.

**Group & Member Permissions** controlan quién puede gestionar la membresía. Las columnas aquí son Ver, Gestionar, Añadir, Añadir propietario, Editar y Eliminar.

| Row | Available actions |
| --- | --- |
| Organization Group, Asset Group | Ver, Añadir, Añadir propietario, Editar, Eliminar |
| Organization Member, Asset Member, Group Member | Gestionar, Añadir propietario, Eliminar |

**Global Feature Permissions** controlan el acceso a funciones de Pro a nivel de instancia, en lugar de Organizations o Assets individuales, por lo que **solo tienen efecto cuando el rol se tiene como Rol global**. Otorgarlos a un rol que solo se usa como membresía de Asset no tiene ningún efecto.

| Row | Available actions |
| --- | --- |
| Report Template | Ver, Añadir, Editar, Eliminar |
| Generated Report | Ver, Añadir, Eliminar |
| Connector, Sensei, Asset Hierarchy, Version Manager, Tuner, Universal Parser, Rule, Integration | Ver, Editar |
| Mitigation Policy | Editar |
| Audit Log, Metering | Ver |

**Additional Permissions** es una lista de verificación de capacidades que no encajan en el esquema Ver/Añadir/Editar/Eliminar:

* **Configure Asset Notifications**: elegir qué notificaciones envía un Asset individual, y a dónde.
* **Import Scan Result**: importar y reimportar resultados de escaneo, creando y actualizando hallazgos.
* **Share Dashboard Layout**: publicar un diseño de panel para otros usuarios. Solo Rol global.
* **Share Table Preference**: publicar una vista de tabla guardada (columnas, filtros, orden). Solo Rol global.
* **View Note History**: ver quién cambió una nota y cuándo.

### Cómo interpretar la cuadrícula

![La vista de solo lectura de los permisos de un rol](images/pro_role_permissions_modal.png)

| What you see | What it means |
| --- | --- |
| Una casilla de verificación vacía | El permiso existe y no está otorgado. Haga clic para otorgarlo. |
| Una casilla de verificación marcada | Otorgado. |
| Una celda vacía y sombreada | El permiso no existe para esa fila y acción. No se puede seleccionar. |
| Un ícono **?** | El permiso Ver se hereda de un objeto superior, por lo que no hay nada que otorgar aquí. |
| Un ✔ verde (vista de solo lectura) | Otorgado. |
| Una ✘ roja (vista de solo lectura) | No otorgado. |

En cada fila, el permiso situado más a la izquierda (**Ver**, o **Gestionar** en las filas de miembros) condiciona el resto de la fila. Debe otorgarlo antes de que las demás celdas de esa fila estén disponibles, porque un rol no puede editar ni eliminar de forma significativa lo que no puede ver. Al revocar ese permiso se revoca también el resto de la fila.

## Edición, clonación y eliminación

El menú **⋮** de cada fila ofrece **Edit Role**, **Clone Role**, **Delete Role** y **Role History**.

Los roles integrados solo ofrecen **Clone Role**. Nadie puede editarlos ni eliminarlos, ni siquiera los superusuarios. Esto mantiene una base de referencia conocida y hace que las actualizaciones sean predecibles.

Eliminar un rol que todavía esté asignado a alguien fallará. Primero reasigne o elimine esas asignaciones, y luego elimine el rol. Las asignaciones que cuentan para este propósito son las membresías de Organization y Asset (tanto de usuario como de grupo), los Roles globales, las membresías de Grupo y el rol de grupo predeterminado en System Settings.

La API puede hacer la reasignación por usted en una sola llamada. Consulte [Gestión de roles a través de la API](#managing-roles-through-the-api).

## Asignación de un rol personalizado

Los roles personalizados aparecen en todos los menús desplegables de roles, junto con los integrados:

| Where | How |
| --- | --- |
| **Rol global en un usuario** | El campo **Global Role** en el formulario del usuario. Solo superusuarios. Consulte [Establecer los permisos de un Usuario](../set_user_permissions/). |
| **Rol global en un grupo** | El campo **Global Role** en el formulario del grupo. Consulte [Compartir permisos: grupos de usuarios](../create_user_group/). |
| **Membresía de Organization o Asset** | El diálogo Permissions en la Organization o el Asset, tanto para usuarios como para grupos. Consulte [Establecer permisos en Pro](../pro_permissions_overhaul/). |
| **Rol de grupo predeterminado** | **Default group role** en System Settings, aplicado a los usuarios recién creados. Consulte [Gestionar los permisos predeterminados](../about_perms_and_roles/#manage-default-permissions). |
| **Rol dentro de un grupo** | El menú desplegable de roles en la lista de miembros de un grupo. Este menú solo ofrece roles que otorgan al menos un permiso de Group, por lo que un rol sin permisos de Group no aparecerá allí. |

Vale la pena conocer dos restricciones:

* **El nivel Owner está reservado.** Un rol personalizado nunca puede ser un rol de nivel Owner. Solo el Owner integrado lo es, por lo que solo él conlleva el poder implícito de gestionar a otros Owners.
* **Otorgar el rol Owner a otra persona sigue requiriendo el permiso Add Owner correspondiente**, ya sea que lo haga en una Organization, un Asset o un Group.

## Qué desbloquea un Rol global personalizado

Algunas partes de la interfaz dependen de un Rol global mínimo en lugar de un permiso individual. Para que los roles personalizados funcionen con esas restricciones, DefectDojo clasifica un Rol global personalizado frente a los niveles integrados: un rol personalizado obtiene el nivel más alto cuyos permisos cubre **por completo**.

* Un rol personalizado que cubre todo lo que otorga Maintainer se trata como Maintainer para esas restricciones.
* Cubra todo lo que otorga Writer, y se tratará como Writer. Lo mismo para Reader.
* Si no cubre ninguno de ellos por completo, no obtiene ningún nivel. Sus permisos individuales siguen funcionando exactamente como se otorgaron; solo permanecen cerradas las restricciones de interfaz basadas en niveles.
* **El nivel Owner nunca se puede obtener de esta manera.** La gestión de roles, y todo lo demás que depende del Rol global Owner, permanece reservada a los superusuarios y al Owner integrado.

La cobertura debe ser completa, algo que a veces sorprende. Un rol clonado de Maintainer obtiene el nivel Maintainer. Si reconstruye los permisos de Maintainer a mano y omite uno, el rol termina en el nivel Writer. Si a un Rol global personalizado le falta interfaz que usted esperaba ver, compárelo con el nivel integrado en las [tablas de permisos de acciones](../user_permission_chart/).

## Historial de roles

Los roles personalizados mantienen un registro de auditoría. Abra **Role History** desde el menú **⋮** de un rol para ver qué permisos se otorgaron o revocaron, por quién y cuándo, junto con los cambios en quién tiene el rol.

Hay dos cosas que este historial no muestra: los cambios en el propio nombre y descripción de un rol, y los permisos de los roles integrados (esos se generan de forma predeterminada, nunca se editan, por lo que nunca generan historial).

El historial de roles es una operación de lectura, por lo que está disponible independientemente de que la función Custom Roles esté activada o no.

## Gestión de roles a través de la API

Los roles están disponibles en `/api/v2/roles/`. Las lecturas están abiertas a cualquier usuario autenticado, porque los clientes necesitan la lista de roles para completar los menús desplegables. Las escrituras requieren el estado de superuser o el Rol global integrado Owner, además del feature flag Custom Roles.

| Operation | Request |
| --- | --- |
| List roles | `GET /api/v2/roles/` |
| Retrieve one role | `GET /api/v2/roles/{id}/` |
| List every grantable permission | `GET /api/v2/roles/permissions_catalog/` |
| Create a role | `POST /api/v2/roles/` with `name`, optional `description`, and a `permissions` list |
| Replace a role's permissions | `PATCH /api/v2/roles/{id}/` with a `permissions` list |
| Clone a role | `POST /api/v2/roles/{id}/clone/` with an optional `name` and `description` |
| Delete a role | `DELETE /api/v2/roles/{id}/` |
| Delete a role and move its assignments | `DELETE /api/v2/roles/{id}/?reassign_to={other_role_id}` |
| Read a role's history | `GET /api/v2/roles/{id}/history/` |

Notas:

* `permissions` **reemplaza** la lista de permisos otorgados del rol en lugar de añadirse a ella. Envíe el conjunto completo con el que desea que el rol termine.
* `?reassign_to=` mueve todas las asignaciones del rol eliminado al rol que indique, en una sola transacción. Esta es la única forma de reasignar en bloque: la interfaz no lo ofrece.
* Intentar editar o eliminar un rol integrado devuelve `403`. Editar un valor de permiso desconocido, reutilizar el nombre de un rol existente, o eliminar un rol en uso sin `reassign_to`, devuelve `400` con una explicación.
* `is_owner` no se puede establecer a través de la API. Enviarlo en la solicitud se acepta pero se ignora.

## Aspectos a tener en cuenta

* **Varios roles sobre el mismo objeto otorgan la unión de sus permisos.** Si un usuario tiene un rol directamente en un Asset y hereda otro a través de un grupo, obtiene todo lo que otorga cualquiera de los dos roles. Los roles solo añaden permisos, nunca los quitan.
* **Los cambios de permisos se aplican en la siguiente carga de página**, no de forma instantánea en la vista actual. Los jobs en segundo plano pueden tardar hasta 30 segundos, y los datos de permisos en caché hasta 5 minutos, en reflejar una edición.
* **Los menús desplegables de roles muestran hasta 250 roles.** Más allá de eso, algunos roles no aparecerán en los menús desplegables, aunque seguirán funcionando.
* **Maintainer y Owner pueden añadir Organizations, pero la cuadrícula no lo muestra.** Para esos dos roles, ese permiso se almacena como una concesión de alcance global, y la cuadrícula solo muestra las concesiones de alcance de objeto, por lo que su celda **Organization > Añadir** aparece como no otorgada. Clonar cualquiera de los dos roles conserva ese permiso.
* **La terminología sigue la de su instancia.** Esta documentación usa Organization y Asset, las etiquetas predeterminadas. Si en su instancia se ha desactivado el cambio de nombre de Organization / Asset, las mismas filas se leen como Product Type y Product.
* **La página Roles es de solo lectura para todos los demás.** Un usuario que acceda directamente a `/settings/roles` puede ver los roles y sus permisos, pero no puede cambiar nada. Los datos de permisos no son sensibles, y el servidor aplica el límite real en cada escritura.
