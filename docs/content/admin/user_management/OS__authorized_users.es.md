---
title: Permisos de código abierto
description: Cómo se otorga el acceso a Productos y Tipos de producto en DefectDojo
  de código abierto
weight: 1
audience: opensource
---

DefectDojo de código abierto controla el acceso a Productos y Tipos de producto mediante el modelo de **Usuarios autorizados**. Cada Producto y Tipo de producto tiene un panel de Usuarios autorizados que enumera a las personas que pueden ver ese registro y los datos anidados debajo de él.

Si utiliza DefectDojo Pro, este artículo no se aplica a su instalación — Pro usa un sistema basado en roles más completo, descrito en [Permisos en DefectDojo](../about_perms_and_roles/).

## Cómo se otorga el acceso

Hay dos listas, y un usuario solo necesita aparecer en una de ellas para obtener acceso:

- **La lista de Usuarios autorizados de un Producto** otorga acceso a ese Producto individual, además de todo lo anidado debajo de él (sus Compromisos, Tests, Hallazgos y Endpoints).
- **La lista de Usuarios autorizados de un Tipo de producto** otorga acceso al Tipo de producto en sí **y se propaga en cascada a todos los Productos que están debajo de él**. Un usuario autorizado en un Tipo de producto no necesita además ser agregado a cada Producto hijo — ya está cubierto.

No hay roles, ni grupos, ni roles globales. Un usuario está en la lista (o es superusuario/miembro del staff — ver más abajo), o no puede ver el Producto.

## Los superusuarios y el staff omiten las listas

Los usuarios marcados como **superusuario** o **staff** en DefectDojo pueden ver y actuar sobre todos los Productos y Tipos de producto, independientemente de las listas de Usuarios autorizados. Las listas existen para otorgar acceso a usuarios que no son del staff; no restringen al staff ni a los superusuarios.

La primera cuenta creada en una instalación nueva de DefectDojo es automáticamente superusuario.

## Quién puede editar las listas

Solo los usuarios **superusuario** o **staff** ven los controles para agregar o quitar personas de un panel de Usuarios autorizados. Todos los demás que tengan acceso a un Producto o Tipo de producto ven el panel como una lista de solo lectura — útil para saber quién más está en el equipo, pero no para cambiar la membresía.

## Dónde se encuentra el panel

El panel de Usuarios autorizados aparece en dos páginas de la interfaz clásica:

- La **página de detalle del Producto** tiene un panel de Usuarios autorizados para ese Producto. Admite dos acciones para los usuarios del staff:
  - **Agregar un usuario a la lista de Usuarios autorizados del Producto**
  - **Quitar un usuario de la lista de Usuarios autorizados del Producto**
- La **página de detalle del Tipo de producto** tiene un panel de Usuarios autorizados para ese Tipo de producto, con las dos acciones correspondientes:
  - **Agregar un usuario a la lista de Usuarios autorizados del Tipo de producto**
  - **Quitar un usuario de la lista de Usuarios autorizados del Tipo de producto**

Cuando quita a un usuario de la lista de un Tipo de producto, la cascada también se elimina — pierde el acceso a todos los Productos hijos, a menos que siga en la lista de un Producto específico, o sea staff/superusuario.

## Cómo elegir entre acceso a nivel de Producto o de Tipo de producto

Algunas reglas prácticas:

- Si una persona debe ver todos los Productos de una categoría (por ejemplo, todos los Productos que pertenecen a un equipo determinado), agréguela a la lista del **Tipo de producto** y deje que la cascada se encargue del resto.
- Si una persona solo debe ver un Producto específico, agréguela a la lista de ese **Producto**.
- Si se encuentra agregando a la misma persona a muchos Productos individuales dentro de un mismo Tipo de producto, es una señal de que debería agregarla al Tipo de producto en su lugar.

## Si viene de una versión anterior de DefectDojo

DefectDojo de código abierto volvió al modelo de Usuarios autorizados en la versión 3.0. Si está actualizando desde una versión que tenía el sistema de Miembros / Grupos / Roles globales, la actualización traslada automáticamente su acceso existente a Usuarios autorizados — no se necesita ningún mapeo manual.

La actualización incluye un comando de administración de solo lectura, `preview_legacy_authorization_migration`, que resume lo que cambiaría una actualización sobre una copia de su base de datos. El flujo de trabajo recomendado es instalar 3.0 en un entorno de staging con una instantánea de producción, ejecutar el comando, revisar el resumen y luego actualizar producción.

Si se mueve en la dirección contraria — de código abierto a DefectDojo Pro — Pro incluye un comando `reconcile_authorized_users_to_rbac` que traslada el acceso de Usuarios autorizados al RBAC de Pro. Admite `--dry-run` y es idempotente.

Para más detalle sobre ambos caminos, consulte las [notas de actualización de la 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization).
