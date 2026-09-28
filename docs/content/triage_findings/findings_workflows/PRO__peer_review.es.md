---
title: Revisión por pares y reclamo
description: Solicite una revisión a personas específicas, reclame una revisión para
  que los demás sepan que ya se está gestionando, y controle quién puede ser solicitado
audience: pro
weight: 4
---

La revisión por pares le permite pedirle a alguien que examine un Hallazgo antes de cerrarlo. En la interfaz de DefectDojo Pro una revisión también se puede **reclamar**, de modo que, cuando varias personas son elegibles, todos puedan ver quién la ha tomado.

## Solicitar una revisión

Abra un Hallazgo y elija **Solicitar revisión** en el menú del Hallazgo, o seleccione varios Hallazgos en una lista y use el [editor masivo](../pro__bulk_edit_findings/).

Puede solicitar una revisión a usuarios y grupos específicos, o marcar **Permitir revisores elegibles** para solicitarla a todos los que sean elegibles en ese activo.

Solicitar una revisión establece el Hallazgo como **En revisión** y notifica a los revisores.

## Reclamar una revisión

Cuando se ha solicitado una revisión a varias personas, cualquiera de ellas puede tomarla:

* En el Hallazgo, use **Reclamar revisión** en el menú del Hallazgo, o el botón en el banner de revisión.
* El Hallazgo entonces muestra quién tiene la revisión: en el propio Hallazgo, como una columna **Reclamado por** en las listas de Hallazgos, y en la cola de [Mi trabajo](/metrics_reports/dashboards/pro__my_work/) de esa persona.

Una vez que se reclama una revisión:

* Solo la persona que la tiene, quien la solicitó, o un superusuario pueden **Anular revisión**. A los demás revisores elegibles se les informa quién la tiene en su lugar.
* Quien la tiene puede devolverla con **Liberar revisión**, lo que la regresa al grupo sin finalizar la revisión.

Si dos personas la reclaman en el mismo momento, una lo logra y a la otra se le informa quién ganó — la revisión solo puede estar en manos de una persona a la vez.

Los reclamos se resuelven solos en algunas situaciones que, de lo contrario, tendría que gestionar manualmente:

* Anular la revisión marca el reclamo como **completado**.
* Quitar al titular de la lista de revisores, o cerrar o reabrir el Hallazgo, **libera** el reclamo.
* Un trabajo en segundo plano libera los reclamos cuyo titular ya no es un revisor solicitado.

Completado y liberado se registran por separado, de modo que una revisión abandonada se puede distinguir de una finalizada.

El reclamo está controlado por el [indicador de función](/admin/feature_flags/pro__feature_flags/) **Reclamo de revisión**, que está activado de forma predeterminada.

## Controlar quién puede ser solicitado para revisar

"Todos los revisores elegibles" significa todos los que tienen el permiso **Revisar hallazgos** en ese activo — no todos los que pueden editar el Hallazgo.

Esto importa cuando desea una visibilidad amplia pero un grupo reducido de revisores. Dado que **Revisar hallazgos** es un permiso independiente, puede:

1. Crear un rol — por ejemplo, un "Revisor de seguridad" — que otorgue **Revisar hallazgos**.
2. Otorgarlo al pequeño grupo de personas a quienes realmente se debería solicitar.
3. Quitar **Revisar hallazgos** de sus roles más amplios, dejando intacto su acceso a los Hallazgos.

Consulte [Roles RBAC personalizados](/admin/user_management/pro__custom_rbac_roles/) para saber cómo crear un rol.

Al actualizar, todos los roles que ya podían editar Hallazgos también reciben **Revisar hallazgos**, de modo que "todos los revisores elegibles" significa exactamente lo mismo que antes, hasta que usted lo cambie deliberadamente.

## Asignar un Hallazgo a una persona

La revisión le pide a alguien que *observe*. La asignación hace que alguien sea *responsable*, y no pone al Hallazgo en revisión.

**Asignados** aparece junto a **Propietarios** en el formulario de edición del Hallazgo. Propietarios es un grupo — el equipo en cuya cola se encuentra esto — mientras que Asignados son personas individuales.

* Asigne desde el formulario de edición del Hallazgo, o a muchos Hallazgos a la vez desde el editor masivo.
* En el editor masivo, los asignados se **agregan** a quienes ya estén asignados. Marque **Reemplazar asignados existentes** para que su selección sea la lista completa — lo que elimina a cualquiera que no esté seleccionado, incluyendo a todos si no selecciona a nadie.
* Las listas de Hallazgos incluyen una columna **Asignados** y un filtro de asignados, y los informes pueden incluir una columna **Asignados**.
* Las asignaciones de cada persona aparecen en su cola de [Mi trabajo](/metrics_reports/dashboards/pro__my_work/).

Solo puede asignar un Hallazgo a alguien que ya pueda verlo. La asignación no otorga acceso.

El [Motor de reglas](/automation/rules_engine/) puede establecer asignados automáticamente: elija **Set Users** y el campo **assignees**.

La asignación está controlada por el [indicador de función](/admin/feature_flags/pro__feature_flags/) **Asignación de trabajo**.
