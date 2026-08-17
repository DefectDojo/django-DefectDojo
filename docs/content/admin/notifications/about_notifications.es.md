---
title: Acerca de las Notificaciones y las 🔔 Alertas
description: Aprenda sobre las notificaciones y las alertas dentro de la aplicación
aliases:
- /es/en/customize_dojo/notifications/about_notifications
---

DefectDojo lo mantiene al día de diversas maneras. Se pueden enviar notificaciones para Compromisos próximos, [Menciones de usuario](/triage_findings/findings_workflows/intro_to_findings/#notes-and-mentions), vencimiento de SLA y otros eventos del software.

Este artículo ofrece una visión general de las notificaciones tanto a nivel de Sistema como Personal.

## Tipos de Notificación

DefectDojo gestiona las notificaciones de dos maneras distintas:

* Las **Notificaciones a Nivel de Sistema** se envían a todos los usuarios.
* **Las Notificaciones Personales las configura cada usuario individualmente, y se reciben además de cualquier Notificación a Nivel de Sistema.**

En ambos casos, se aplican las reglas de [Control de Acceso Basado en Roles](../../user_management/about_perms_and_roles/), por lo que los usuarios no recibirán notificaciones de actividad de Productos o Tipos de Producto (ni de sus objetos relacionados) a los que no tengan acceso.

## Métodos de Entrega de Notificaciones

Existen cuatro métodos de entrega para las notificaciones de DefectDojo:

* DefectDojo puede compartir **🔔 Alertas**, almacenadas como una lista en la interfaz de DefectDojo
* DefectDojo puede enviar notificaciones a una dirección de **Email**
* DefectDojo puede enviar notificaciones a **Slack**, ya sea en un canal compartido o individual
* DefectDojo también puede enviar notificaciones a **Microsoft Teams** en un canal compartido

Las notificaciones se pueden enviar a varios destinos simultáneamente.

Para recibir notificaciones de Slack y Teams necesitará tener una integración en funcionamiento. Para más información sobre cómo configurar esta integración, consulte nuestra [Guía](../email_slack_teams).

## Alertas dentro de la aplicación

El sistema de Alertas de DefectDojo lo mantiene al día de toda la actividad de Producto o del sistema.

### La Lista de Alertas

La Lista de Alertas siempre está visible en la esquina superior derecha de DefectDojo, y contiene una lista compacta de notificaciones. Al hacer clic en cada Alerta se le llevará directamente a la página correspondiente en DefectDojo.

Puede abrir su Lista de Alertas haciendo clic en el **ícono 🔔▼** en la esquina superior derecha:

![image](images/About_In-App_Alerts.png)

Para ver todas sus notificaciones, junto con detalles adicionales, puede hacer clic en el botón **Ver todas las Alertas \>**, que abrirá la **Página de Alertas**.

También puede **Borrar todas las Alertas \>** desde la Lista de Alertas.

### La Página de Alertas

La Página de Alertas almacena todas sus Alertas de DefectDojo con detalle adicional. En esta página puede leer las descripciones de cada Alerta en DefectDojo, y eliminarlas de la cola de Alertas una vez que ya no las necesite.

![image](images/About_In-App_Alerts_2.png)

Para eliminar una o más Alertas de la Página de Alertas, marque la casilla vacía junto a ella, y luego haga clic en el botón **Eliminar seleccionadas** en la esquina inferior derecha de la Página.

### Notas sobre las Alertas

* Leer una Alerta, o abrir la Página de Alertas, no eliminará ninguna Alerta del contador junto al ícono de campana. Esto es para que pueda acceder fácilmente a alertas pasadas y usarlas como recordatorios o como un registro de actividad personal.
* Usar la función **Borrar todas las Alertas \>** en el Menú de Alertas también vaciará por completo la **Página de Alertas**, así que use esta función con cuidado.
* Eliminar una Alerta solo afecta a su propia Lista de Alertas: no afectará a las Alertas de ningún otro usuario.
* Eliminar una Alerta no elimina ningún historial de importación ni registro de actividad de DefectDojo.

## Reducir las Notificaciones de Solicitud de Revisión (Pro)

Si se solicita una revisión a todos los revisores elegibles, se notifica a todos los elegibles para ese activo. Eso supone muchos correos para un revisor que solo se ocupa de una parte de su parque de activos.

En la interfaz de DefectDojo Pro puede reducir sus propias notificaciones de solicitud de revisión. En su página de configuración de notificaciones, bajo **Review Requests**:

* **Review Request Scope** — *All* (el valor por defecto) le notifica sobre todo lo que puede ver. *Selected* lo limita a los activos y tipos de activo que elija.
* **Review Request Assets** / **Review Request Asset Types** — el subconjunto del parque de activos sobre el que desea recibir información. Una solicitud coincide si se refiere a uno de sus activos seleccionados *o* a uno de sus tipos de activo seleccionados.

Hay dos cosas que conviene tener claras:

* Elegir *Selected* y no seleccionar nada significa **ninguno**, no todos.
* Esta reducción suprime la notificación, **no la solicitud**. Usted sigue siendo un revisor solicitado y la solicitud sigue apareciendo en su cola de [Mi Trabajo](/metrics_reports/dashboards/pro__my_work/) bajo **Awaiting My Review**; simplemente no se le notifica al respecto. Esto es intencional: la cola es el registro duradero, las notificaciones son el recordatorio.

Esta reducción también tiene prioridad sobre la anulación a nivel de sistema descrita a continuación, de modo que un revisor que se ha excluido a sí mismo no recibe notificación aunque `review_requested` esté configurado para primar sobre las preferencias personales.

La reducción también se puede configurar a través de la API en el endpoint de notificaciones, lo cual es la vía práctica si está configurando muchos revisores a la vez.

## Notificaciones de Asignación de Trabajo (Pro)

Cuando se le asignan Hallazgos, la notificación **Work Assigned** le indica cuántos y enlaza a su cola de Mi Trabajo.

Se agrega por persona en lugar de por Hallazgo: asignar cien Hallazgos envía un solo mensaje, no cien. Al igual que con las solicitudes de revisión, la asignación es visible en su cola tanto si la notificación le llega como si no.

## Consideraciones sobre código abierto

### Anulaciones específicas

La configuración de notificaciones del sistema (scope: system) describe el envío de notificaciones a los superadministradores. La configuración de notificaciones de usuario (scope: personal) describe el envío de notificaciones al usuario específico.

Sin embargo, existe un caso de uso concreto en el que el usuario decide deshabilitar las notificaciones (para reducir el ruido), pero la configuración del sistema se utiliza para anular este comportamiento. Estas anulaciones se aplican por defecto únicamente a `user_mentioned` y `review_requested`.

El alcance de esta configuración es personalizable (véase la variable de entorno `DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP`).

Para más información sobre este comportamiento, consulte la [pull request relacionada #9699](https://github.com/DefectDojo/django-DefectDojo/pull/9699/)

### Webhooks (experimental)

DefectDojo también admite webhooks que siguen los mismos eventos que otras notificaciones (se le puede notificar en las mismas situaciones). Los detalles sobre la configuración se describen en [la página relacionada](/automation/api/notification_webhooks/).
