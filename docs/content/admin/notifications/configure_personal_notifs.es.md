---
title: Configurar Notificaciones Personales
description: Configurar notificaciones para una cuenta personal
aliases:
- /es/en/customize_dojo/notifications/configure_personal_notifs
---

## Configurar notificaciones Personales

Las Notificaciones Personales se envían además de las Notificaciones a Nivel de Sistema, y se aplicarán a cualquier Producto, Tipo de Producto u otro tipo de dato al que tenga acceso. Las preferencias de Notificación Personal solo se aplican a un único usuario, y solo se pueden configurar desde la cuenta que las está configurando.

![image](images/Configure_System_&_Personal_Notifications.png)

Las notificaciones del sistema las configura un Superusuario de DefectDojo y un usuario individual no puede excluirse de ellas.

1. Comience desde la página de Notificaciones (⚙️**Configuration \> Notifications** en la barra lateral).
2. En el menú desplegable **Scope**, puede seleccionar el conjunto de notificaciones que desea editar.
3. Seleccione Personal Notifications.
4. Marque el método de notificación que desea usar para cada tipo de notificación. Puede seleccionar más de uno.

Las Notificaciones Personales no se pueden enviar por Microsoft Teams, ya que Teams solo permite publicar notificaciones Globales en un único canal.

### Recibir notificaciones Personales de un Producto específico

Además de las notificaciones personales estándar, los Usuarios de DefectDojo también pueden recibir notificaciones sobre la actividad de un Producto específico. Esto es útil cuando hay determinados Productos que un usuario necesita supervisar más de cerca.

![image](images/Configure_System_&_Personal_Notifications_3.png)

Esta configuración se puede cambiar desde la sección **Notifications** de la página del **Producto**: por ejemplo, `your-instance.defectdojo.com/product/{id}`.

Desde aquí puede establecer si desea recibir notificaciones de **🔔 Alert**, **Mail** o **Slack** por las acciones realizadas en este Producto en particular. Estas notificaciones se aplican además de cualquier notificación a nivel de sistema que ya esté recibiendo.

Microsoft Teams no puede enviar notificaciones personales de ningún tipo, por lo que las notificaciones de Teams no se pueden elegir en este menú.

Las notificaciones personales por email siempre se enviarán al correo asociado a su inicio de sesión de DefectDojo. Para configurar una cuenta personal de Slack y recibir notificaciones, consulte nuestra [Guía](../email_slack_teams/#send-personal-notifications-to-slack).
