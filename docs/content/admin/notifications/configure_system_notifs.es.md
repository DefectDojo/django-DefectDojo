---
title: Configurar Notificaciones a Nivel de Sistema
description: Cómo configurar notificaciones Personales y de Sistema
aliases:
- /es/en/customize_dojo/notifications/configure_system_notifs
---

DefectDojo tiene dos tipos diferentes de notificaciones: **Personales** (enviadas a una única cuenta) y de **Sistema** (que se envían a todos los usuarios).

Tanto las Notificaciones Personales de una cuenta como las Notificaciones de Sistema globales se pueden configurar desde la misma página: **⚙️Configuration \> Notifications** en la barra lateral.

![image](images/Configure_System_&_Personal_Notifications.png)

## Configurar notificaciones de Sistema (Interfaz Clásica)

**Necesitará acceso de Superusuario para cambiar las notificaciones a Nivel de Sistema.**

1. Comience desde la página de Notificaciones (⚙️ **Configuration \> Notifications** en la barra lateral).
2. En el menú desplegable Scope, puede seleccionar el conjunto de notificaciones que desea editar.
3. Seleccione System Notifications.
4. Marque el método de entrega de notificación que desea usar para cada tipo de notificación. Puede seleccionar más de uno.

![image](images/Configure_System_&_Personal_Notifications_2.png)

Para configurar destinos para las notificaciones por email a nivel de sistema (Email, Slack o MS Teams), consulte nuestra [Guía](../email_slack_teams).

## Notificaciones de Plantilla

Los Superusuarios también tienen acceso a un formulario "Template". El Formulario de Plantilla le permite establecer las Notificaciones Personales por defecto que se habilitan para cualquier usuario nuevo.

## Dónde se envían las Notificaciones de Sistema

Las Notificaciones de Sistema se enviarán a:
- la única dirección de email especificada en la Configuración del Sistema (si está habilitada)
- cualquier usuario de DefectDojo con cuenta y los permisos RBAC correspondientes
- la cuenta de Slack o Teams a nivel de sistema.

Como con cualquier notificación en DefectDojo, las Notificaciones de Sistema solo se enviarán a los usuarios que tengan acceso a los datos correspondientes. Así que, incluso si las Notificaciones de Producto se configuran a Nivel de Sistema, los usuarios solo recibirán notificaciones de los Productos a los que tengan acceso para ver.

Esta restricción no se aplica a las Notificaciones de Sistema que se envían a un Email o canal de Slack específico.

Consulte nuestra guía sobre [Control de Acceso Basado en Roles](../../user_management/about_perms_and_roles/) para más información sobre RBAC y la configuración de permisos.

Sin embargo, las cuentas conectadas de Email, Slack y Teams del Sistema no pueden aplicar RBAC, ya que no están asociadas a un usuario específico de DefectDojo. **Todas las notificaciones a nivel de sistema seleccionadas se enviarán a estas ubicaciones, así que debe asegurarse de que a estos canales solo puedan acceder personas específicas de su organización.**
