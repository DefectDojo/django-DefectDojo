---
title: Configurar notificaciones por correo electrónico, Slack o Teams
description: Configure Microsoft Teams para recibir notificaciones
aliases:
- /es/en/customize_dojo/notifications/email_slack_teams
---

**Necesitará acceso de superusuario para usar la página de Configuración del sistema, lo cual es necesario para completar este proceso.**

Las notificaciones pueden enviarse a Slack o Teams cuando se activan determinados eventos en DefectDojo.

## Configuración de notificaciones de Slack

DefectDojo puede publicar notificaciones de Slack de dos formas distintas: 

* Notificaciones a nivel de sistema, que se enviarán a un único canal de Slack
* Notificaciones personales, que solo se enviarán a usuarios específicos.

A continuación se muestra un ejemplo de una notificación de Slack enviada desde DefectDojo:  
​
![image](images/Configure_a_Slack_Integration.png)

DefectDojo no cuenta con una aplicación de Slack dedicada, pero puede crear una fácilmente para su espacio de trabajo siguiendo esta guía. Se requiere una aplicación de Slack para que las notificaciones tanto del sistema como personales se envíen correctamente.

### Crear una aplicación de Slack

Para configurar una conexión de Slack con DefectDojo, deberá crear una aplicación de Slack personalizada.

1. Comience este proceso desde la página de aplicaciones de Slack: <https://api.slack.com/apps>.
2. Haga clic en «**Create New App**».
3. Seleccione «**From App Manifest**».
4. Seleccione su espacio de trabajo de Slack en el menú.
5. Ingrese su App Manifest: puede copiar y pegar este archivo JSON, que incluye todos los ajustes de permisos necesarios para permitir que la integración de Slack se ejecute.  
​
```
{  
   "_metadata": {  
     "major_version": 1,  
     "minor_version": 1  
   },  
   "display_information": {  
     "name": "DefectDojo",  
     "description": "Notifications from DefectDojo. See https://docs.defectdojo.com/en/notifications/configure-a-slack-integration/ for configuration steps.",  
     "background_color": "#0000AA"  
   },  
   "features": {  
       "bot_user": {  
           "display_name": "DefectDojo Notifications"  
       }  
   },  
   "oauth_config": {  
     "scopes": {  
       "bot": [  
         "chat:write",  
         "chat:write.customize",  
         "chat:write.public",  
         "incoming-webhook",  
         "users:read",  
         "users:read.email"  
       ]  
     },  
     "redirect_urls": [  
       "https://slack.com/oauth/v2/authorize"  
     ]  
   }  
 }
```

Revise el App Summary y haga clic en Create App cuando haya terminado. Complete la instalación haciendo clic en el botón **Install To Workplace**.

### Configurar su integración de Slack en DefectDojo

Ahora deberá configurar la integración de Slack en DefectDojo para completarla.

**Necesitará acceso de superusuario para acceder a la página de Configuración del sistema de DefectDojo.**

1. Navegue a la página App Information de su aplicación de Slack, desde <https://api.slack.com/apps>. Esta será la aplicación creada en la primera sección - **Crear una aplicación de Slack**.  
​
2. Busque su OAuth Access Token. Puede encontrarlo en la barra lateral de Slack - **Features / OAuth & Permissions**. Copie el **Bot User OAuth Token.  
​**

![image](images/Configure_a_Slack_Integration_2.png)

3. Abra DefectDojo en una pestaña nueva y navegue a **Configuration > System Settings** desde la barra lateral. (En la interfaz Pro, este formulario se encuentra en **Enterprise Settings > System Settings**.)
4. Marque la casilla **Enable Slack notifications**.
5. Pegue el **Bot User OAuth Token** del paso 1 en el campo **Slack token**.
6. El campo **Slack Channel** debe corresponder al canal de su espacio de trabajo donde desea que el bot de DefectDojo escriba las notificaciones.
7. Si desea cambiar el nombre del bot de DefectDojo, puede ingresar un nombre personalizado aquí. Si no lo hace, se usará **DefectDojo Notifications**, según lo definido en el App Manifest de Slack.

Una vez completado este proceso, DefectDojo podrá enviar notificaciones a nivel de sistema a este canal. Seleccione las notificaciones que desea enviar desde la [página de Notificaciones del sistema]().

![image](images/Configure_a_Slack_Integration_3.png)

#### Notas sobre las notificaciones a nivel de sistema en Slack:

Slack no puede aplicar ninguna regla de RBAC al canal de Slack que está creando, por lo que compartirá notificaciones de todo el sistema DefectDojo. No existe ningún método en DefectDojo para filtrar las notificaciones de Slack a nivel de sistema por Tipo de producto, Producto o Compromiso.

Si desea aplicar un filtrado basado en RBAC a sus mensajes de Slack, habilitar las notificaciones personales de Slack es una mejor opción.

### Enviar notificaciones personales a Slack

Si su equipo tiene habilitada una integración de Slack (mediante el proceso anterior), los usuarios individuales también pueden configurar notificaciones para enviarlas directamente a su canal personal de Slackbot.

1. Comience navegando a su página de Perfil personal en DefectDojo. Encuéntrela haciendo clic en el **icono** 👤 en la esquina superior derecha. Seleccione su nombre de usuario de DefectDojo en la lista. (👤 **paul** en nuestro ejemplo)
​
![image](images/Configure_a_Slack_Integration_4.png)

2. Configure su **Slack Email Address** en el menú. Este campo se encuentra anidado dentro de **Additional Contact Information** en DefectDojo.

Ahora puede [configurar notificaciones específicas](../about_notifications/) para que se envíen a su canal personal de Slackbot. Otros usuarios de su canal de Slack no recibirán estos mensajes.

## Configuración de notificaciones de Microsoft Teams

Microsoft Teams puede recibir notificaciones en un canal específico. Para ello, deberá **configurar un webhook entrante** en el canal donde desea recibir los mensajes.

Tenga en cuenta que Microsoft retirará los antiguos [webhooks de Office Connector](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet); use un nuevo webhook basado en Power Automate Workflow, como se documenta a continuación.

1. Complete el proceso indicado en la **[documentación de Microsoft Teams](https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498)** para crear un nuevo Incoming Webhook. Tenga a mano su enlace único logic.azure.com, ya que lo necesitará en los pasos siguientes. Puede crear el webhook para un canal o para un chat específico.
​
![image](images/Configure_a_Microsoft_Teams_Integration.png)
2. En DefectDojo, navegue a **Configuration > System Settings** desde la barra lateral. (En la interfaz Pro, este formulario se encuentra en **Enterprise Settings > System Settings**.)
3. Marque la casilla **Enable Microsoft Teams notifications**. Esto abrirá una sección oculta del formulario, etiquetada «**Msteams url**».
​
![image](images/Configure_a_Microsoft_Teams_Integration_2.png)
4. Pegue la URL de logic.azure.com (creada en el paso 1) en el cuadro **Msteams url**. Su aplicación de Teams ahora escuchará las notificaciones entrantes de DefectDojo y las publicará en el canal que seleccionó.

### Notas sobre la integración con Teams

* Slack no puede aplicar ninguna regla de RBAC al canal de Teams que está creando, por lo que compartirá notificaciones de todo el sistema DefectDojo. No existe ningún método en DefectDojo para filtrar las notificaciones de Teams a nivel de sistema por Tipo de producto, Producto o Compromiso.
* DefectDojo no puede enviar notificaciones personales a usuarios en Microsoft Teams.

## Configuración de notificaciones por correo electrónico a nivel de sistema

Las notificaciones de DefectDojo también pueden enviarse a una dirección de correo electrónico específica.

1. Desde la página de Configuración del sistema (**Configuration > System Settings** en la interfaz clásica, o **Enterprise Settings > System Settings** en la interfaz Pro), navegue hasta Enable Mail (email) Notifications. 

2. Marque la casilla **Enable mail notifications** y luego ingrese la dirección de correo electrónico a la que desea que se envíen estas notificaciones (mail notifications to).

![image](images/notifs_email.png)

Tenga en cuenta que DefectDojo no puede aplicar filtrado RBAC a estos correos electrónicos: se enviarán para toda la actividad en DefectDojo. Si prefiere enviar un conjunto más personalizado de notificaciones por correo electrónico, es mejor configurar [Notificaciones personales](../configure_personal_notifs) con un usuario o cuenta de servicio vinculada a la dirección correspondiente.
