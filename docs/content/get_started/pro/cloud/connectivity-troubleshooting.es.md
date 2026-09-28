---
title: Solución de problemas de conectividad
description: Vuelva a conectarse a su instancia de DefectDojo
weight: 2
audience: pro
aliases:
- /es/en/cloud_management/connectivity-troubleshooting
---

Si tiene dificultades para acceder a su instancia de DefectDojo, estos son algunos pasos que puede seguir para volver a conectarse:

## Puedo acceder al sitio, pero no puedo iniciar sesión

1. Puede restablecer la contraseña de su cuenta desde la página de inicio de sesión: **yourcompanyinstance.cloud.defectdojo.com/login**. Haga clic en 'I forgot my password' para comenzar el proceso.
​

![image](images/Connectivity_Troubleshooting.png)

2. Introduzca su dirección de correo electrónico y haga clic en "Reset my password".
​
3. Debería recibir un correo electrónico con el asunto "`Password reset on yourcompanyinstance.cloud.defectdojo.com`". Este correo contiene un enlace en el que puede hacer clic para establecer una nueva contraseña.


![image](images/Connectivity_Troubleshooting_2.png)

Si no recibe un correo electrónico, revise su carpeta de Spam. Si aun así no lo encuentra, pida al administrador de DefectDojo de su equipo que confirme que tiene una cuenta registrada en su instancia.



## No puedo acceder al sitio cloud.defectdojo de mi empresa

Si el sitio cloud.defectdojo de su empresa no carga en su navegador, o se agota el tiempo de espera, puede ser necesario que su empresa cambie sus reglas de firewall para aceptar su conexión.

Las reglas de firewall se pueden cambiar en su Cloud Manager en <https://cloud.defectdojo.com/accounts/manage_subscriptions>.

Si su empresa usa una VPN compartida, un servidor proxy o una herramienta similar, asegúrese de que esté autorizada para conectarse a DefectDojo y de que la dirección IP esté incluida en las reglas de Firewall de DefectDojo.

Si el problema persiste, contacte a [support@defectdojo.com](mailto:support@defectdojo.com) .



## No puedo iniciar sesión en el Cloud Manager

Si no puede acceder al Cloud Manager, vaya a la página de inicio de sesión en <https://cloud.defectdojo.com/accounts/login/> y haga clic en **"Forgot your password?"**


![image](images/Connectivity_Troubleshooting_3.png)
Se le pedirá que introduzca su dirección de correo electrónico, y nuestro equipo le enviará un correo con un enlace para restablecer su contraseña e introducir una nueva.

Tenga en cuenta que este método de inicio de sesión solo funciona para el **Cloud Manager**, un sitio de administración al que puede que no todos los miembros de su equipo tengan acceso. Iniciar sesión directamente en su instancia para usar DefectDojo solo es posible conectándose directamente a **yourcompanyinstance.cloud.defectdojo.com/login**.



## He perdido el acceso a mis códigos de MFA

* **Para el Cloud Manager:** Si pierde el acceso a sus códigos de MFA o a su aplicación de autenticación, contacte al Soporte de DefectDojo en [support@defectdojo.com](mailto:support@defectdojo.com).
* **Para una instancia de DefectDojo:** Primero intente con uno de los **códigos de recuperación** emitidos cuando se configuró el MFA — que se introducen en lugar del código de seis dígitos al iniciar sesión. Si esos no están disponibles, un administrador con acceso al servidor puede borrar el MFA de la cuenta usando `python manage.py remove_mfa --username <username>`; el usuario entonces inicia sesión con su contraseña y vuelve a inscribirse, conservando todos los permisos e historial existentes. En DefectDojo Cloud, contacte a Soporte para que ejecuten ese comando. Consulte [Autenticación multifactor](/admin/user_management/pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device) para conocer todas las opciones.
