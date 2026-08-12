---
title: Uso del Cloud Manager
description: Gestione su suscripción y la configuración de su cuenta
weight: 1
collapsed: true
audience: pro
aliases:
- /es/en/cloud_management/using-cloud-manager
---

Iniciar sesión en el Cloud Manager de DefectDojo le permite configurar los ajustes de su cuenta y gestionar su suscripción con DefectDojo Cloud.

## **Nueva suscripción**
<https://cloud.defectdojo.com/accounts/onboarding/step_1>

Esta página le permite solicitar una instancia de Cloud nueva, [o adicional](../additional-cloud-instance/), de DefectDojo.

## **Gestionar suscripciones**
<https://cloud.defectdojo.com/accounts/manage_subscriptions>

La página de Gestión de suscripciones muestra todas sus instancias de Cloud actualmente activas, y le permite configurar los ajustes de Firewall de cada instancia.

### Cambiar la configuración del Firewall
![image](images/using_the_cloud_manager.png)

Una vez en la página **Edit Subscription**, introduzca la dirección IP, la máscara y la etiqueta de la regla que desea añadir. Si necesita más de una regla de firewall, haga clic en **Add New Range** para crear una nueva regla vacía.

![image](images/using_the_cloud_manager_2.png)

Aquí también puede abrir su firewall a servicios externos (GitHub y Jira Cloud).  Si lo desea, también puede desactivar completamente su firewall seleccionando **Proceed Without Firewall** en el menú.

## Añadir usuarios adicionales al Cloud Portal

Si tiene varios usuarios a los que desea dar control sobre su Cloud Portal / suscripción de DefectDojo, puede añadirlos mediante este formulario.  Los usuarios que desee añadir deberán haber creado su propia cuenta de Cloud Portal en cloud.defectdojo.com; no basta con tener una cuenta en su instancia de DefectDojo.

![image](images/using_the_cloud_manager_5.png)

Introduzca el correo electrónico asociado a la cuenta de Cloud Portal del usuario y haga clic en Submit para añadirlo a su lista de usuarios vinculados.  El usuario podrá ahora gestionar el Cloud Portal y su suscripción de DefectDojo.

## Recursos
<https://cloud.defectdojo.com/resources/>

La página Resources contiene un formulario de contacto (Contact Us), que puede utilizar para ponerse en contacto con nuestro equipo de Soporte.

![image](images/using_the_cloud_manager_3.png)

## Herramientas
<https://cloud.defectdojo.com/external_tools/defectdojo-cli>

La página Tools es uno de los lugares donde puede descargar herramientas externas de Pro, como Universal Importer o DefectDojo CLI.  Estas herramientas son complementos externos que pueden usarse para crear rápidamente una canalización de importación por línea de comandos en su red. Para más información sobre estas herramientas, consulte la documentación de [External Tools](/import_data/pro/specialized_import/external_tools/).

![image](images/using_the_cloud_manager_6.png)


## Configuración de la cuenta
<https://cloud.defectdojo.com/accounts/settings>

La página de configuración de la cuenta tiene cuatro secciones:

* **User Contact** le permite configurar su nombre de usuario, dirección de correo electrónico, nombre y apellidos.
* **Email Accounts** le permite añadir direcciones de correo electrónico adicionales a su cuenta. Al añadir una cuenta de correo adicional se enviará un correo de verificación a la nueva dirección.
* **Manage Social Accounts** le permite conectar DefectDojo Cloud con sus credenciales de GitHub o Google, que pueden usarse para iniciar sesión en lugar de un nombre de usuario y contraseña.
* **MFA Settings** le permite añadir un código de MFA a Google Authenticator, 1Password o aplicaciones similares. Añadir un paso adicional a su proceso de inicio de sesión es una buena medida proactiva para evitar accesos no autorizados.

### Añadir MFA al inicio de sesión de su Cloud Portal
<https://cloud.defectdojo.com/settings/mfa/configure/>

Tenga en cuenta que esto solo añadirá MFA al inicio de sesión de DefectDojo Cloud, no al inicio de sesión de su aplicación DefectDojo.

![image](images/using_the_cloud_manager_4.png)

1. Empiece instalando una aplicación de autenticación que admita autenticación por código QR en su smartphone o equipo.
2. Una vez hecho esto, haga clic en **Generate QR Code**.
3. Escanee el código QR proporcionado en DefectDojo con su aplicación de autenticación y, a continuación, introduzca el código de seis\-dígitos proporcionado por su aplicación.
4. Haga clic en **Enable Multi\-Factor Authentication**.
