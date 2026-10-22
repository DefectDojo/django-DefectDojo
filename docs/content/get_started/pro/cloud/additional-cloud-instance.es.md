---
title: Configurar una instancia adicional de Cloud
description: Agregue una instancia de prueba, desarrollo u otra instancia de DefectDojo
  a su cuenta
weight: 3
audience: pro
aliases:
- /es/en/cloud_management/additional-cloud-instance
---

El proceso para agregar una segunda instancia de Cloud es más o menos el mismo que para agregar su primera instancia. Esta guía asume que ya ha configurado su servidor inicial de DefectDojo y que tiene un acuerdo con nuestro equipo de Ventas para agregar otra instancia.

Si aún no ha solicitado una instancia de Cloud adicional, contacte a [info@defectdojo.com](mailto:info@defectdojo.com) antes de continuar.

## Paso 1: Abra el proceso de Nueva Suscripción

Puede iniciar este proceso desde el siguiente enlace: <https://cloud.defectdojo.com/accounts/onboarding/step_1>, o haciendo clic en 🛒 **New Subscription** desde la página del Cloud Manager (cloud.defectdojo.com).

![image](images/request_a_trial.png)

## Paso 2: Configure su Server Label

Introduzca el **Name** de su empresa y el **Server Label** que desea usar con DefectDojo. A continuación se creará un dominio personalizado para su instancia de DefectDojo en nuestros servidores.

Mantenga el nombre de su empresa igual que antes, pero cree un nuevo Server Label y marque el botón "**Use Server Label in Domain**", para poder diferenciar fácilmente entre sus servidores.

![image](images/request_a_trial_2.png)

## Paso 3: Seleccione una ubicación del servidor

Seleccione una ubicación de servidor en el menú desplegable. Como antes, recomendamos seleccionar un servidor que esté geográficamente lo más cerca posible de sus usuarios para reducir la latencia del servidor.

![image](images/request_a_trial_3.png)

## Paso 4: Configure sus reglas de Firewall

Introduzca los rangos de direcciones IP, la máscara de subred y las etiquetas a los que desea permitir el acceso a DefectDojo. Su equipo puede agregar o cambiar direcciones IP y reglas adicionales una vez que su instancia esté en funcionamiento.

Si lo desea, estas reglas de firewall pueden ser diferentes de las reglas de su instancia principal de DefectDojo.

![image](images/request_a_trial_4.png)

Si desea usar servicios externos con esta instancia (GitHub o JIRA), marque las casillas correspondientes que aparecen bajo **Select External Services.**

También puede continuar sin firewall seleccionando **Proceed Without Firewall**.  Su firewall se puede volver a habilitar más adelante.

## Paso 5: Confirme su tipo de plan y la frecuencia de facturación

Al final de nuestro proceso, se le pondrá en contacto con nuestro equipo de ventas, que podrá cotizar con precisión su nuevo servidor. Recomendamos seleccionar el tipo de plan que tenga las especificaciones de servidor que necesita para la nueva instancia.

![image](images/request_a_trial_5.png)

Es posible que un segundo servidor no requiera los mismos requisitos de almacenamiento, CPU y RAM que su instancia "principal", pero esto dependerá de los requisitos técnicos de su equipo.

## Paso 6: Revise y envíe su solicitud

Le pediremos que revise su solicitud una vez más. Una vez enviada, solo las reglas de Firewall pueden ser cambiadas por su equipo sin la ayuda de Soporte.

![image](images/request_a_trial_6.png)

Después de revisar y aceptar el Acuerdo de Licencia y Soporte de DefectDojo, puede proceder a **Checkout With Stripe**, o si tiene un acuerdo de facturación existente puede hacer clic en **Contact Sales**.

Nuestro equipo de Soporte se pondrá en contacto con usted con las credenciales de inicio de sesión cuando su servidor haya sido aprobado y aprovisionado.
