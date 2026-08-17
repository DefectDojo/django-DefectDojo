---
title: Solución de problemas de errores de Jira (Legado)
description: Solución de problemas con una integración de Jira
weight: 2
aliases:
- /es/issue_tracking/jira/troubleshooting_jira/
- /es/en/share_your_findings/troubleshooting_jira/
---

Aquí tiene algunos problemas comunes con la integración de Jira, y formas de solucionarlos.

## No encuentro ninguna configuración de Jira en DefectDojo

Si no hay ningún menú de Jira en la barra lateral, ninguna sección de Jira en los formularios de Producto / Compromiso, ni la opción **Push to Jira** en los Hallazgos, es muy probable que la integración de Jira siga deshabilitada en la Configuración del Sistema.  DefectDojo oculta todos los controles de Jira hasta que se activa.

Marque **Enable Jira Integration** en la página de Configuración del Sistema:

* Open Source: ⚙️ **Configuration \> System Settings**, luego marque **Enable JIRA integration**.  También se requiere un **Jira webhook secret** antes de que el formulario se pueda guardar, así que haga clic en el icono 🔄 para generar uno.  Consulte la [Guía de integración de Jira](/connectors/os_jira/os__jira_guide/#step-1-enable-the-jira-integration-in-system-settings).
* Pro: **\<Your Edition\> Settings \> System Settings**, luego marque **Enable Jira Integration** en **Jira Integration Settings**.  Consulte la [Guía de integración de Jira](/connectors/downstream/pro__jira_guide/#step-1-enable-the-jira-integration-in-system-settings).

Si la configuración ya está habilitada y aún no puede ver el menú de Jira, es posible que a su usuario le falte el permiso de configuración **View Jira Instance**, que también es necesario para que aparezca el menú.  Se puede asignar directamente en la página de Usuario o mediante un Grupo de Usuarios.  Consulte [Acerca de los permisos y roles](/admin/user_management/about_perms_and_roles/#configuration-permissions).

## DefectDojo no puede comunicarse con Jira (ni con otros servicios salientes) en absoluto

Si la integración de Jira de DefectDojo falla con errores de conexión similares a "connection refused", "no route to host" o fallos genéricos del protocolo de enlace TLS — y las credenciales en sí son válidas — es posible que su instancia de DefectDojo esté detrás de un firewall que exige que el tráfico saliente pase por un proxy HTTPS de reenvío.

Para implementaciones Pro on-prem, configure las variables de entorno `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` en la implementación.  `dojo-compose-cli` las propaga automáticamente a los contenedores `uwsgi`, `celeryworker` y de Connector.  Consulte [Ejecutar DefectDojo detrás de un proxy HTTPS de reenvío](/onprem_deployment/forward_proxy/) para ver el recorrido completo de configuración.

> Nota: configurar `HTTPS_PROXY` solo configura el tráfico **saliente** de DefectDojo.  No afecta la capacidad de Jira para entregar webhooks **entrantes** a DefectDojo — consulte [Los cambios realizados en incidencias de Jira no actualizan los Hallazgos en DefectDojo](#changes-made-to-jira-issues-are-not-updating-findings-in-defectdojo) más abajo para ese caso.

## No se puede configurar Jira en DefectDojo debido a errores 404, 401 o 403
Jira Cloud:
- Consulte la documentación de la API REST de Jira Cloud sobre autenticación: https://developer.atlassian.com/cloud/jira/software/basic-auth-for-rest-apis/
- Verifique en la línea de comandos que las credenciales proporcionadas puedan acceder a las incidencias necesarias en Jira:

```
curl -D- \
   -u <emailaddress>:<personal_access_token> \
   -X GET \
   -H "Content-Type: application/json" \
   https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Por ejemplo:
```
curl -D- \
   -u defectdojo@example.com:ATATT1234567890abcdefghijklmnopqrstuvwxyz \
   -X GET \
   -H "Content-Type: application/json" \
   https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Jira Data Center o Server:
- Consulte la documentación de la API REST de Jira Data Center sobre autenticación:
    - https://developer.atlassian.com/server/jira/platform/basic-authentication/ (usuario + contraseña)
    - https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html (token de acceso personal)
- Verifique en la línea de comandos que las credenciales proporcionadas puedan acceder a las incidencias necesarias en Jira:

```
curl -u username:password -X GET -H "Content-Type: application/json" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Por ejemplo:
```
curl -u defectdojo@example.com:123456 -X GET -H "Content-Type: application/json" https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Al usar tokens de acceso personal:
```
curl -H "Authorization: Bearer <personal_access_token>" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Por ejemplo:
```
curl -H "Authorization: Bearer ATATT1234567890abcdefghijklmnopqrstuvwxyz" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

## Las cuentas de servicio de Jira no son compatibles

Las cuentas de servicio de Jira Cloud (creadas a través de la consola de administración de Atlassian) usan un host de API distinto al de las cuentas de usuario estándar y **actualmente no son compatibles** con la integración de Jira de DefectDojo. Intentar usar un token de API de una cuenta de servicio o credenciales OAuth 2.0 de una cuenta de servicio dará como resultado errores HTTP 403.

Para configurar la integración de Jira, cree una cuenta de usuario de Jira estándar (con una dirección de correo electrónico válida) y genere un token de API desde esa cuenta. Si desea identificar claramente las incidencias creadas por DefectDojo, cree un usuario dedicado con un nombre como "DefectDojo" y use su token de API para la integración.

## No encuentro un Epic Name ID para mi Space
Ciertos Spaces en Jira, como los Team-Managed Spaces, no usan Epics y por lo tanto no tendrán un Epic Name ID.  En ese caso, configure el Epic Name ID como 0 en DefectDojo.

## Los Hallazgos que envío con 'Push To Jira' no aparecen en Jira
Usar el flujo de trabajo 'Push To Jira' inicia un proceso asíncrono; sin embargo, una incidencia debería crearse en Jira con bastante rapidez después de activar 'Push To Jira'.

* Revise sus notificaciones de DefectDojo para ver si el proceso se completó correctamente.  Si el envío falló, recibirá una respuesta de error de Jira en sus notificaciones.

Motivos comunes por los que no se crean las incidencias:
* El tipo de incidencia predeterminado que ha seleccionado no se puede usar con el Space de Jira
* Las incidencias del Space tienen atributos obligatorios que impiden que se creen a través de DefectDojo (lo cual se puede gestionar mediante Custom Fields en Jira)


## Error: ¿Producto mal configurado o sin permisos en Jira?

Este mensaje de error puede aparecer al intentar añadir una configuración de Jira ya creada a un Producto.  DefectDojo intentará validar una conexión con Jira, y si esa conexión falla, generará este mensaje de error.

* Compruebe si sus credenciales de Jira tienen permiso para crear incidencias en el Space de Jira que ha seleccionado.
* El campo "Project Key" debe ser un Space de Jira válido. Las incidencias de Jira pueden usar muchas Keys distintas dentro de un mismo Space; la forma más sencilla de confirmar su Project Key es mirar la URL de ese Space de Jira en particular: normalmente tendrá un aspecto como `https://xyz.atlassian.net/jira/core/projects/JTV/board`.  En este caso, `JTV` es la Space Key.

## Los cambios realizados en incidencias de Jira no actualizan los Hallazgos en DefectDojo

* Empiece por confirmar que el receptor de webhooks de DefectDojo está configurado correctamente y puede recibir actualizaciones con éxito.

* Asegúrese de que el certificado SSL usado por Defect Dojo sea de confianza para JIRA. Para JIRA Cloud debe usar [un certificado SSL/TLS válido, firmado por una autoridad de certificación de confianza global](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

* Si está intentando enviar cambios de estado, confirme que las asignaciones de transición de Jira estén configuradas correctamente (Reopen / Close Transition IDs).

* [Pruebe](https://support.atlassian.com/jira/kb/testing-webhooks-in-jira-cloud/) su webhook de JIRA usando un endpoint público como Pipedream o Beeceptor:

* Confirme que el Hallazgo esté realmente vinculado a la incidencia de Jira. Si la incidencia no está vinculada a un Hallazgo de DefectDojo, la solicitud del webhook igual se acepta (HTTP `200`) pero no se actualiza ningún Hallazgo.

* Recuerde que el endpoint **siempre devuelve HTTP `200`**, se haya aplicado o no una actualización. Un `200` en el lado emisor (un webhook del sistema o una regla de Jira Automation) no confirma que el cambio llegara a un Hallazgo — revise el cuerpo de la respuesta y los registros de DefectDojo para ver el resultado real.

* Si está usando **Jira Automation** (*Send web request*) en lugar de un webhook del sistema, revise lo siguiente:
    * El **Body** de la solicitud está configurado como **Custom data** e incluye un `webhookEvent` de nivel superior con el valor `"jira:issue_updated"` o `"comment_created"`. Las opciones de body **Empty** y **Jira issue data** omiten este campo, y DefectDojo ignora cualquier solicitud cuyo `webhookEvent` no reconozca.
    * `Content-Type: application/json` está configurado en la solicitud — DefectDojo rechaza cualquier otro tipo de contenido.
    * Para las actualizaciones de incidencias, `issue.id` es el ID **numérico** de la incidencia de Jira (`{{issue.id}}`), no la issue key, y los campos `resolution` y `updated` están ambos presentes (`resolution` puede ser `null`). La falta de `resolution`/`updated` hace que la solicitud se omita silenciosamente.
    * Para los comentarios, la URL de `comment.self` contiene el `{{issue.id}}` numérico en su segmento `.../issue/<id>/comment/...`, y tanto `body` como `updateAuthor` están presentes.
    * Si no aparecen los comentarios, revise la **prevención de bucles**: DefectDojo omite un comentario cuando su autor coincide con la cuenta de Jira que DefectDojo usa para publicar comentarios. Ejecute la regla de Automation como un usuario de Jira distinto si desea que esos comentarios se importen.
    * Use la vista previa del payload de Automation para confirmar que los smart values se resuelven como se espera — sus nombres pueden variar entre instancias de Jira.

## No se están creando los Epics de Jira

`"Field 'customfield_xyz' cannot be set. It is not on the appropriate screen, or unknown."`

La integración de Jira de DefectDojo necesita un valor de customfield para 'Epic Name'.  Sin embargo, es posible que la configuración de su proyecto no use realmente 'Epic Name' como campo al crear Epics.  Atlassian hizo un cambio en [agosto de 2023](https://community.atlassian.com/t5/Jira-articles/Upcoming-changes-to-epic-fields-in-company-managed-projects/ba-p/1997562) que combinó los campos 'Epic Name' y 'Epic Summary'.

Es posible que los Spaces de Jira más nuevos no usen este campo al crear Epics de forma predeterminada, lo que provoca este mensaje de error.

Para corregir este problema, puede añadir el campo 'Epic Name' a la pantalla de creación de incidencias de su proyecto:

1. Intente crear un Epic en Jira manualmente (a través de la interfaz de Jira).
2. Abra el menú "..."
3. Haga clic en 'Find Your Field'
4. Escriba 'Epic Name'
5. Añada Epic Name como campo a esa pantalla en particular siguiendo las instrucciones de Jira.

![image](images/epic_name_error.png)

## Configuración de reintentos y tiempos de espera de conexión de JIRA

La integración de JIRA de DefectDojo incluye ajustes configurables de reintento y tiempo de espera para gestionar la limitación de tasa y los problemas de conexión. Estos ajustes son importantes para mantener la capacidad de respuesta del sistema, especialmente cuando se usan workers de Celery.

### Variables de configuración disponibles

Las siguientes variables de entorno controlan el comportamiento de la conexión con JIRA:

- **`DD_JIRA_MAX_RETRIES`** (predeterminado: `3`): número máximo de reintentos para errores recuperables. La integración reintentará automáticamente ante HTTP 429 (Too Many Requests), HTTP 503 (Service Unavailable) y errores de conexión. Consulte la [documentación de limitación de tasa de JIRA](https://developer.atlassian.com/cloud/jira/platform/rate-limiting/) para más información.

- **`DD_JIRA_CONNECT_TIMEOUT`** (predeterminado: `10` segundos): tiempo de espera de conexión para establecer una conexión con el servidor JIRA.

- **`DD_JIRA_READ_TIMEOUT`** (predeterminado: `30` segundos): tiempo de espera de lectura para esperar una respuesta del servidor JIRA una vez establecida la conexión.

**Nota sobre la limitación de tasa**: la biblioteca de jira tiene un tiempo de espera máximo integrado de 60 segundos para los reintentos por limitación de tasa. Si el encabezado `Retry-After` de JIRA indica un tiempo de espera superior a 60 segundos, la solicitud fallará y no se reintentará. Esta es una limitación de la versión de la biblioteca de jira actualmente en uso.

### Por qué importan los valores conservadores

**Importante**: se recomienda usar valores conservadores (más bajos) para estos ajustes. Este es el motivo:

1. **Bloqueo de tareas de Celery**: las operaciones de JIRA en DefectDojo se ejecutan como tareas asíncronas de Celery. Cuando una tarea está esperando un retraso de reintento, bloquea a ese worker de Celery para procesar otras tareas.

2. **Agotamiento del pool de workers**: si varias operaciones de JIRA están reintentando con retrasos largos, puede agotar rápidamente su pool de workers de Celery, provocando que otras tareas (no solo las relacionadas con JIRA) se pongan en cola y esperen.

3. **Capacidad de respuesta del sistema**: los retrasos de reintento largos pueden hacer que el sistema parezca no responder, especialmente durante interrupciones de JIRA o eventos de limitación de tasa.

La limitación de tasa de JIRA es nueva, así que cuéntenos en Slack o GitHub qué es lo que mejor le funciona.

## Jira y DefectDojo están desincronizados

A veces Jira está caído, o DefectDojo está caído, o hubo un error en un webhook. En ese caso, Jira puede quedar desincronizado con DefectDojo. Si esto ocurre en muchas incidencias, la reconciliación manual puede no ser viable. Para este escenario existe el comando de gestión 'jira_status_reconciliation'.

Como este comando requiere acceso al backend, no está disponible para los usuarios de la nube de DefectDojo Pro; en su lugar, póngase en contacto con nuestro equipo de soporte para obtener ayuda con este problema.

{{< highlight bash >}}
usage: manage.py jira_status_reconciliation [-h] [--mode MODE] [--product PRODUCT] [--engagement ENGAGEMENT] [--dryrun] [--version] [-v {0,1,2,3}]

Reconcile finding status with JIRA issue status, stdout will contain semicolon seperated CSV results.
Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped.

optional arguments:
  -h, --help            show this help message and exit
  --mode MODE           - reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change
                        timestamp in both systems to determine which one is the correct status
                        - push_status_to_jira: update JIRA status for all JIRA issues
                        connected to a Defect Dojo finding (will not push summary/description, only status)
                        - import_status_from_jira: update Defect Dojo
                        finding status from JIRA
  --product PRODUCT     Only process findings in this product (name)
  --engagement ENGAGEMENT
                        Only process findings in this product (name)
  --dryrun              Only print actions to be performed, but make no modifications.
  -v {0,1,2,3}, --verbosity {0,1,2,3}
                        Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, 3=very verbose output
{{< /highlight >}}

Esto se puede ejecutar desde el contenedor Docker de uwsgi usando:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation'
{{< /highlight >}}

La salida DEBUG se puede obtener con `-v 3`, pero solo después de aumentar el nivel de registro a DEBUG en su archivo settings.dist.py o local_settings.py

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation -v 3'
{{< /highlight >}}

Al final del comando se imprimirá un resumen en CSV separado por punto y coma. Esto se puede capturar redirigiendo stdout a un archivo:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation > jira_reconciliation.csv'
{{< /highlight >}}
