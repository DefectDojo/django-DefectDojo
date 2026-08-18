---
title: Implementación de DefectDojo Pro en OpenShift
description: 'Qué es específico de OpenShift al implementar DefectDojo Pro autoalojado:
  security context constraints, Routes y almacenamiento ReadWriteMany'
draft: false
weight: 8
audience: pro
---

DefectDojo Pro se ejecuta en OpenShift 4.x, incluyendo OpenShift Container Platform, ROSA y OKD.

Esta página complementa la guía de instalación suministrada con su licencia de DefectDojo Pro. Esa guía contiene el procedimiento completo, incluida una sección dedicada a OpenShift. Esta página cubre lo que es diferente en OpenShift, para que sepa qué tener listo antes de empezar y qué esperar de la configuración específica de la plataforma.

Con los materiales de su licencia se suministra un script de bootstrap para OpenShift. Se instala en un clúster existente y se encarga de la mayor parte de lo que describe esta página, incluido el almacenamiento, el valor de `fsGroup`, la Route y la instalación en sí. Es idempotente, así que volver a ejecutarlo reutiliza lo que ya creó, y admite una ejecución en seco (dry run) que imprime lo que haría sin cambiar nada. El resto de esta página se aplica ya sea que use ese script o ejecute la instalación usted mismo.

## Security context constraints

DefectDojo Pro se ejecuta bajo la SCC predeterminada `restricted-v2`. No necesita otorgar `anyuid`, `privileged`, ni ninguna otra SCC elevada a la cuenta de servicio.

Cuando se configura para OpenShift, DefectDojo Pro se ejecuta con contextos de seguridad no privilegiados en todos sus componentes. Los contenedores se ejecutan sin privilegios, no pueden escalar privilegios y eliminan todas las capabilities. El ID de usuario queda a cargo de OpenShift, que lo asigna desde el rango asignado a su namespace, en lugar de fijarse a un UID fijo que la SCC rechazaría.

Si se rechazan pods por no pasar la validación de la SCC, la causa habitual es que la implementación no se configuró para OpenShift, no que haga falta otorgar una constraint.

## El almacenamiento debe ser ReadWriteMany

Los pods de Django y de los workers de Celery leen y escriben los mismos archivos multimedia, que son los escaneos cargados, las capturas de pantalla y los informes generados. Necesitan un volumen compartido, por lo que el almacenamiento ReadWriteOnce no es suficiente para una implementación multinodo.

En OpenShift, lo predeterminado es un PersistentVolumeClaim contra la StorageClass predeterminada del clúster. Esto funciona cuando la clase predeterminada aprovisiona ReadWriteMany, lo cual es típico en clústeres respaldados por OpenShift Data Foundation o NFS. Para implementaciones multinodo donde la clase predeterminada es ReadWriteOnce, configure en su lugar almacenamiento respaldado por NFS.

### fsGroup en almacenamiento respaldado por NFS

OpenShift restringe `fsGroup` al rango asignado al namespace. Cuando usa almacenamiento NFS o EFS, debe suministrar un valor de ese rango o el montaje del volumen fallará con un error de permisos.

Lea el inicio del rango desde la anotación del namespace y úselo como su `fsGroup`:

```bash
oc get namespace <namespace> \
  -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
```

La anotación contiene un rango expresado como un valor de inicio y una longitud. Use el valor de inicio. Esto solo es necesario para almacenamiento NFS y EFS, no para la ruta predeterminada de PersistentVolumeClaim.

## Routes, TLS y cookies

En OpenShift, DefectDojo Pro se expone a través de una Route en lugar de un Ingress, con terminación TLS en el borde (edge) y una redirección desde HTTP.

En ROSA, los hostnames de las Routes se generan como `<release-name>-<namespace>.apps.<cluster-domain>`, así que un release `dojopro` en el namespace `dojopro` obtiene `dojopro-dojopro.apps.<cluster-domain>`. Obtenga el dominio de apps del clúster con:

```bash
oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
```

Un hostname bajo el dominio de apps del clúster está cubierto por el certificado comodín (wildcard) predeterminado y no necesita configuración de certificado. Para cualquier otro hostname, suministre su propio certificado y agregue un CNAME al hostname de la Route.

Defina `dojo.secureCookies` en `false` en OpenShift. Con una Route de terminación en el borde (edge-terminated), el TLS termina en el router y la conexión desde el router al pod es HTTP plano, por lo que las cookies marcadas como seguras nunca se envían de vuelta y el inicio de sesión falla. Esto es obligatorio, no opcional, siempre que la Route termine el TLS en el borde.

## Perfiles de recursos

Hay tres perfiles de recursos disponibles y usted selecciona uno en el momento de la instalación. `minimal` es para desarrollo, CI y pruebas. `standard` es para producción con carga moderada. `performance` es para producción con carga alta y habilita el autoescalado.

Defina su dimensionamiento a través del perfil en lugar de sobrescribir valores individuales, para que su propio archivo de configuración no entre en conflicto con él.

## Antes de empezar

Un clúster de OpenShift 4.x en el que haya iniciado sesión, con `oc`, `helm`, `openssl` y `jq` disponibles localmente.

Un namespace, y el valor de su anotación supplemental-groups si usa almacenamiento NFS o EFS.

Una StorageClass predeterminada que aprovisione ReadWriteMany, o los detalles de un servidor NFS.

PostgreSQL 16 para cualquier uso más allá de la evaluación. Hay un PostgreSQL embebido disponible para desarrollo, pero pase a una base de datos gestionada externa antes de ejecutar en producción.

Su archivo de licencia de DefectDojo Pro.

El hostname de Route que pretende usar.

## Acceso de red saliente

En un clúster con restricciones de egress, permita HTTPS saliente en el puerto 443 hacia el registro de contenedores que aloja las imágenes de DefectDojo Pro. El hostname del registro está en la guía de instalación suministrada con su licencia. Los endpoints del registro están detrás de balanceadores de carga y sus direcciones cambian, así que permita el hostname en lugar de una dirección fija.

El clúster también necesita alcanzar su base de datos en el puerto de PostgreSQL.

El enriquecimiento de explotabilidad es opcional y necesita dos destinos adicionales por HTTPS en el puerto 443. Las puntuaciones EPSS provienen de `api.first.org`, y los datos de CISA KEV provienen de `www.cisa.gov`. Ambos se sirven desde redes de distribución de contenido cuyas direcciones cambian, así que permita los hostnames. Sin ellos, DefectDojo funciona con normalidad y los hallazgos no se enriquecen con datos de EPSS o KEV.

Cuando el tráfico saliente pasa por un proxy en lugar de ser directo, consulte [Ejecución de DefectDojo detrás de un proxy HTTPS de reenvío](/onprem_deployment/forward_proxy/).

## El job de initializer debe finalizar primero

La instalación ejecuta un job de Kubernetes que aplica las migraciones, crea el usuario admin y carga los datos iniciales. Tarda alrededor de quince minutos. Hasta que se complete, el usuario admin no existe y no puede iniciar sesión, aunque la Route ya responda.

Obsérvelo:

```bash
oc get job -n <namespace>
oc logs -f -n <namespace> -l app.kubernetes.io/component=initializer
```

El job termina cuando `oc get job` reporta `1/1` completions.

Los demás pods esperan al initializer mediante un init container. Una vez que la base de datos se ha inicializado, puede definir `dojo.skipInitContainer` en `true` para omitir esa espera en actualizaciones posteriores.

## Verificación

```bash
oc get pods -n <namespace>
oc get route -n <namespace>
oc describe route -n <namespace>
```

Luego abra el hostname de la Route e inicie sesión.

## Solución de problemas

### Pods rechazados por security context constraints

Lo más probable es que la implementación no se haya configurado para OpenShift, por lo que recurrió a valores predeterminados que fijan un ID de usuario que la SCC no permitirá. Otorgar `anyuid` o `privileged` no es la solución y no es necesario.

### El inicio de sesión redirige de vuelta a la página de inicio de sesión

`dojo.secureCookies` está en `true` detrás de una Route con terminación en el borde. Defínalo en `false` y actualice.

### Errores de permisos al montar el volumen en NFS

El `fsGroup` está fuera del rango permitido del namespace. Lea la anotación supplemental-groups y use el inicio del rango.

### Errores Multi-Attach, o pods atascados en ContainerCreating

El volumen es ReadWriteOnce y más de un pod está intentando montarlo. Verifique el claim y la clase detrás de él:

```bash
oc get pvc -n <namespace>
oc describe pod <pod-name> -n <namespace> | tail -30
```

Pase a una clase ReadWriteMany, o a almacenamiento respaldado por NFS.

### Advertencias de certificado en el navegador

El TLS predeterminado de la Route usa el certificado comodín del clúster, que solo cubre nombres bajo el dominio de apps del clúster. Para cualquier otro hostname, suministre su propio certificado.

### Lectura de logs

```bash
oc logs -n <namespace> -l app.kubernetes.io/component=django -c uwsgi --tail=50
oc logs -n <namespace> -l app.kubernetes.io/component=celery-worker --tail=50
```

Para una salida más detallada, tanto `config.logLevel` como `celery.logLevel` aceptan `DEBUG`.

## Actualización

Las actualizaciones siguen el procedimiento estándar. Consulte [Actualización de DefectDojo Pro (On-Premise)](/get_started/pro/onprem/upgrading/).

## Preguntas o soporte

Para obtener ayuda con una implementación en OpenShift, contacte a su representante de cuenta o a [support@defectdojo.com](mailto:support@defectdojo.com).
