---
title: Límites de tamaño de carga para archivos de escaneo grandes
description: Por qué falla la carga de un archivo de escaneo grande, y qué límite
  aumentar en implementaciones de Kubernetes y Docker Compose
draft: false
weight: 10
audience: pro
---

Un archivo de escaneo grande puede ser rechazado por más de un límite, en distintos puntos de la ruta de la solicitud, y el error que recibe le indica cuál alcanzó. Esta página explica dónde están esos límites y cómo aumentarlos en una implementación autoalojada.

## Qué límite estoy alcanzando

| Lo que ve | De dónde proviene |
| --- | --- |
| Un simple `413 Request Entity Too Large`, sin estilo, sin ninguna página de DefectDojo alrededor | El controlador de ingress rechazó la solicitud antes de que llegara a la aplicación |
| `Report file is too large. Maximum supported size is N MB` | El límite de la aplicación, reportado por el propio DefectDojo |
| La carga se ejecuta durante un tiempo y luego falla, en lugar de ser rechazada de inmediato | Un tiempo de espera agotado (timeout) en lugar de un límite de tamaño |

Trabaje de afuera hacia adentro. No tiene sentido aumentar el límite de la aplicación si el controlador de ingress está rechazando la solicitud primero.

## El límite de la aplicación

DefectDojo impone su propio tamaño máximo de archivo de escaneo, y rechaza cualquier archivo más grande con un mensaje que indica el límite actual. El valor predeterminado es 100 MB.

En el chart de Helm, configúrelo en sus valores:

```yaml
dojo:
  scanMaxFileSize: 100
```

Para implementaciones con Docker Compose, configure en su lugar `DD_SCAN_FILE_MAX_SIZE`, en megabytes.

## El límite del ingress

Este es el que produce un `413` desnudo sin ningún estilo de DefectDojo, porque la solicitud nunca llega a la aplicación.

El chart establece un límite de tamaño del cuerpo de la solicitud en el ingress, con un valor predeterminado de 2400 MB:

```yaml
django:
  ingress:
    maxBodySize: "2400m"
```

Ese valor se emite como la anotación `nginx.ingress.kubernetes.io/proxy-body-size`. Se emite en todas las plataformas y no solo en Kubernetes genérico, porque el controlador de ingress nginx suele usarse delante de una plataforma administrada. Establecerlo como una cadena vacía omite la anotación, y requiere que `django.ingress.platformAnnotations.enabled` esté activo, lo cual es así por defecto.

Los controladores distintos de nginx ignoran esa anotación, así que en ellos debe aumentar el límite mediante el propio mecanismo del controlador:

| Controlador predeterminado de la plataforma | Dónde vive el límite |
| --- | --- |
| EKS con el AWS Load Balancer Controller | Configuración del ALB |
| GKE con el controlador de ingress de GCE | Configuración del balanceador de carga |
| AKS con Application Gateway | El límite de tamaño del cuerpo de solicitud de Application Gateway |
| OpenShift Route | `tuningOptions` de HAProxy en el router |

### Tiempos de espera cuando nginx está delante de una plataforma administrada

El chart emite tiempos de espera generosos para el proxy nginx, 1800 segundos para lectura, envío y conexión, junto con el buffering del proxy desactivado. Esas anotaciones solo se emiten cuando la plataforma es Kubernetes genérico. En EKS, GKE, AKS y OpenShift el chart emite en su lugar las anotaciones propias de esa plataforma, porque eso es lo que lee su controlador predeterminado.

Esto importa si ejecuta el controlador de ingress nginx en una de esas plataformas. Obtiene la anotación de tamaño del cuerpo, ya que esa se emite en todas partes, pero no los tiempos de espera. Una carga grande puede entonces superar la verificación de tamaño y aun así cortarse a mitad de camino por el tiempo de espera predeterminado del controlador, que es de donde proviene la tercera fila de la tabla anterior. Proporcione usted mismo los tiempos de espera:

```yaml
django:
  ingress:
    annotations:
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"
```

## El límite de la ruta de importación

Las implementaciones en Kubernetes ejecutan las importaciones de escaneos a través de pods dedicados, y el nginx que está delante de las rutas de importación tiene su propio límite de tamaño de cuerpo. Se calcula en lugar de ser fijo:

```yaml
django:
  uwsgiImport:
    maxBodySizeMb: null
```

Dejado en `null`, se calcula como `dojo.scanMaxFileSize` más 5 MB, el margen que cubre la sobrecarga de la codificación multipart. Aumentar el límite de la aplicación por lo tanto aumenta este también, y la mayoría de las implementaciones nunca necesitan configurarlo. Establezca un entero solo si desea anular el valor calculado.

## Implementaciones con Docker Compose

Las implementaciones con Compose no tienen controlador de ingress, por lo que el límite de ingress no se aplica. El nginx que se incluye en la implementación limita el cuerpo de las solicitudes a 800 MB, que es el tope práctico, y el límite de la aplicación se aplica por encima de eso como en todas partes.

Aumentar el límite de nginx implica cambiar un archivo que se incluye con la implementación, y esos archivos se reemplazan al actualizar en lugar de conservarse como su directorio de personalizaciones. Contacte a soporte antes de cambiarlo, para que el cambio no desaparezca en la próxima actualización.

## Preguntas o soporte

Si las cargas siguen fallando después de aumentar el límite que coincide con su síntoma, recopile la respuesta que recibió su cliente y los registros de nginx o del controlador que cubren el intento, y luego contacte a [support@defectdojo.com](mailto:support@defectdojo.com).
