---
title: Ejecución en producción
description: Para su uso en entornos de producción, se recomiendan ajustes de rendimiento
  y copias de seguridad.
draft: false
weight: 4
audience: opensource
aliases:
- /es/en/open_source/installation/running-in-production
---

## Uso en producción (con Docker Compose)

El archivo docker-compose.yml de este repositorio es totalmente funcional para evaluar DefectDojo en su entorno local.

Aunque Docker Compose es uno de los métodos de instalación compatibles para desplegar una instancia de DefectDojo en contenedores en un entorno de producción, el archivo docker-compose.yml no está pensado para uso en producción sin antes personalizarlo según su situación particular.

Consulte [Ejecución con Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) para obtener más información sobre cómo ejecutar DefectDojo con Docker Compose.

### Requisitos del sistema

Se recomienda usar un servidor de base de datos dedicado en lugar de la base de datos PostgreSQL preconfigurada. Esto mejorará significativamente el rendimiento de DefectDojo.

#### Tamaño de la instancia

Con una base de datos separada, las recomendaciones mínimas para ejecutar DefectDojo son:

-   2 vCPUs
-   8 GB de RAM
-   10 GB de espacio en disco (recuerde que su base de datos no está aquí \-- así que
     lo que tenga disponible para su S/O debería ser suficiente). Podría asignar
    un disco distinto al de su OS\'s para obtener posibles mejoras de
    rendimiento.

### Seguridad
Verifique la configuración de `nginx` y otros aspectos en tiempo de ejecución, como los encabezados de seguridad, para cumplir con sus requisitos de cumplimiento normativo.
Cambie la clave de cifrado AES256 `&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw` en `docker-compose.yml` por algo único para su instancia.
Esta clave de cifrado se utiliza para cifrar claves de API y otras credenciales almacenadas en Defect Dojo para conectarse a herramientas externas como SonarQube. La clave se puede generar de varias maneras, por ejemplo usando un gestor de contraseñas o `openssl`:

```
     openssl rand -base64 32
```
```
      DD_CREDENTIAL_AES_256_KEY: "${DD_CREDENTIAL_AES_256_KEY:-<PUT THE GENERATED KEY HERE>o}"
```

## Copia de seguridad de archivos

En ambos casos (base de datos dedicada o en contenedores), si está autoalojando la instancia, se recomienda implementar y crear copias de seguridad periódicas de sus datos.

### Archivos multimedia

Los archivos multimedia de los archivos cargados, incluidos los modelos de amenazas y las aceptaciones de riesgo, se almacenan en un volumen de docker. Este volumen debe respaldarse regularmente.

## Ajustes de rendimiento

### uWSGI

De forma predeterminada (excepto en modo `ptvsd` para fines de depuración), uWSGI
gestionará 16 conexiones simultáneas.

Según su configuración de recursos, puede ajustar:

-   `DD_UWSGI_NUM_OF_PROCESSES` para el número de procesos generados.
    (predeterminado 4)
-   `DD_UWSGI_NUM_OF_THREADS` para el número de hilos en esos
    procesos. (predeterminado 4)

Por ejemplo, podría tener 4 procesos con 6 hilos cada uno, lo que arroja 24
conexiones simultáneas.

### Celery worker

De forma predeterminada, se genera un único worker de celery monoproceso. Al almacenar una gran cantidad de hallazgos o ejecutar importaciones grandes, puede resultar útil ajustar estos parámetros para evitar el agotamiento de recursos.

Las siguientes variables se pueden modificar para aumentar el rendimiento del worker, manteniendo un único contenedor de celery.

-   `DD_CELERY_WORKER_POOL_TYPE` le permite cambiar a `prefork`.
    (predeterminado `solo`)

Cuando habilita `prefork`, se deben usar las variables de abajo. consulte el
Dockerfile.django-* para ver las referencias dentro del archivo.

-   `DD_CELERY_WORKER_AUTOSCALE_MIN` tiene un valor predeterminado de 2.
-   `DD_CELERY_WORKER_AUTOSCALE_MAX` tiene un valor predeterminado de 8.
-   `DD_CELERY_WORKER_CONCURRENCY` tiene un valor predeterminado de 8.
-   `DD_CELERY_WORKER_PREFETCH_MULTIPLIER` tiene un valor predeterminado de 128.

Puede ejecutar el siguiente comando para ver la configuración:

`docker compose exec celerybeat bash -c "celery -A dojo inspect stats"`
y ver qué está en vigor.

### Importación asíncrona: obsoleta
Esta función se eliminó en la versión 2.47.0
