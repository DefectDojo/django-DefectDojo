---
title: Configuración
description: DefectDojo es altamente configurable.
draft: false
weight: 2
audience: opensource
aliases:
- /es/en/open_source/installation/configuration
---

## dojo/settings/settings.dist.py

La configuración principal se almacena en [`dojo/settings/settings.dist.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py). Es útil usar este archivo como referencia de lo que se puede configurar, pero no debe editarse directamente, porque los cambios se sobrescribirán al actualizar DefectDojo. Existen varios métodos para modificar la configuración predeterminada:

### Variables de entorno

La mayoría de los parámetros se pueden establecer mediante variables de entorno.

Cuando despliega DefectDojo mediante **Docker Compose**, puede establecer variables de entorno en [`docker-compose.yml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docker-compose.yml). Tenga en cuenta que debe configurar las variables para tres servicios: `uwsgi`, `celerybeat` y `celeryworker`.

Cuando despliega DefectDojo en un clúster de **Kubernetes**, puede establecer variables de entorno como `extraConfigs` y `extraSecrets` en [`helm/defectdojo/values.yaml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/helm/defectdojo/values.yaml).

### Archivo de entorno (no aplica con Docker Compose ni Kubernetes)

`settings.dist.py` lee las variables de entorno de un archivo cuyo nombre se especifica en la variable de entorno `DD_ENV_PATH`. Si esta variable no está definida, se usa el valor predeterminado `.env.prod`. El archivo debe ubicarse en el directorio `dojo/settings`.

Puede encontrar un ejemplo en [`template_env`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-env).

### local_settings.py

`local_settings.py` puede contener personalizaciones más complejas, como añadir entradas de MIDDLEWARE o INSTALLED_APP.
Este archivo se procesa *después* de que se procesa settings.dist.py, por lo que puede modificar la configuración que DefectDojo entrega de fábrica.
 El archivo debe ubicarse en el directorio `dojo/settings`. Las variables de entorno de este archivo no deben llevar el prefijo `DD_`.
Si el archivo no existe, puede crearlo sin problema. No edite `settings.dist.py` directamente.

Puede encontrar un ejemplo en [`dojo/settings/template-local_settings`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-local_settings).

En el modo de release de Docker Compose, los archivos de `docker/extra_settings/` (relativo al archivo `docker-compose.yml`) se copiarán en `dojo/settings/` dentro del contenedor de docker al iniciar.

`local_settings.py` también se puede usar en Kubernetes. La variable `localsettingspy` se almacenará como ConfigMap y se montará en la ubicación correspondiente de los contenedores.

## Configuración en la UI

Los usuarios con estado de superusuario pueden configurar más opciones mediante la UI, en `Configuration` / `System Settings`.
