---
title: Konfiguration
description: DefectDojo ist in hohem Maß konfigurierbar.
draft: false
weight: 2
audience: opensource
aliases:
- /de/en/open_source/installation/configuration
---

## dojo/settings/settings.dist.py

Die wichtigsten Einstellungen liegen in [`dojo/settings/settings.dist.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py). Diese Datei eignet sich sehr gut als Referenz dafür, was konfiguriert werden kann, sie sollte jedoch nicht direkt bearbeitet werden, da Änderungen beim Aktualisieren von DefectDojo überschrieben werden. Es gibt mehrere Wege, die Standardeinstellungen zu ändern:

### Umgebungsvariablen

Die meisten Parameter lassen sich über Umgebungsvariablen setzen. 

Wenn Sie DefectDojo über **Docker Compose** bereitstellen, können Sie Umgebungsvariablen in [`docker-compose.yml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docker-compose.yml) setzen. Beachten Sie, dass Sie die Variablen für drei Dienste setzen müssen: `uwsgi`, `celerybeat` und `celeryworker`.

Wenn Sie DefectDojo in einem **Kubernetes**-Cluster bereitstellen, können Sie Umgebungsvariablen als `extraConfigs` und `extraSecrets` in [`helm/defectdojo/values.yaml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/helm/defectdojo/values.yaml) setzen.

### Umgebungsdatei (nicht bei Docker Compose oder Kubernetes)

`settings.dist.py` liest Umgebungsvariablen aus einer Datei, deren Name in der Umgebungsvariablen `DD_ENV_PATH` angegeben ist. Ist diese Variable nicht gesetzt, wird der Standardwert `.env.prod` verwendet. Die Datei muss im Verzeichnis `dojo/settings` liegen.

Ein Beispiel finden Sie in [`template_env`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-env).

### local_settings.py

`local_settings.py` kann komplexere Anpassungen enthalten, etwa zusätzliche MIDDLEWARE- oder INSTALLED_APP-Einträge.
Diese Datei wird *nach* settings.dist.py verarbeitet, sodass Sie von DefectDojo standardmäßig gelieferte Einstellungen anpassen können.
 Die Datei muss im Verzeichnis `dojo/settings` liegen. Umgebungsvariablen in dieser Datei dürfen nicht das Präfix `DD_` haben.
Fehlt die Datei, können Sie sie einfach anlegen. Bearbeiten Sie `settings.dist.py` nicht direkt.

Ein Beispiel finden Sie in [`dojo/settings/template-local_settings`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-local_settings).

Im Release-Modus von Docker Compose werden Dateien in `docker/extra_settings/` (relativ zur Datei `docker-compose.yml`) beim Start in `dojo/settings/` im Docker-Container kopiert.

`local_settings.py` lässt sich auch in Kubernetes verwenden. Die Variable `localsettingspy` wird als ConfigMap gespeichert und an der zuständigen Stelle in den Containern eingebunden.

## Konfiguration in der Benutzeroberfläche

Benutzer mit Superuser-Status können weitere Optionen über die Benutzeroberfläche unter `Configuration` / `System Settings` konfigurieren. 
