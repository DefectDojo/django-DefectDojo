---
title: Betrieb in der Produktion
description: Für den Einsatz in Produktionsumgebungen werden Performance-Anpassungen
  und Backups empfohlen.
draft: false
weight: 4
audience: opensource
aliases:
- /de/en/open_source/installation/running-in-production
---

## Produktiveinsatz (mit Docker Compose)

Die Datei docker-compose.yml in diesem Repository ist voll funktionsfähig, um DefectDojo in Ihrer lokalen Umgebung zu evaluieren.

Docker Compose ist zwar eine der unterstützten Installationsmethoden, um ein containerisiertes DefectDojo in einer Produktionsumgebung zu betreiben, die Datei docker-compose.yml ist jedoch nicht für den Produktiveinsatz gedacht, ohne sie zuvor an Ihre konkrete Situation anzupassen.

Weitere Informationen zum Betrieb von DefectDojo mit Docker Compose finden Sie unter [Betrieb mit Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md).

### Systemanforderungen

Es wird empfohlen, einen dedizierten Datenbankserver zu verwenden und nicht die vorkonfigurierte PostgreSQL-Datenbank. Das verbessert die Performance von DefectDojo deutlich.

#### Instanzgröße

Mit einer separaten Datenbank gelten für den Betrieb von DefectDojo folgende Mindestempfehlungen:

-   2 vCPUs
-   8 GB RAM
-   10 GB Festplattenspeicher (denken Sie daran: Ihre Datenbank liegt nicht hier,
     was Sie für Ihr Betriebssystem vorgesehen haben, sollte also genügen). Für mögliche
    Performance-Verbesserungen können Sie eine andere Festplatte als die
    des Betriebssystems verwenden.

### Sicherheit
Prüfen Sie die `nginx`-Konfiguration und weitere Laufzeitaspekte wie Security-Header, damit sie Ihre Compliance-Anforderungen erfüllen.
Ändern Sie den AES256-Schlüssel `&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw` in `docker-compose.yml` in einen für Ihre Instanz einzigartigen Wert.
Dieser Schlüssel verschlüsselt API-Schlüssel und andere in Defect Dojo gespeicherte Zugangsdaten für die Verbindung zu externen Tools wie SonarQube. Ein Schlüssel kann auf verschiedene Weise erzeugt werden, zum Beispiel mit einem Passwortmanager oder `openssl`:

```
     openssl rand -base64 32
```
```
      DD_CREDENTIAL_AES_256_KEY: "${DD_CREDENTIAL_AES_256_KEY:-<PUT THE GENERATED KEY HERE>o}"
```

## Dateisicherung

In beiden Fällen (dedizierte DB oder containerisiert) wird beim Self-Hosting empfohlen, regelmäßige Backups Ihrer Daten einzurichten und zu erstellen.

### Mediendateien

Mediendateien für hochgeladene Dateien, darunter Threat Models und Risikoakzeptanz, werden in einem Docker-Volume gespeichert. Dieses Volume muss regelmäßig gesichert werden.

## Performance-Anpassungen

### uWSGI

Standardmäßig (außer im `ptvsd`-Modus zum Debuggen) verarbeitet uWSGI
16 gleichzeitige Verbindungen.

Abhängig von Ihren Ressourceneinstellungen können Sie anpassen:

-   `DD_UWSGI_NUM_OF_PROCESSES` für die Anzahl der gestarteten Prozesse.
    (Standard 4)
-   `DD_UWSGI_NUM_OF_THREADS` für die Anzahl der Threads in diesen
    Prozessen. (Standard 4)

Sie können zum Beispiel 4 Prozesse mit je 6 Threads betreiben, was 24
gleichzeitige Verbindungen ergibt.

### Celery worker

Standardmäßig wird ein einzelner Celery-Worker mit nur einem Prozess gestartet. Beim Speichern großer Mengen von Befunden oder bei großen Importen kann es hilfreich sein, diese Parameter anzupassen, um Ressourcenengpässe zu vermeiden.

Die folgenden Variablen können geändert werden, um die Worker-Performance zu erhöhen und dabei einen einzelnen Celery-Container beizubehalten.

-   `DD_CELERY_WORKER_POOL_TYPE` erlaubt den Wechsel zu `prefork`.
    (Standard `solo`)

Wenn Sie `prefork` aktivieren, müssen die folgenden
Variablen verwendet werden. Siehe die
Dockerfile.django-* für Verweise in den Dateien.

-   `DD_CELERY_WORKER_AUTOSCALE_MIN` hat den Standardwert 2.
-   `DD_CELERY_WORKER_AUTOSCALE_MAX` hat den Standardwert 8.
-   `DD_CELERY_WORKER_CONCURRENCY` hat den Standardwert 8.
-   `DD_CELERY_WORKER_PREFETCH_MULTIPLIER` hat den Standardwert 128.

Mit dem folgenden Befehl können Sie die Konfiguration einsehen:

`docker compose exec celerybeat bash -c "celery -A dojo inspect stats"`
und erkennen, welche Werte wirksam sind.

### Asynchroner Import: Veraltet
Diese Funktion wurde in 2.47.0 entfernt
