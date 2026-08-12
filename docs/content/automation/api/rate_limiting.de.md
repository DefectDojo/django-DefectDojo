---
title: Ratenbegrenzung
description: Ratenbegrenzung auf der Anmeldeseite konfigurieren, um Brute-Force-Angriffe
  abzuschwächen
weight: 4
audience: opensource
aliases:
- /de/en/open_source/rate_limiting
---

DefectDojo enthält eine Ratenbegrenzung für die Anmeldeseite zum Schutz vor Brute-Force-Angriffen, umgesetzt mit [Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/index.html).

## Konfiguration

Die Ratenbegrenzung wird über die folgenden Einstellungen konfiguriert (siehe [Konfiguration](/get_started/open_source/configuration/) für die Anwendung dieser Einstellungen):

```python
DD_RATE_LIMITER_ENABLED=(bool, True),
DD_RATE_LIMITER_RATE=(str, '5/m'),
DD_RATE_LIMITER_BLOCK=(bool, True),
DD_RATE_LIMITER_ACCOUNT_LOCKOUT=(bool, True),
```

### Ratenlimit (`DD_RATE_LIMITER_RATE`)

Legt fest, wie häufig Anfragen begrenzt werden. Unterstützte Einheiten:

- Sekunden: `1s`
- Minuten: `5m`
- Stunden: `100h`
- Tage: `2400d`

Weitere Konfigurationsmöglichkeiten finden Sie in der [Dokumentation zu den Raten von Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/rates.html).

### Anfragen blockieren (`DD_RATE_LIMITER_BLOCK`)

Standardmäßig protokolliert die Ratenbegrenzung Verstöße, blockiert Anfragen aber nicht. Wird `DD_RATE_LIMITER_BLOCK` auf `True` gesetzt, werden alle eingehenden Anfragen aktiv blockiert, sobald die konfigurierte Rate überschritten wird.

### Kontosperrung (`DD_RATE_LIMITER_ACCOUNT_LOCKOUT`)

Ist diese Option aktiviert, muss ein Benutzer, dessen Anmeldeversuche die Ratenbegrenzung auslösen, sein Passwort zurücksetzen, bevor er sich wieder anmelden kann. Das verringert das Risiko einer Kompromittierung von Zugangsdaten während eines Brute-Force-Angriffs.

## Verhalten bei mehreren Prozessen

Beim Betrieb mit mehreren `uwsgi`-Prozessen verwendet das Paket für die Ratenbegrenzung einen speicherbasierten Cache, der für jeden Prozess lokal ist. Die Zähler der Ratenbegrenzung werden in dieser Standardkonfiguration nicht prozessübergreifend geteilt.
