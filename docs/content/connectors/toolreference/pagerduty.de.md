---
title: "PagerDuty"
description: "Einrichtung des PagerDuty Downstream-Connectors für DefectDojo"
weight: 102
audience: pro
---
Die PagerDuty-Integration ermöglicht es Ihnen, DefectDojo-Befunde und Befundgruppen als PagerDuty-Incidents zu übertragen, die auf einem PagerDuty-Service Ihrer Wahl eröffnet werden.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf `https://api.pagerduty.com` gesetzt werden.  Wird Ihr PagerDuty-Konto in der EU-Serviceregion gehostet, verwenden Sie stattdessen `https://api.eu.pagerduty.com`.
- **API Token** sollte auf einen PagerDuty-REST-API-Key gesetzt werden.  Ein Kontoadministrator kann einen solchen in der PagerDuty-Web-App unter **Integrations > API Access Keys > Create New API Key** erstellen.  Lassen Sie „Read-only“ deaktiviert - DefectDojo muss Incidents erstellen und aktualisieren.
- **From Email** sollte die E-Mail-Adresse eines gültigen Benutzers in Ihrem PagerDuty-Konto sein.  PagerDuty verlangt diese Adresse beim Erstellen oder Aktualisieren von Incidents, und sie wird als Anforderer des Incidents angezeigt.

### Issue-Tracker-Zuordnung

- **Service ID** sollte die ID des PagerDuty-Services sein, auf dem Incidents eröffnet werden.  Sie finden sie am Ende der URL, während Sie den Service in PagerDuty ansehen, zum Beispiel `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`.

### Details zur Schweregrad-Zuordnung

Standardmäßig wird dies dem PagerDuty-Incident-Feld **Urgency** zugeordnet, das nur `high` oder `low` akzeptiert:

- **Name des Schweregrad-Felds**: `Urgency`
- **Info-Zuordnung**: `low`
- **Niedrig-Zuordnung**: `low`
- **Mittel-Zuordnung**: `low`
- **Hoch-Zuordnung**: `high`
- **Kritisch-Zuordnung**: `high`

Alternativ können Sie, wenn in Ihrem PagerDuty-Konto [Priorities](https://support.pagerduty.com/main/docs/incident-priority) aktiviert sind, Schweregrade stattdessen Prioritätsnamen zuordnen.  Setzen Sie den **Namen des Schweregrad-Felds** auf `Priority` und verwenden Sie die Prioritätsnamen Ihres Kontos (zum Beispiel `P1` bis `P5`) als Zuordnungswerte.  Bei einer Zuordnung auf Priority bleibt die Urgency des Incidents den Urgency-Regeln Ihres Services überlassen.

### Details zur Status-Zuordnung

PagerDuty-Incidents haben drei Status: `triggered`, `acknowledged` und `resolved`.

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `triggered`
- **Geschlossen-Zuordnung**: `resolved`
- **Falsch-positiv-Zuordnung**: `resolved`
- **Risiko-akzeptiert-Zuordnung**: `acknowledged`

Beachten Sie, dass `resolved` in PagerDuty ein endgültiger Status ist - ein aufgelöster Incident kann nicht wieder geöffnet werden.  Beachten Sie außerdem, dass PagerDuty es nicht erlaubt, Titel oder Beschreibung eines Incidents nach dem Erstellen zu bearbeiten; beim Übertragen eines aktualisierten Befunds werden daher Status, Urgency und Priority synchronisiert, Inhaltsänderungen jedoch nicht.
