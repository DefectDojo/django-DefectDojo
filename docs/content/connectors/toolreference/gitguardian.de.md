---
title: "GitGuardian"
description: "Einrichtung des GitGuardian Upstream-Connectors für DefectDojo"
weight: 62
audience: pro
---
Der GitGuardian-Connector verwendet die GitGuardian-REST-API, um **Secret-Incidents** zu importieren — von GitGuardian erkannte offengelegte Anmeldedaten in Ihren überwachten Quellen. DefectDojo erstellt für jede überwachte Quelle (Repository oder Perimeter) mit derzeit offenen Incidents einen Eintrag und importiert jeden offenen Incident als Befund.

Zu Ihrer Sicherheit importiert der Connector nur Incident-**Metadaten** — den Detektor, den Schweregrad, die Gültigkeit, den Status und einen Link zurück zu GitGuardian. Der offengelegte Secret-Wert selbst wird von DefectDojo nie abgerufen oder gespeichert; folgen Sie dem Link in jedem Befund, um die betroffenen Stellen in GitGuardian zu prüfen.

#### Voraussetzungen

Sie benötigen einen GitGuardian-API-Schlüssel. Wir empfehlen ein **Service-Account-Token** (statt eines persönlichen Zugriffstokens), damit automatisierte Aktivitäten leicht zu unterscheiden sind. Erstellen Sie es unter **API** im GitGuardian-Dashboard und gewähren Sie diese Lese-Scopes:

* `incidents:read`
* `sources:read`

#### Connector-Zuordnungen

1. Geben Sie Ihre GitGuardian-API-URL in das Feld **Location** ein: `https://api.gitguardian.com` für die SaaS-Plattform, oder die API-URL Ihrer selbstgehosteten Instanz.
2. Geben Sie den API-Schlüssel in das Feld **Secret** ein.

Es werden nur **offene** Incidents (Status `TRIGGERED` oder `ASSIGNED`) importiert; Incidents, die Sie in GitGuardian beheben oder ignorieren, werden beim nächsten Sync automatisch in DefectDojo als behoben markiert. Ein bestätigt aktives Secret (Gültigkeit *valid*) wird als verifizierter Befund importiert.
