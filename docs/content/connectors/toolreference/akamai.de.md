---
title: "Akamai API Security"
description: "Einrichtung des Akamai API Security Upstream-Connectors für DefectDojo"
weight: 13
audience: pro
---
Der Akamai-API-Security-Connector verwendet einen API-Schlüssel, um Sicherheitsbefunde von der Akamai-API abzurufen. DefectDojo ermittelt Ihre Akamai-Umgebung und erstellt separate Einträge für jede in Ihrem Konto konfigurierte **Application** und jeden **Host**.

#### Voraussetzungen

Sie benötigen einen API-Schlüssel mit Zugriff auf die Akamai-API. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, um automatisierte Aktivitäten klar von manuellen Team-Aktionen zu unterscheiden.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL Ihrer Akamai-API in das Feld **Location** ein. Diese URL ist spezifisch für Ihre Akamai-Instanz, zum Beispiel
2. Geben Sie einen gültigen **API Key** in das Feld **Secret** ein.

DefectDojo ordnet **Applications** und **Hosts** als separate Einträge zu. Jede Application erscheint als `{name} (application)` und jeder Host als `{name} (host)` in Ihrer Eintragsliste.
