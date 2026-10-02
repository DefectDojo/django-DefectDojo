---
title: "Google Cloud Security Command Center"
description: "Einrichtung des Google Cloud Security Command Center Upstream-Connectors für DefectDojo"
weight: 67
audience: pro
---
Der Google-Cloud-SCC-Connector verwendet die Security-Command-Center-v2-REST-API, um aktive Sicherheitsbefunde aus Ihrer Google-Cloud-Organisation, -Ordner oder -Projekt zu importieren. DefectDojo erstellt für jedes Google-Cloud-**Projekt** mit offenen Befunden einen Eintrag.

#### Voraussetzungen

Security Command Center muss für Ihre Organisation **aktiviert** sein (das Standard-Tier ist kostenlos). Anschließend benötigen Sie ein Service-Konto, das Befunde auflisten kann, sowie einen JSON-Schlüssel dafür:

1. Erstellen Sie in Google Cloud ein Service-Konto — ein dediziertes für DefectDojo wird empfohlen.
2. Gewähren Sie ihm die Rolle **Security Center Findings Viewer** (`roles/securitycenter.findingsViewer`) auf der Ebene, aus der Sie importieren möchten (Organisation, Ordner oder Projekt).
3. Erstellen Sie einen **JSON-Schlüssel** für das Service-Konto und laden Sie ihn herunter.

#### Connector-Zuordnungen

1. Lassen Sie das Feld **Location** auf dem Standardwert `https://securitycenter.googleapis.com`, sofern Sie keinen nicht standardmäßigen Endpunkt verwenden.
2. Geben Sie im Feld **Parent Resource** den Geltungsbereich für den Import ein: `organizations/{id}`, `folders/{id}` oder `projects/{id}`.
3. Fügen Sie den vollständigen Inhalt der **JSON-Schlüssel**-Datei des Service-Kontos in das Feld **Service Account Key** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Es werden nur `ACTIVE`, nicht stummgeschaltete Befunde importiert, sodass Befunde, die Sie in SCC deaktivieren oder stummschalten, beim nächsten Sync automatisch in DefectDojo als behoben markiert werden. Das betroffene GCP-Projekt jedes Befunds wird zu dessen Eintrag.
