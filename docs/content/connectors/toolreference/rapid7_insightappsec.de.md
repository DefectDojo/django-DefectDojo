---
title: "Rapid7 InsightAppSec"
description: "Einrichtung des Rapid7 InsightAppSec Upstream-Connectors für DefectDojo"
weight: 112
audience: pro
---
Der Rapid7-InsightAppSec-Connector importiert **DAST-Schwachstellenbefunde** von der InsightAppSec-Cloud-Plattform, angereichert mit Attack-Module-Metadaten (zum Beispiel *SQL Injection*), CVSS-Scores und den vom Scan gesammelten Nachweisen. DefectDojo erstellt für jede InsightAppSec-**App** einen Eintrag.

**Bitte beachten Sie:** Dieser Connector unterscheidet sich vom **Rapid7-InsightVM**-Connector weiter unten — InsightAppSec ist Rapid7s Cloud-DAST-Produkt auf der Insight-Plattform, während InsightVM-Befunde aus Ihrer eigenen Security Console stammen.

#### Voraussetzungen

Ein Insight-Platform-Konto mit InsightAppSec sowie ein Platform-**API-Schlüssel**: Öffnen Sie in der [Rapid7-Insight-Plattform](https://insight.rapid7.com) das Einstellungsmenü (Zahnrad) \> **API Keys** und generieren Sie einen **User Key** (beliebige Rolle) oder einen **Organization Key** (Platform-Admins). Kopieren Sie den Schlüssel, wenn er angezeigt wird — er wird nur einmal angezeigt.

Sie benötigen außerdem Ihre Platform-**Region**, sichtbar in Ihrer Insight-URL (zum Beispiel `us`, `us2`, `us3`, `eu`, `ca`, `au` oder `ap`).

#### Connector-Zuordnungen

1. Geben Sie Ihren regionalen API-Endpunkt in das Feld **Location** ein — zum Beispiel `https://us.api.insight.rapid7.com` (ersetzen Sie `us` durch Ihre Region).
2. Geben Sie den API-Schlüssel der Insight-Plattform in das Feld **API Key** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede InsightAppSec-App wird zu einem Eintrag. Es werden nur **offene** Schwachstellen (Unreviewed oder Verified) importiert — Befunde, die Rapid7 als Remediated, False Positive, Ignored oder Duplicate markiert hat, werden ausgeschlossen, sodass ein erneuter Import sie in DefectDojo schließt. Schweregrade werden direkt abgebildet (`SAFE` und `INFORMATIONAL` werden als Info importiert).
