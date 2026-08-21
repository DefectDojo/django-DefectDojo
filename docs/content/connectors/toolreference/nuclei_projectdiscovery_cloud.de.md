---
title: "Nuclei (ProjectDiscovery Cloud)"
description: "Einrichtung des Nuclei (ProjectDiscovery Cloud) Upstream-Connectors für DefectDojo"
weight: 97
audience: pro
---
Der Nuclei-Connector verwendet die REST-API der ProjectDiscovery Cloud Platform (PDCP), um [nuclei](https://github.com/projectdiscovery/nuclei)-Scan-Ergebnisse aus Ihrem PDCP-Konto abzurufen. DefectDojo ermittelt jeden Scan im Konto und erstellt für jeden **Scan** einen separaten Eintrag.

#### Voraussetzungen

Sie benötigen einen ProjectDiscovery-Cloud-**API-Schlüssel**. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, um automatisierte Aktivitäten klar von manuellen Team-Aktionen zu unterscheiden. Generieren Sie einen Schlüssel unter **Settings \> API Key** in der ProjectDiscovery-Cloud-Oberfläche ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)). Ergebnisse gelangen entweder über gehostete Scans oder über die mit `-dashboard` ausgeführte nuclei-CLI zu PDCP.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL der PDCP-API in das Feld **Location** ein: `https://api.projectdiscovery.io`.
2. Geben Sie Ihren **API-Schlüssel** in das Feld **Secret** ein.
3. Geben Sie optional eine **Team ID** ein, um den Sync auf einen Team-Workspace zu beschränken (zu finden unter **Settings \> Team**). Bleibt das Feld leer, synchronisiert DefectDojo Ihren persönlichen Workspace.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jeden PDCP-**Scan** als separaten Eintrag zu und importiert dessen Befunde über alle Schweregrade hinweg, einschließlich informativer.
