---
title: "HCL AppScan"
description: "Einrichtung des HCL AppScan Upstream-Connectors für DefectDojo"
weight: 73
audience: pro
---
Der HCL-AppScan-Connector verwendet die AppScan-v4-REST-API, um Issues aus **AppScan on Cloud (ASoC)** oder einem selbstgehosteten **AppScan 360°** zu importieren (beide teilen sich die API). Er synchronisiert das gesamte Konto: DefectDojo ermittelt jede Anwendung und erstellt für jede einen Eintrag; anschließend werden die Issues dieser Anwendung (DAST, SAST und IAST) als Befunde importiert.

#### Voraussetzungen

Sie benötigen einen AppScan-**API-Schlüssel** — eine Key ID und ein Key Secret, generiert unter Ihren AppScan-Kontoeinstellungen (API Key). Der Connector tauscht diese bei jedem Lauf gegen ein kurzlebiges Session-Token ein; Key ID, Key Secret und Token werden nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie die AppScan-Konsolen-URL in das Feld **Location** ein: Verwenden Sie für ASoC `https://cloud.appscan.com` (oder `https://eu.cloud.appscan.com` für die EU-Region); verwenden Sie für AppScan 360° den Host Ihrer Instanz.
2. Setzen Sie **Provider** auf `ASOC` für AppScan on Cloud oder auf `A360` für ein selbstgehostetes AppScan 360°.
3. Geben Sie die **API Key ID** und das **API Key Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jede AppScan-**Anwendung** einem Eintrag (VEP) zu und jedes **Issue** einem Befund: Der Titel ist der Issue-Typ mit angehängter Domain/Entität/Cause-ID/URL/Pfad; der Schweregrad bildet Informational auf Info ab (Low/Medium/High/Critical werden unverändert übernommen); die CWE, eine beschriftete Beschreibung, die Abhilfemaßnahme und der Hinweis sowie der Host/Port-Endpunkt werden übernommen. Issues aus statischer Analyse werden als statische Befunde erfasst und dynamische/interaktive Issues als dynamische Befunde; offene Issues sind aktiv, und behobene/bestandene Issues sind behoben.

Weitere Informationen finden Sie in der [AppScan-REST-API-Dokumentation](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html).
