---
title: "CrowdStrike Falcon"
description: "Einrichtung des CrowdStrike Falcon Upstream-Connectors für DefectDojo"
weight: 41
audience: pro
---
Der CrowdStrike-Falcon-Connector importiert **Spotlight-Schwachstellen** und **EDR-Detections** von der Falcon-Plattform als zwei separate Befundtypen (`CrowdStrike:Spotlight` und `CrowdStrike:Detections`). DefectDojo erstellt für jeden Falcon-**Host** einen Eintrag.

#### Voraussetzungen

Ein Falcon-**API-Client** (Client ID und Secret), erstellt in der Falcon-Konsole unter **Support \> API Clients and Keys**. Gewähren Sie ihm die Scopes für die zu importierenden Daten: **Hosts: Read** (erforderlich, für die Host-Ermittlung), **Vulnerabilities (Spotlight): Read** (für Spotlight-Befunde) und **Alerts: Read** (für EDR-Detections). Die beiden Befundtypen sind unabhängig voneinander — fehlt dem Client ein Scope, wird dieser Befundtyp übersprungen, statt den Sync scheitern zu lassen; ein Client ohne **Alerts: Read** importiert also weiterhin Spotlight-Schwachstellen.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL der API Ihrer Falcon-Cloud in das Feld **Location** ein, passend zu Ihrer Konsolen-Region — zum Beispiel `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1) oder `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Geben Sie die Client ID des API-Clients in das Feld **Client ID** ein.
3. Geben Sie das Secret des API-Clients in das Feld **Client Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jeder Falcon-Host wird zu einem Eintrag, benannt nach Hostname, Betriebssystem und Typ. Es werden nur Spotlight-Schwachstellen mit dem Status **open** und **reopened** importiert, sodass ein erneuter Import behobene Befunde schließt.
