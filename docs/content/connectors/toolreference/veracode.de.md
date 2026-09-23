---
title: "Veracode"
description: "Einrichtung des Veracode Upstream-Connectors für DefectDojo"
weight: 137
audience: pro
---
Der Veracode-Connector importiert Anwendungsbefunde von der Veracode-Plattform, aufgeteilt nach Scan-Typ in die Befundtypen **SAST**, **DAST**, **SCA** und **Manual**. DefectDojo erstellt für jede Veracode-**Anwendung** einen Eintrag.

#### Voraussetzungen

Generieren Sie eine Veracode-**API-Anmeldeinformation** für ein Konto, das die zu importierenden Anwendungen sehen kann: Öffnen Sie in der Veracode-Plattform Ihr Kontomenü \> **API Credentials** und wählen Sie **Generate API Credentials** (siehe [Managing Veracode API credentials](https://docs.veracode.com/r/c_api_credentials3)). Kopieren Sie sowohl die **API ID** als auch den **API Secret Key** — das Secret wird nur einmal angezeigt.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL der Veracode-API in das Feld **Location** ein: `https://api.veracode.com` (kommerzielle Region), `https://api.veracode.eu` (europäische Region) oder `https://api.veracode.us` (US-Bundesregion).
2. Geben Sie die API ID in das Feld **API ID** ein.
3. Geben Sie den API Secret Key in das Feld **Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede Veracode-Anwendung wird zu einem Eintrag. Es werden nur **offene** Befunde importiert, sodass ein erneuter Import von Veracode als behoben gemeldete Befunde schließt.
