---
title: "Bright Security"
description: "Einrichtung des Bright Security Upstream-Connectors für DefectDojo"
weight: 28
audience: pro
---
Der Bright-Security-Connector verwendet die [Bright](https://brightsec.com)-API (ehemals NeuraLegion), um **DAST-Befunde** zu importieren. DefectDojo ermittelt jeden Scan, auf den das Token zugreifen kann, und erstellt für jeden abgeschlossenen Scan einen Eintrag; anschließend werden die Issues dieses Scans als Befunde importiert.

#### Voraussetzungen

Sie benötigen einen Bright-**API-Schlüssel**, der in der Bright-App unter **User settings → API keys** erstellt wird (ein `Org`- oder persönlicher Schlüssel). Der Schlüssel wird im Header `Authorization: Api-Key` gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Behalten Sie den vorgegebenen Wert im Feld **Location**, `https://app.brightsec.com`, oder geben Sie Ihren Bright-Host explizit an.
2. Geben Sie den Bright-API-Schlüssel in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jeden abgeschlossenen **Scan** einem Eintrag zu und jedes **Issue** einem Befund: Der Schweregrad stammt aus Brights eigener Bewertung (Critical/High/Medium/Low), der CVSS-Score, die CWE und die Abhilfemaßnahme werden übernommen, der betroffene Entry Point wird zum Endpunkt, und der Request/Response-Nachweis wird in die Beschreibung aufgenommen. Befunde werden als dynamische Befunde erfasst und anhand der Bright-Issue-ID dedupliziert.

Weitere Informationen finden Sie in der [Bright-API-Dokumentation](https://docs.brightsec.com/).
