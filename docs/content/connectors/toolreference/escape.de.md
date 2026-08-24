---
title: "Escape"
description: "Einrichtung des Escape Upstream-Connectors für DefectDojo"
weight: 55
audience: pro
---
Der Escape-Connector verwendet die [Escape](https://escape.tech)-API, um **API-Sicherheits(DAST)-Befunde** zu importieren. DefectDojo zählt jede Organisation, auf die das Token zugreifen kann, sowie jede Anwendung darin auf, erstellt für jede Anwendung mit einem Scan einen Eintrag und importiert die Issues des letzten Scans dieser Anwendung als Befunde — es gibt keine Pro-Anwendungs-Konfiguration.

#### Voraussetzungen

Sie benötigen einen Escape-**API-Schlüssel**, der in der Escape-App unter **Settings → API keys** erstellt wird. Der Schlüssel wird im Header `Authorization: Key` gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Behalten Sie den vorgegebenen Wert im Feld **Location**, `https://public.escape.tech/v2`, oder geben Sie Ihren Escape-API-Host explizit an.
2. Geben Sie den Escape-API-Schlüssel in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jede **Anwendung** einem Eintrag zu und jedes Scan-**Issue** einem Befund: Der Schweregrad stammt aus Escapes Bewertung (Critical/High/Medium/Low), die CWE wird übernommen, die OWASP-Kategorie und die HTTP-Methode werden zu Tags, die betroffene URL wird zum Endpunkt, und die Abhilfehinweise werden einbezogen. Befunde werden als dynamische Befunde erfasst und anhand der Escape-Issue-ID dedupliziert.

Weitere Informationen finden Sie in der [Escape-API-Dokumentation](https://docs.escape.tech/).
