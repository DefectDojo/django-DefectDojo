---
title: "Fortify"
description: "Einrichtung des Fortify Upstream-Connectors für DefectDojo"
weight: 59
audience: pro
---
Der Fortify-Connector importiert SAST-/DAST-Ergebnisse von Fortify (OpenText/Micro Focus) und deckt beide Editionen ab, die sich die Plattform teilen: **SSC** (Software Security Center, selbstgehostet) und **Fortify on Demand (FoD)** (SaaS). Er synchronisiert das gesamte Konto: DefectDojo ermittelt jede Anwendung (SSC-Projektversion/FoD-Release) und erstellt für jede einen Eintrag; anschließend werden die Issues dieser Anwendung als Befunde importiert.

#### Voraussetzungen

- **SSC**: ein **FortifyToken** — erstellen Sie eines in der SSC-Oberfläche unter **Administration → Token Management** (ein CIToken/UnifiedLoginToken).
- **FoD**: ein **OAuth2-API-Schlüssel** — eine Client ID und ein Client Secret aus **Settings → API** (mit dem Scope `api-tenant`).

Das Token und das OAuth-Secret werden nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie die Fortify-Basis-URL in das Feld **Location** ein: für SSC Ihren Server-Host (der Connector ergänzt `/ssc/api/v1`); für FoD den API-Host Ihrer Region, z. B. `https://api.ams.fortify.com`.
2. Setzen Sie **Edition** auf `SSC` oder `FoD`.
3. Geben Sie für **FoD** die OAuth-**Client ID** ein; für SSC leer lassen.
4. Geben Sie in **Token / Client Secret** das SSC-FortifyToken oder das FoD-OAuth-Client-Secret ein.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jede Fortify-**Anwendung** einem Eintrag zu und jedes **Issue** einem Befund: Der Schweregrad stammt aus Fortifys eigener **Friority**-Bewertung (Critical/High/Medium/Low), der Titel kombiniert die Issue-Kategorie mit Datei und Zeile, und Dateipfad, Zeile, Kingdom, Analyzer und Engine-Typ werden übernommen. Issues von statischen Analyse-Engines (SCA) werden als statische Befunde erfasst und WebInspect(DAST)-Issues als dynamische Befunde; unterdrückte, entfernte und verborgene Issues werden übersprungen, als „Not an Issue" geprüfte Issues werden als falsch-positiv markiert, und „Exploitable"/geprüfte Issues werden als verifiziert markiert.

Weitere Informationen finden Sie in der Dokumentation zu [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) und [Fortify on Demand](https://api.ams.fortify.com/swagger/ui).
