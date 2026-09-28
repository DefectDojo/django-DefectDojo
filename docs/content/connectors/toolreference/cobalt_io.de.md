---
title: "Cobalt.io"
description: "Einrichtung des Cobalt.io Upstream-Connectors für DefectDojo"
weight: 37
audience: pro
---
Der Cobalt.io-Connector verwendet die Cobalt.io-API (v2), um Pentest-Befunde aus Ihrer Cobalt.io-Organisation abzurufen. DefectDojo ermittelt jede Organisation, auf die Ihr API-Token zugreifen kann, und erstellt für jedes **Asset** (die Einheit, die Cobalt pentestet) einen separaten Eintrag.

#### Voraussetzungen

Sie benötigen ein persönliches Cobalt.io-**API-Token**. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, um automatisierte Aktivitäten klar von manuellen Team-Aktionen zu unterscheiden. Generieren Sie ein Token unter **Settings \> API Tokens** in der Cobalt.io-Oberfläche. Organisations-Tokens werden automatisch ermittelt \- Sie müssen sie nicht angeben.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL der Cobalt.io-API in das Feld **Location** ein: `https://api.cobalt.io` (oder Ihren regionalen Host, zum Beispiel `https://api.us.cobalt.io`).
2. Geben Sie Ihr **persönliches API-Token** in das Feld **Secret** ein.
3. Geben Sie optional ein **Organization Token** ein, um den Sync auf eine einzelne Organisation zu beschränken. Bleibt das Feld leer, synchronisiert DefectDojo jede Organisation, auf die das persönliche API-Token zugreifen kann.

DefectDojo ordnet jedes Cobalt.io-**Asset** als separaten Eintrag zu. Für jedes zugeordnete Asset werden Befunde importiert, wobei deren Cobalt.io-Status (zum Beispiel `valid_fix`, `wont_fix`, `invalid`) den Befundstatus in DefectDojo bestimmt.
