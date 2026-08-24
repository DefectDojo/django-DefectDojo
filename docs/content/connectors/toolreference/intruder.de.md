---
title: "Intruder"
description: "Einrichtung des Intruder Upstream-Connectors für DefectDojo"
weight: 79
audience: pro
---
Der Intruder-Connector verwendet die [Intruder-REST-API](https://developers.intruder.io/), um den Status Ihres gesamten Kontos in DefectDojo zu übertragen. Jedes Intruder-**Target** wird als Eintrag (Produkt) ermittelt; jedes **Vorkommen** eines Issues auf einem Target wird zu einem Befund.

#### Connector-Zuordnungen

1. Lassen Sie das Feld **Location** auf `https://api.intruder.io/` (dem Standard-Intruder-API-Server).
2. Geben Sie ein Intruder-**API-Zugriffstoken** in das Feld **Secret** ein.

Generieren Sie ein Zugriffstoken in Intruder unter **My account > API Access Tokens** (Sie benötigen Ihr Kontopasswort, um es zu erstellen, und das Token wird nur einmal angezeigt). Einzelheiten finden Sie in der [Intruder-API-Dokumentation](https://developers.intruder.io/docs/creating-an-access-token).

Befunde werden pro Vorkommen abgeleitet: Der Schweregrad stammt aus dem Issue-Schweregrad, CVEs und CVSS aus dem Vorkommen, der Standort aus Target/Port, und ein zurückgestelltes (snoozed) Vorkommen wird als inaktiver Befund (falsch-positiv oder risikoakzeptiert) importiert.
