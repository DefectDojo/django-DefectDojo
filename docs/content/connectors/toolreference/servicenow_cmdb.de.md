---
title: "ServiceNow CMDB"
description: "Einrichtung des ServiceNow CMDB Upstream-Connectors für DefectDojo"
weight: 121
audience: pro
---
Der ServiceNow-CMDB-Connector ist ein **Asset-Connector**: Anstatt Befunde zu importieren, liest er Configuration Items (CIs) aus Ihrer ServiceNow Configuration Management Database und erstellt für jede CI ein DefectDojo-Asset, gruppiert in Organisationen nach CI-Klasse. Es werden keine Befunde importiert.

#### Voraussetzungen

Sie benötigen eine ServiceNow-Instanz und ein Konto, das die CMDB-Tabellen über die ServiceNow-Table-API lesen kann. Wir empfehlen ein dediziertes, schreibgeschütztes Service-Konto für DefectDojo. Das Konto benötigt Lesezugriff auf die zu importierenden `cmdb_ci`-Tabellen.

#### Connector-Zuordnungen

1. Geben Sie die URL Ihrer ServiceNow-Instanz in das Feld **Location** ein: `https://{your-instance}.service-now.com`.
2. Wählen oder erstellen Sie eine ServiceNow-**Tool Configuration**, die die Instanz-Anmeldedaten enthält (den ServiceNow-Benutzernamen und das Passwort).

Jedes Configuration Item wird zu einem nach der CI benannten Eintrag, gruppiert nach seiner **CI-Klasse** (zum Beispiel Application, Server oder Business Service). Discovery und Sync gleichen die CI-Liste ab: Neue CIs erscheinen als `NEW`-Einträge, und eine aus der CMDB entfernte CI wird beim nächsten Sync als `MISSING` markiert, damit Ihr Team sie prüfen kann. DefectDojo löscht niemals stillschweigend ein Produkt.
