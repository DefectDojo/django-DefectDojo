---
title: "Dependency-Track"
description: "Einrichtung des Dependency-Track Upstream-Connectors für DefectDojo"
weight: 48
audience: pro
---
Dieser Connector ruft Daten von einer On-Premise-Dependency\-Track-Instanz über die REST-API ab.

​**Connector-Zuordnungen**

1. Geben Sie die URL Ihres lokalen Dependency\-Track-Servers in das Feld **Location** ein.
2. Geben Sie einen gültigen API-Schlüssel in das Feld **Secret** ein.

So generieren Sie einen Dependency\-Track-API-Schlüssel:

1. **Access Management**: Navigieren Sie in der Dependency\-Track-Oberfläche zu Administration \> Access Management \> Teams.
2. **Teams Setup**: Sie können entweder ein neues Team erstellen oder ein bestehendes auswählen. Mit Teams können Sie den API-Zugriff anhand der Gruppenmitgliedschaft verwalten.
3. **Generate API Key**: Suchen Sie auf der Detailseite des ausgewählten Teams den Abschnitt „API Keys". Klicken Sie auf die Schaltfläche \+, um einen neuen API-Schlüssel zu generieren.
4. **Assign Permissions**: Klicken Sie im Abschnitt „Permissions" der Team-Seite auf die Schaltfläche \+, um die Berechtigungsauswahl zu öffnen. Wählen Sie die Berechtigungen **VIEW\_PORTFOLIO** und **VIEW\_VULNERABILITY**, um API-Zugriff auf Projekt-Portfolios und Schwachstellendetails zu ermöglichen.
5. Klicken Sie auf „**Select**", um diese Berechtigungen zu bestätigen und zu speichern.

Weitere Informationen finden Sie in der **[Dependency\-Track-Dokumentation](https://docs.dependencytrack.org/integrations/rest-api/)**.
