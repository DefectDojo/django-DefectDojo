---
title: "Rapid7 InsightVM"
description: "Einrichtung des Rapid7 InsightVM Upstream-Connectors für DefectDojo"
weight: 113
audience: pro
---
Der Rapid7-InsightVM-Connector importiert Asset-Schwachstellenbefunde aus Ihrer InsightVM-**Security Console** (API v3), angereichert mit dem globalen Schwachstellenkatalog der Console. DefectDojo erstellt für jede InsightVM-**Site** einen Eintrag.

#### Voraussetzungen

Netzwerkzugriff von DefectDojo auf Ihre Security Console sowie ein **Benutzerkonto** der Console — dessen Login wird für die HTTP-Basic-Authentifizierung verwendet. Die Console-API wird standardmäßig auf Port **3780** bereitgestellt.

#### Connector-Zuordnungen

1. Geben Sie die URL Ihrer Security Console einschließlich des Ports in das Feld **Location** ein — zum Beispiel `https://console.example.com:3780`.
2. Geben Sie den Console-Benutzernamen in das Feld **Username** ein.
3. Geben Sie das Console-Passwort in das Feld **Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede InsightVM-Site wird zu einem Eintrag; der Connector durchläuft die Assets der Site und importiert deren anfällige Befunde.
