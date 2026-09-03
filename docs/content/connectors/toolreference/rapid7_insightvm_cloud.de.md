---
title: "Rapid7 InsightVM - Cloud Instance"
description: "Einrichtung des Rapid7 InsightVM - Cloud Instance Upstream-Connectors für DefectDojo"
weight: 113
audience: pro
---
Der Rapid7-InsightVM-Cloud-Instance-Connector importiert Asset-Schwachstellenbefunde aus InsightVM, das auf der **Rapid7-Insight-Plattform** gehostet wird (Cloud Integrations API v4), angereichert mit dem Schwachstellenkatalog der Plattform. DefectDojo erstellt für jede InsightVM-**Site** einen Eintrag.

**Bitte beachten Sie:** Dieser Connector ist für InsightVM auf der Rapid7-Insight-Cloud-Plattform. Wenn Ihre Befunde aus Ihrer eigenen **Security Console** (on\-premises) stammen, verwenden Sie stattdessen den Connector [Rapid7 InsightVM](/connectors/toolreference/rapid7_insightvm/), der sich mit Console-Anmeldedaten statt mit einem Platform-API-Schlüssel authentifiziert.

#### Voraussetzungen

Ein Insight-Platform-Konto mit InsightVM sowie ein Platform-**API-Schlüssel**: Öffnen Sie in der [Rapid7-Insight-Plattform](https://insight.rapid7.com) das Einstellungsmenü (Zahnrad) \> **API Keys** und generieren Sie einen **User Key** (beliebige Rolle) oder einen **Organization Key** (Platform-Admins). Kopieren Sie den Schlüssel, wenn er angezeigt wird: Er wird nur einmal angezeigt.

Sie benötigen außerdem Ihre Platform-**Region**, sichtbar in Ihrer Insight-URL (zum Beispiel `us`, `us2`, `us3`, `eu`, `ca`, `au` oder `ap`).

#### Connector-Zuordnungen

1. Geben Sie Ihren regionalen API-Endpunkt in das Feld **Location** ein, zum Beispiel `https://us.api.insight.rapid7.com` (ersetzen Sie `us` durch Ihre Region). Dieses Feld ist mit dem US-Endpunkt vorausgefüllt.
2. Geben Sie den API-Schlüssel der Insight-Plattform in das Feld **API Key** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede InsightVM-Site wird zu einem Eintrag; der Connector liest die Integrations-Assets der Plattform und importiert deren anfällige Befunde, angereichert aus dem Schwachstellenkatalog. Befunde werden unter demselben Typ **Rapid7 InsightVM - Connectors Import** wie beim On\-premises-Connector importiert, sodass die Ergebnisse beider Connectoren gemeinsam dedupliziert werden.
