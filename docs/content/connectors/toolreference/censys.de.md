---
title: "Censys"
description: "Einrichtung des Censys Upstream-Connectors für DefectDojo"
weight: 32
audience: pro
---
Der Censys-Connector liest Host-Assets aus der Censys Platform und importiert die exponierten Dienste jedes Hosts als Befunde. Er verwendet die globale Such-API der Censys Platform, um die Hosts zu ermitteln, auf die Sie ihn beschränken.

#### Voraussetzungen

Sie benötigen ein Censys-**Platform**-Konto mit API-Zugriff:

* Ein **Personal Access Token**, erstellt in der Censys Platform Console unter Personal Access Tokens.
* Ihre **Organization ID**, die auf derselben Einstellungsseite unter „Current Organization" angezeigt wird. Der API-Zugriff auf den Such-Endpunkt erfordert eine Organisation, daher ist mindestens ein Starter-Tier erforderlich. Free-Tier-Tokens haben keine Organization ID und können die Such-API nicht nutzen.

Pro-Host-CVE- und Risikodaten sind nur in den Censys-Core(Enterprise)-Tiers verfügbar, sodass Befunde in niedrigeren Tiers exponierte Dienste statt Schwachstellen darstellen.

Weitere Informationen finden Sie in der [Censys-Platform-API-Dokumentation](https://docs.censys.com/reference/get-started).

#### Connector-Zuordnungen

1. Geben Sie `https://api.platform.censys.io` in das Feld **Location** ein.
2. Geben Sie Ihr Personal Access Token in das Feld **API Key** ein.
3. Geben Sie Ihre **Organization ID** ein.
4. Geben Sie eine **Search Query** ein, die den Import auf Ihre eigenen Assets beschränkt, zum Beispiel `host.autonomous_system.asn: <your ASN>` oder `host.ip: 203.0.113.0/24`.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo erstellt für jeden Host einen Eintrag und importiert dessen exponierte Dienste als Befunde.
