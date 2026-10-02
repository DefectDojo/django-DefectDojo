---
title: "Shodan"
description: "Einrichtung des Shodan Upstream-Connectors für DefectDojo"
weight: 123
audience: pro
---
Der Shodan-Connector verwendet die Shodan-REST-API, um die von Shodan auf Ihren im Internet exponierten Hosts beobachteten Schwachstellen (CVEs) zu importieren. Sie geben eine Shodan-Suchanfrage an, die den Import auf Ihre eigenen Assets beschränkt; DefectDojo erstellt für jeden passenden Host einen Eintrag und importiert dessen CVEs als Befunde.

#### Voraussetzungen

Sie benötigen einen Shodan-API-Schlüssel, den Sie auf Ihrer Shodan-**Account**-Seite finden. Die Host-Suche mit Schwachstellendaten erfordert eine Shodan-Mitgliedschaft oder einen kostenpflichtigen API-Plan — die kostenlose Stufe kann Suchergebnisse nicht seitenweise durchblättern.

#### Connector-Zuordnungen

1. Geben Sie `https://api.shodan.io` in das Feld **Location** ein.
2. Geben Sie Ihren Shodan-API-Schlüssel in das Feld **API Key** ein.
3. Geben Sie im Feld **Search Query** eine Shodan-Abfrage ein, die den Import auf die Assets Ihrer Organisation beschränkt — zum Beispiel `hostname:example.com`, `net:203.0.113.0/24` oder `org:"Example Inc"`. Es werden nur Hosts importiert, die dieser Abfrage entsprechen; beschränken Sie sie daher auf Infrastruktur, die Ihnen gehört.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jeder passende Host wird zu einem Eintrag, und jede von Shodan auf den exponierten Diensten dieses Hosts erkannte CVE wird als Befund importiert — der Schweregrad wird aus dem CVSS-Score abgeleitet, wobei EPSS- und CISA-KEV-Kontext einbezogen wird, sofern verfügbar. Jede Seite der Suchergebnisse verbraucht ein Shodan-Abfrage-Guthaben.
