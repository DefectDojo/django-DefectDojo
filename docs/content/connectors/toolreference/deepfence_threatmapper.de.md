---
title: "Deepfence ThreatMapper"
description: "Einrichtung des Deepfence ThreatMapper Upstream-Connectors für DefectDojo"
weight: 46
audience: pro
---
Der Deepfence-ThreatMapper-Connector verwendet die REST-API der [ThreatMapper](https://github.com/deepfence/ThreatMapper)-Management-Konsole, um **Schwachstellen-Scan**-Ergebnisse zu importieren. DefectDojo ermittelt jeden Node, den ThreatMapper gescannt hat — ein Container-Image, einen Host oder einen Container — und erstellt für jeden einen Eintrag; anschließend wird der letzte abgeschlossene Scan dieses Nodes als Befunde importiert.

#### Voraussetzungen

Sie benötigen ein ThreatMapper-**API-Token**, das Sie in der Konsole unter **Settings → User Management** finden (der API-Schlüssel Ihres Benutzers). Der Connector tauscht dieses bei jedem Sync gegen ein kurzlebiges Zugriffstoken ein; das API-Token wird nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie die URL Ihrer ThreatMapper-Konsole in das Feld **Location** ein (zum Beispiel `https://threatmapper.example.com`).
2. Geben Sie im Feld **Secret** das ThreatMapper-API-Token ein.
3. Wenn Ihre Konsole ein selbstsigniertes Zertifikat verwendet, setzen Sie **Skip TLS Verification** auf `true`.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jeden gescannten **Node** einem Eintrag zu und jede **CVE** im letzten abgeschlossenen Schwachstellen-Scan einem Befund. Der Schweregrad stammt aus ThreatMappers eigener Bewertung, und das betroffene Paket, der CVSS-Score, die Fix-Version (als Abhilfemaßnahme), Referenzlinks und ein Detailblock werden übernommen. Befunde werden als dynamische Befunde erfasst und anhand von Node, CVE, Paket und Paketpfad dedupliziert.

Weitere Informationen finden Sie in der [ThreatMapper-Dokumentation](https://community.deepfence.io/threatmapper/docs/v2.5/).
