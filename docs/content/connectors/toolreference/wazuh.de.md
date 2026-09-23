---
title: "Wazuh"
description: "Einrichtung des Wazuh Upstream-Connectors für DefectDojo"
weight: 140
audience: pro
---
Der Wazuh-Connector verwendet den Wazuh Indexer (OpenSearch), um Schwachstellenbefunde abzurufen. Wazuh 4.8 und später speichern erkannte CVEs im Indexer statt in der Wazuh-Server-API, daher liest dieser Connector sie direkt aus dem Index `wazuh-states-vulnerabilities-*`.

DefectDojo erstellt für jeden Wazuh-Agenten (Endpunkt) einen Eintrag und importiert die von diesem Agenten erkannten CVEs geplant als Befunde.

#### Voraussetzungen

Sie benötigen:

* Die Basis-URL Ihres Wazuh Indexer einschließlich des Ports (der Indexer lauscht standardmäßig auf Port 9200). DefectDojo verbindet sich direkt mit dem Indexer, dieser Endpunkt muss daher von DefectDojo aus erreichbar sein. Bei selbstverwalteten Bereitstellungen ist dies der Host, auf dem der Wazuh Indexer läuft. Verwenden Sie bei Wazuh Cloud den in Ihrer Wazuh-Cloud-Konsole angezeigten Indexer-Endpunkt, der sich von der Wazuh-Dashboard-URL unterscheidet.
* Einen Indexer-Benutzer und ein Passwort mit Lesezugriff auf den Index `wazuh-states-vulnerabilities-*`. Wir empfehlen, für DefectDojo einen dedizierten Benutzer anzulegen.

Die Schwachstellenerkennung muss in Wazuh aktiviert sein, damit der Vulnerability-State-Index befüllt wird. Weitere Informationen finden Sie in der [Wazuh-Dokumentation zur Schwachstellenerkennung](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html).

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL Ihres Wazuh Indexer einschließlich Schema und Port in das Feld **Location** ein, zum Beispiel `https://your-indexer.example.com:9200`. Geben Sie keinen abschließenden Pfad an. DefectDojo erstellt die Suchpfade automatisch.
2. Geben Sie den Indexer-Benutzernamen in das Feld **Username** ein.
3. Geben Sie das Indexer-Passwort in das Feld **Password** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.
