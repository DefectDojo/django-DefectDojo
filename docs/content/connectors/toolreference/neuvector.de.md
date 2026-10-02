---
title: "NeuVector"
description: "Einrichtung des NeuVector Upstream-Connectors für DefectDojo"
weight: 93
audience: pro
---
Der NeuVector-Connector verwendet die Controller-REST-API von [NeuVector](https://github.com/neuvector/neuvector), um Container-**Image-Schwachstellen-Scans** zu importieren. DefectDojo ermittelt jedes von NeuVector gescannte Image und erstellt für jedes einen Eintrag; anschließend wird der Scan-Bericht dieses Images als Befunde importiert.

#### Voraussetzungen

Sie benötigen einen NeuVector-**Benutzernamen und ein Passwort** für ein Controller-Konto mit Berechtigung, Scan-Ergebnisse zu lesen. Der Connector meldet sich mit diesen Anmeldedaten an, um ein Session-Token zu erhalten; das Passwort und das Token werden nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie Ihre NeuVector-Controller-URL einschließlich des REST-API-Ports in das Feld **Location** ein — zum Beispiel `https://neuvector.example.com:10443`.
2. Geben Sie den Controller-**Username** und das **Password** ein.
3. Wenn Ihr Controller ein selbstsigniertes Zertifikat verwendet, setzen Sie **Skip TLS Verification** auf `true`.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jedes gescannte **Image** einem Eintrag zu und jede **CVE** in dessen Scan-Bericht einem Befund. Der Schweregrad stammt aus NeuVectors eigener Bewertung, und das betroffene Paket und die Version, der CVSSv3-Score und -Vektor, die Fix-Version (als Abhilfemaßnahme) sowie ein Referenzlink werden übernommen. Befunde werden anhand von Image, CVE, Paket, Version und Schweregrad dedupliziert.

Weitere Informationen finden Sie in der [NeuVector-API-Dokumentation](https://open-docs.neuvector.com/automation/automation).
