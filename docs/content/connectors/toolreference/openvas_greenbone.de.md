---
title: "OpenVAS / Greenbone"
description: "Einrichtung des OpenVAS / Greenbone Upstream-Connectors für DefectDojo"
weight: 98
audience: pro
---
Der OpenVAS-/Greenbone-Connector importiert **Netzwerk-Schwachstellenbefunde** aus einer Greenbone-Instanz (Greenbone Community Edition oder Greenbone Enterprise). Er kommuniziert mit `gvmd` über **GMP (Greenbone Management Protocol)** — ein XML-Protokoll über ein TLS-Socket, nicht HTTP — und synchronisiert die gesamte Instanz: Er zählt Scan-**Tasks** auf und erstellt für jeden ein DefectDojo-Produkt, wobei die Ergebnisse des jeweils letzten Berichts jedes Tasks importiert werden.

#### Voraussetzungen

Ein Greenbone-**GMP-Benutzer** (Benutzername + Passwort) und Netzwerkzugriff auf den GMP-TLS-Port von gvmd (standardmäßig **9390**). Der Compose-Stack der Greenbone Community Edition stellt gvmd über einen Unix-Socket bereit; um ihn von einem vernetzten Connector aus zu erreichen, betreiben Sie den Connector entweder dort, wo er den Socket erreichen kann, oder exponieren Sie den GMP-TLS-Port (zum Beispiel eine `socat`-TLS-Bridge zu `gvmd.sock`).

#### Connector-Zuordnungen

1. Geben Sie den gvmd-Host in das Feld **Location** ein (Host oder `host:port`).
2. Geben Sie den GMP-**Username** und das **Password** ein.
3. Legen Sie optional den **GMP Port** fest (Standard 9390).
4. Für das standardmäßige selbstsignierte Zertifikat von gvmd geben Sie entweder ein **CA Certificate (PEM)** zur Verifizierung an, oder setzen Sie **Skip TLS Verification** auf `true`.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jeder Greenbone-Task wird zu einem Eintrag. Befunde stammen aus dem letzten abgeschlossenen Bericht des Tasks — einer pro `<result>`. Der Schweregrad wird der Threat-Level-Angabe des Ergebnisses entnommen (Greenbones informative Stufen `Log`/`Debug` werden auf Info abgebildet), wobei der numerische CVSS-Score erfasst wird; CVE-Referenzen werden zu Schwachstellen-IDs, die NVT-Lösung wird zur Abhilfemaßnahme, und Host/Port jedes Ergebnisses werden zu einem Endpunkt.
