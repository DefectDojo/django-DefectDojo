---
title: "Tenable Web App Scanning"
description: "Einrichtung des Tenable Web App Scanning Upstream-Connectors für DefectDojo"
weight: 132
audience: pro
---
Der Tenable-Web-App-Scanning-Connector importiert **Web-Anwendungs(DAST)-Befunde** von Tenable Web App Scanning. Es handelt sich um einen separaten Connector zu Tenable (Vulnerability Management): Die beiden Produkte decken unterschiedliche Assets ab und werden unabhängig voneinander konfiguriert, sodass Sie entweder eines oder beide verwenden können.

DefectDojo erstellt für jede **gescannte Web-Anwendung** einen Eintrag. Anwendungen werden aus Ihren Web-App-Scanning-Scan-Konfigurationen ermittelt; eine Konfiguration, die nie ausgeführt wurde, erzeugt erst nach ihrem ersten abgeschlossenen Scan einen Eintrag. Scannen mehrere Konfigurationen dieselbe Anwendung, teilen sie sich einen einzigen Eintrag.

#### Voraussetzungen

Tenable-**API-Schlüssel** (ein Access Key und ein Secret Key) für einen Benutzer mit Web-App-Scanning-Berechtigungen. Generieren Sie diese in Tenable unter **My Account \> API Keys**, und stellen Sie sicher, dass der Benutzer die zu importierenden Scans sehen kann — auf Vulnerability Management beschränkte Schlüssel können keine Web-App-Scanning-Daten lesen.

On-Premise-Tenable-Connectors sind derzeit nicht verfügbar.

#### Connector-Zuordnungen

1. Geben Sie <https://cloud.tenable.com> in das Feld **Location** ein.
2. Geben Sie Ihren **Access Key** und **Secret Key** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Befunde werden mit dem Schweregrad importiert, den Tenable für Ihr Konto meldet, einschließlich jeder von Ihrem Team neu eingestuften Bewertung. Jeder Befund enthält die betroffene URL als Endpunkt, den Request-Parameter und die Payload, die ihn ausgelöst haben, sowie Tenables Nachweis und Ausgabe als Schritte zur Reproduktion, zusammen mit CWE-, CVE-, CVSS- und EPSS-Werten, sofern das erkennende Plugin diese liefert.

Es werden nur derzeit offene oder wiedereröffnete Befunde importiert. Ein von Tenable als behoben markierter Befund wird beim nächsten Sync in DefectDojo geschlossen.
