---
title: "Docker Scout"
description: "Einrichtung des Docker Scout Upstream-Connectors für DefectDojo"
weight: 50
audience: pro
---
Der Docker-Scout-Connector verwendet die Docker-Scout-Metrics-Exporter-API, um den Schwachstellenstatus der Images Ihrer Organisation zu melden. DefectDojo ermittelt jeden Docker-Scout-Stream (Ihre Laufzeitumgebungen) und importiert für jeden eine Zusammenfassung der Schwachstellen und der Richtlinien-Compliance.

#### Voraussetzungen

Sie benötigen ein persönliches Docker-Zugriffstoken, das von einem **Owner** einer Docker-Organisation erstellt wurde, die **bei Docker Scout registriert** ist. Der Metrics Exporter ist eine Funktion auf Organisationsebene, daher liefert ein persönliches Konto oder eine nicht bei Docker Scout registrierte Organisation keine Daten.

Erstellen Sie das Token in Ihren Docker-Kontoeinstellungen unter **Personal access tokens**, und notieren Sie sich Ihren Docker-**Organisations-Namespace**, den Sie ebenfalls benötigen.

#### Connector-Zuordnungen

1. Geben Sie `https://api.scout.docker.com` in das Feld **Location** ein.
2. Geben Sie Ihr persönliches Docker-Zugriffstoken in das Feld **Secret** ein.
3. Geben Sie Ihren Docker-**Organization**-Namespace ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo erstellt für jeden Docker-Scout-Stream einen separaten Eintrag und importiert einen Befund pro Schweregrad für die Schwachstellen, die Docker Scout in diesem Stream zählt, sowie einen Befund für jedes Image, das Ihre Docker-Scout-Richtlinie nicht erfüllt. Die Metrics-API von Docker Scout meldet aggregierte Zählwerte statt einzelner CVEs, daher fassen diese Befunde den Status eines Streams zusammen. Öffnen Sie den Stream in Docker Scout für Details pro Image und pro CVE.

Weitere Informationen finden Sie in der [Docker-Scout-Dokumentation](https://docs.docker.com/scout/).
