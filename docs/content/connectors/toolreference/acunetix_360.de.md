---
title: "Acunetix 360"
description: "Einrichtung des Acunetix 360 Upstream-Connectors für DefectDojo"
weight: 12
audience: pro
---
Der Acunetix-360-Connector importiert **DAST-Schwachstellenbefunde** von der Acunetix-360-Cloud-Plattform (der Invicti-Plattform). DefectDojo ermittelt die gescannten Websites Ihres Kontos und erstellt für jede **Website** einen Eintrag; die Befunde einer Website stammen aus deren letztem abgeschlossenen Scan.

**Bitte beachten Sie:** Dieser Connector ist für **Acunetix 360** (das Cloud-Produkt unter `online.acunetix360.com`). Er ist nicht für den On-Premises-Scanner Acunetix Standard/Premium gedacht, der über eine andere API verfügt.

#### Voraussetzungen

Ein Acunetix-360-Konto und eine **API-Anmeldeinformation**: Öffnen Sie in Acunetix 360 Ihr Kontomenü \> **API Settings**, und notieren Sie sich die **API User ID** und generieren Sie ein **API Token**. Der Connector authentifiziert sich damit als HTTP-Basic-Anmeldedaten, daher wird ein dediziertes Service-Konto empfohlen, um automatisierte Aktivitäten von manuellen Team-Aktionen zu unterscheiden.

#### Connector-Zuordnungen

1. Geben Sie Ihre Acunetix-360-URL in das Feld **Location** ein: `https://online.acunetix360.com`.
2. Geben Sie die API User ID in das Feld **API User ID** ein.
3. Geben Sie das API Token in das Feld **API Token** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede gescannte Website wird zu einem Eintrag. Die Befunde stammen aus dem letzten abgeschlossenen Scan der Website; Schwachstellen, die Acunetix 360 als **Accepted Risk** oder **False Positive** markiert hat, werden weiterhin importiert, aber als inaktiv gekennzeichnet (risikoakzeptiert oder falsch-positiv), damit das DefectDojo-Produkt die Triage des Herstellers widerspiegelt.
