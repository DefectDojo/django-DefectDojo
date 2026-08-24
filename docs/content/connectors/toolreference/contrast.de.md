---
title: "Contrast"
description: "Einrichtung des Contrast Upstream-Connectors für DefectDojo"
weight: 39
audience: pro
---
Der Contrast-Connector verwendet die Contrast-Assess-REST-API, um Anwendungsschwachstellen zu importieren. DefectDojo ermittelt die Anwendungen in Ihrer Contrast-Organisation und erstellt für jede einen Eintrag.

#### Voraussetzungen

Sie benötigen vier Werte von Contrast. Wir empfehlen, ein dediziertes Service-Konto anzulegen, damit automatisierte Aktivitäten leicht von den manuellen Aktionen Ihres Teams zu unterscheiden sind. In der Contrast-Oberfläche finden Sie unter **User Settings > Profile > Your Keys**:

* Ihren organisationsweiten **API Key**.
* Ihren persönlichen **Service Key**.
* Den **Benutzernamen**, zu dem die Anmeldedaten gehören (die Login-E-Mail-Adresse des Kontos).
* Ihre **Organization ID** — die UUID der Organisation, aus der importiert werden soll, ebenfalls unter **Organization Settings** angezeigt.

#### Connector-Zuordnungen

1. Geben Sie die URL, über die Sie auf Contrast zugreifen, in das Feld **Location** ein — beim gehosteten Produkt ist dies typischerweise `https://app.contrastsecurity.com` (oder Ihre regionale/selbstgehostete Team-Server-URL).
2. Geben Sie die Login-E-Mail-Adresse des Kontos in das Feld **Username** ein.
3. Geben Sie den organisationsweiten **API Key** in das Feld **API Key** ein.
4. Geben Sie den persönlichen **Service Key** in das Feld **Service Key** ein.
5. Geben Sie die **Organization ID** (UUID) in das Feld **Organization ID** ein.
6. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede Contrast-Anwendung wird zu einem Eintrag, und ihre Schwachstellen werden als Befunde importiert.
