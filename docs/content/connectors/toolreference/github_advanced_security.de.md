---
title: "GitHub Advanced Security"
description: "Einrichtung des GitHub Advanced Security Upstream-Connectors für DefectDojo"
weight: 64
audience: pro
---
Der GitHub-Advanced-Security-Connector importiert **Code-Scanning-**, **Dependabot-** und **Secret-Scanning**-Warnungen von GitHub als drei separate Befundtypen (`GitHub:CodeScanning`, `GitHub:Dependabot` und `GitHub:SecretScanning`). DefectDojo ermittelt jedes nicht archivierte Repository in der konfigurierten Organisation und erstellt für jedes einen Eintrag.

#### Voraussetzungen

GitHub-Advanced-Security-Funktionen müssen für die zu importierenden Repositories aktiviert sein. Der Connector authentifiziert sich mit einem GitHub-**Personal Access Token**:

1. Öffnen Sie in GitHub **Settings \> Developer settings \> Personal access tokens** und erstellen Sie ein Token, das der Zielorganisation gehört (oder Zugriff darauf hat).
2. Gewähren Sie ihm Lesezugriff auf die Sicherheitswarnungen: Ein *fein-granulares* Token benötigt **Read-only**-Zugriff auf **Code scanning alerts**, **Dependabot alerts** und **Secret scanning alerts** der Repositories der Organisation; ein *klassisches* Token benötigt die Scopes **`repo`** und **`security_events`**.
3. Stellen Sie sicher, dass der Owner des Tokens die zu importierenden Repositories sehen kann — der Connector sieht nur Repositories, auf die das Token zugreifen kann.

#### Connector-Zuordnungen

1. Geben Sie `https://api.github.com` in das Feld **Location** ein. Verwenden Sie für GitHub Enterprise Server `https://<your-host>/api/v3`.
2. Geben Sie den Organisations-Login in das Feld **Organization** ein.
3. Geben Sie das Personal Access Token in das Feld **Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes nicht archivierte Repository wird zu einem Eintrag, der über die drei Warnungsfamilien nach offenen Warnungen abgefragt wird. Eine Warnungsfamilie, die für ein Repository nicht aktiviert ist, wird übersprungen statt als behoben gemeldet, sodass deaktivierte Funktionen keine falschen Schließungen verursachen.
