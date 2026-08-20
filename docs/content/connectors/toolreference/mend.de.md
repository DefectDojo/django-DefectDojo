---
title: "Mend"
description: "Einrichtung des Mend Upstream-Connectors für DefectDojo"
weight: 88
audience: pro
---
Der Mend-Connector (ehemals **WhiteSource**) verwendet die Mend-API, um Sicherheitsbefunde aus Ihrer Mend-Organisation zu importieren. DefectDojo erstellt für jedes Mend-**Projekt** einen Eintrag.

#### Voraussetzungen

Sie benötigen einen Mend-(Service-)Benutzer mit einem **User Key** (einem persönlichen Zugriffstoken) und Ihre Mend-**Organization UUID**. Wir empfehlen ein dediziertes Service-Konto, damit automatisierte Aktivitäten leicht von manuellen Team-Aktionen zu unterscheiden sind. Die Organization UUID finden Sie in der Mend-App unter **Administration > Organization UUID**.

#### Connector-Zuordnungen

1. Geben Sie Ihre Mend-API-URL in das Feld **Location** ein. Diese URL ist **regionsspezifisch** — verwenden Sie die API-Basis-URL der Region, in der Ihre Mend-Organisation gehostet wird.
2. Geben Sie die Login-E-Mail-Adresse des Mend-Benutzers in das Feld **Email** ein.
3. Geben Sie Ihre Mend-**Organization UUID** in das Feld **Organization UUID** ein.
4. Geben Sie den Mend-**User Key** in das Feld **User Key** ein.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.
