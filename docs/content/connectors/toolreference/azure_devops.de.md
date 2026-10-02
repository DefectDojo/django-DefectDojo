---
title: "Azure DevOps"
description: "Einrichtung des Azure DevOps Upstream-Connectors für DefectDojo"
weight: 20
audience: pro
---
Der Azure-DevOps-Connector ist ein **Asset-Connector**: Er zählt die Git-Repositories in jedem Projekt Ihrer Azure-DevOps-Organisation auf und erstellt für jedes Repository ein DefectDojo-Asset, gruppiert in Organisationen nach Azure-DevOps-Projekt. Es werden keine Befunde importiert.

#### Voraussetzungen

Sie benötigen ein Personal Access Token (PAT) für die Organisation. Wir empfehlen, das Token von einem dedizierten Service-Konto aus zu erstellen. Es werden nur Lese-Scopes benötigt:

1. Öffnen Sie in Azure DevOps **User settings \> Personal access tokens \> New Token**.
2. Klicken Sie auf **Show all scopes** und wählen Sie dann **Code: Read** und **Project and Team: Read**.

Nur Azure DevOps Services (dev.azure.com) wird unterstützt; der On-Premise Azure DevOps Server wird derzeit nicht unterstützt.

#### Connector-Zuordnungen

1. Geben Sie Ihre Organisations-URL in das Feld **Location** ein: `https://dev.azure.com/{your-organization}`. Auch die alten `https://{your-organization}.visualstudio.com`-URLs werden akzeptiert, und zusätzliche Pfadsegmente (zum Beispiel ein Link zu einem bestimmten Projekt) werden ignoriert.
2. Geben Sie das PAT in das Feld **Secret** ein.

Jedes Repository wird zu einem nach dem Repository benannten Eintrag, gruppiert nach seinem Azure-DevOps-**Projekt**. Deaktivierte Repositories werden übersprungen; das Deaktivieren oder Löschen eines Repositorys markiert seinen Eintrag beim nächsten Sync daher als `MISSING`.
