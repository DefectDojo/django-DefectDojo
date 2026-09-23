---
title: "IriusRisk"
description: "Einrichtung des IriusRisk Upstream-Connectors für DefectDojo"
weight: 80
audience: pro
---
Der IriusRisk-Connector verwendet ein API-Token, um Threat-Modeling-Daten aus Ihrer IriusRisk-Instanz abzurufen.

#### Voraussetzungen

Sie benötigen ein API-Token aus Ihrem IriusRisk-Konto. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, um automatisierte Aktivitäten klar von manuellen Team-Aktionen zu unterscheiden.

So generieren Sie ein API-Token in IriusRisk:

1. Melden Sie sich bei Ihrer IriusRisk-Instanz an.
2. Navigieren Sie zu Ihrem **User Profile** im Menü oben rechts.
3. Wählen Sie **API Token** und generieren Sie ein neues Token.

Weitere Informationen finden Sie in der [IriusRisk-API-Dokumentation](https://support.iriusrisk.com/hc/en-us/categories/360001148511).

#### Connector-Zuordnungen

1. Geben Sie die URL Ihrer IriusRisk-Instanz in das Feld **Location URL** ein. Bei Cloud-gehosteten Instanzen ist dies typischerweise `https://{your-subdomain}.iriusrisk.com`. Verwenden Sie bei On-Premise-Installationen die Basis-URL Ihrer Instanz.
2. Geben Sie Ihr **API Token** in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.
