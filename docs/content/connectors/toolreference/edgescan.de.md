---
title: "Edgescan"
description: "Einrichtung des Edgescan Upstream-Connectors für DefectDojo"
weight: 52
audience: pro
---
Der Edgescan-Connector verwendet die Edgescan-REST-API, um offene Schwachstellen aus Ihrem gesamten Edgescan-Konto zu importieren. DefectDojo zählt jedes Edgescan-**Asset** auf und erstellt für jedes einen Eintrag; anschließend werden die offenen Schwachstellen dieses Assets als Befunde importiert — es gibt keine Pro-Asset-Konfiguration.

#### Voraussetzungen

Sie benötigen ein Edgescan-API-Token. Erstellen Sie eines in Ihrem Edgescan-Konto unter **Account settings \> API tokens**: Geben Sie eine Bezeichnung ein, klicken Sie auf **Create**, und kopieren Sie das generierte Token (es wird nur einmal angezeigt). Wir empfehlen ein dediziertes Konto für den Connector, damit automatisierte Aktivitäten leicht zu unterscheiden sind.

#### Connector-Zuordnungen

1. Geben Sie Ihre Edgescan-URL in das Feld **Location** ein — `https://live.edgescan.com` für die Standard-Hosted-Plattform, oder den Host Ihres Tenants, falls abweichend.
2. Geben Sie Ihr Edgescan-API-Token in das Feld **Secret** ein. Es wird als `X-API-TOKEN`-Header gesendet.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes Edgescan-Asset wird zu einem Eintrag, und jede offene Schwachstelle dieses Assets wird als Befund importiert. Der Schweregrad wird von Edgescans numerischer Skala (1–5) auf DefectDojos Info–Kritisch abgebildet, und CVE-Referenzen, die CWE sowie ein CVSS-v3-Vektor werden einbezogen, sofern Edgescan sie bereitstellt.
