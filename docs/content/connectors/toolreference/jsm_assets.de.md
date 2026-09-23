---
title: "Jira Service Management Assets"
description: "Einrichtung des Jira Service Management Assets Upstream-Connectors für DefectDojo"
weight: 83
audience: pro
---
Der JSM-Assets-Connector ist ein **Asset-Connector**: Er zählt die Objekte in Ihrem Jira-Service-Management-Assets-Workspace (ehemals Insight) auf und erstellt für jedes Objekt ein DefectDojo-Asset, gruppiert in Organisationen nach Objektschema. Es werden keine Befunde importiert.

#### Voraussetzungen

* Assets erfordert einen **Jira-Service-Management-Premium- oder -Enterprise-Plan**. Bei Free- oder Standard-Plänen antwortet die Assets-API mit `403 "Access to Assets API was denied"`, obwohl der Rest der Site funktioniert.
* Das verwendete Atlassian-Konto muss auf der Site über **Jira-Service-Management-Produktzugriff** verfügen (einen Agent-Sitzplatz) — reiner Site-Zugriff genügt nicht.
* Erstellen Sie ein klassisches Atlassian-API-Token unter [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens). Wir empfehlen ein dediziertes Service-Konto.

#### Connector-Zuordnungen

1. Geben Sie Ihre Atlassian-Site-URL in das Feld **Location** ein: `https://{your-site}.atlassian.net`.
2. Geben Sie die Atlassian-Konto-E-Mail-Adresse, zu der das Token gehört, in das Feld **Email** ein.
3. Geben Sie das API-Token in das Feld **Secret** ein.

Jedes Assets-Objekt wird zu einem nach dem Label des Objekts benannten Eintrag, gruppiert nach seinem **Objektschema**.
