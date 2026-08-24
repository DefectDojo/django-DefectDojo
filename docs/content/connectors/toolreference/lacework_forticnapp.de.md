---
title: "Lacework / FortiCNAPP"
description: "Einrichtung des Lacework / FortiCNAPP Upstream-Connectors für DefectDojo"
weight: 86
audience: pro
---
Der Lacework-/FortiCNAPP-Connector verwendet die Lacework-v2-API, um **Host- und Container-Schwachstellen** für Ihr gesamtes Lacework-Konto zu importieren.

#### Voraussetzungen

Sie benötigen einen Lacework-**API-Schlüssel** — eine API-Key-ID und ein Secret, erstellt in der Lacework-Konsole unter **Settings → API keys**. Der Connector tauscht diese bei jedem Sync gegen ein kurzlebiges Zugriffstoken ein; Key-ID, Secret und Token werden nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie Ihre Lacework-Konto-URL in das Feld **Location** ein — zum Beispiel `https://YOUR-ACCOUNT.lacework.net` (ein bloßer Kontoname wird ebenfalls akzeptiert).
2. Geben Sie die **API Key ID** und das **API Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet das Lacework-**Konto** einem Eintrag zu (der gesamte Konto-Geltungsbereich). Jede **Container**- und **Host**-Schwachstelle wird zu einem Befund: Der Schweregrad stammt aus Laceworks eigener Bewertung, das betroffene Paket und die Version werden zur Komponente, die Fix-Version wird zur Abhilfemaßnahme, und das betroffene Image/der betroffene Host wird als Tags erfasst. Container-Schwachstellen werden als statische Befunde erfasst (Image-Scans) und Host-Schwachstellen als dynamische Befunde (Scans laufender Hosts).

Weitere Informationen finden Sie in der [Lacework-API-Dokumentation](https://docs.lacework.net/api/v2/docs).
