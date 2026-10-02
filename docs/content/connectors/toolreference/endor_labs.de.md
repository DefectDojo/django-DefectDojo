---
title: "Endor Labs"
description: "Einrichtung des Endor Labs Upstream-Connectors für DefectDojo"
weight: 54
audience: pro
---
Der Endor-Labs-Connector verwendet die Endor-Labs-REST-API, um einen gesamten Endor-Labs-**Namespace** zu synchronisieren. DefectDojo ermittelt jedes Endor-**Projekt** als Eintrag und importiert die Befunde dieses Projekts, wobei Endors **Reachability**-Bewertung übernommen wird, damit Sie Schwachstellen priorisieren können, deren betroffener Code tatsächlich erreichbar ist.

#### Voraussetzungen

Sie benötigen einen Endor-Labs-**API-Schlüssel** (eine Schlüsselkennung plus deren Secret) und den **Namespace**, den Sie synchronisieren möchten. Erstellen Sie den Schlüssel in der Endor-Labs-Plattform unter **Settings \> Access \> API Keys**; der Schlüssel benötigt Lesezugriff auf die Projekte und Befunde in diesem Namespace.

Der Connector authentifiziert sich, indem er den API-Schlüssel und das Secret gegen ein kurzlebiges Bearer-Token eintauscht — das Secret wird nur für diesen Austausch verwendet und nie im Klartext gespeichert.

#### Connector-Zuordnungen

1. Geben Sie `https://api.endorlabs.com` in das Feld **Location** ein. Wenn Ihr Tenant in einer anderen Region gehostet wird, verwenden Sie stattdessen die API-Basis-URL dieser Region.
2. Geben Sie den zu synchronisierenden Endor-Labs-**Namespace** ein (zum Beispiel `your-org` oder `your-org.team`).
3. Geben Sie die **API-Key**-Kennung ein.
4. Geben Sie das zum Schlüssel gehörende **API Secret** ein.
5. Setzen Sie optional **Traverse Child Namespaces** auf `true`, um auch Befunde aus untergeordneten Namespaces des konfigurierten Namespace zu importieren.
6. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden. Befunde unterhalb des gewählten Schweregrads werden nicht importiert.

DefectDojo erstellt für jedes Endor-Labs-Projekt im Namespace einen Eintrag und importiert dessen Befunde, wobei Endor-Schweregrade auf DefectDojo-Schweregrade, die CVE/GHSA-Kennungen und den CVSS-Score jeder Schwachstelle sowie Endors Reachability-Tags abgebildet werden. Die Reachability-Bewertung (zum Beispiel *Reachable — vulnerable function is called* oder *Unreachable*) wird als Impact des Befunds sowie als Tag angezeigt.

Weitere Informationen finden Sie in der **[Endor-Labs-REST-API-Dokumentation](https://docs.endorlabs.com/rest-api/)**.
