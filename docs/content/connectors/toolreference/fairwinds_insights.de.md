---
title: "Fairwinds Insights"
description: "Einrichtung des Fairwinds Insights Upstream-Connectors für DefectDojo"
weight: 56
audience: pro
---
Der Fairwinds-Insights-Connector verwendet die REST-API von [Fairwinds Insights](https://insights.fairwinds.com), um **Kubernetes-Sicherheitsbefunde** aus Ihrer gesamten Organisation zu importieren. DefectDojo zählt jeden aktiven **Cluster** auf und erstellt für jeden einen Eintrag; anschließend werden die Security-**Action Items** dieses Clusters \(von Polaris, Trivy, Kube\-bench, OPA und den anderen Insights-Berichten\) als Befunde importiert — es gibt keine Pro-Cluster-Konfiguration.

#### Voraussetzungen

Sie benötigen einen Fairwinds-Insights-**Organisationsnamen** und ein **API-Token**. Erstellen Sie das Token in der Insights-App unter **Organization Settings \> Tokens**; ein `read_only`-Token ist ausreichend. Das Token ist organisationsweit gültig und wird als Bearer-Token gesendet; es wird nie protokolliert.

#### Connector-Zuordnungen

1. Behalten Sie den vorgegebenen Wert im Feld **Location**, `https://insights.fairwinds.com`, oder geben Sie Ihren Insights-Host explizit an.
2. Geben Sie Ihren Insights-**Organization**-Namen ein (den Slug, der in Ihrer Dashboard-URL angezeigt wird).
3. Geben Sie das Insights-API-Token in das Feld **Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jeden aktiven **Cluster** einem Eintrag zu und jedes Security-**Action Item** einem Befund: Der Schweregrad stammt aus Fairwinds' numerischer Bewertung \(abgebildet auf DefectDojos Info–Kritisch\), der Fairwinds-Bericht, der das Item erzeugt hat \(`polaris`, `trivy`, `kube-bench`, ...\), wird zu einem Tool-Tag, die betroffene Kubernetes-Ressource und das Container-Image werden einbezogen, und etwaige CVE-Kennungen werden extrahiert. Befunde werden als statische Befunde erfasst und anhand der Fairwinds-Action-Item-ID dedupliziert.

Weitere Informationen finden Sie in der [Fairwinds-Insights-API-Dokumentation](https://insights.docs.fairwinds.com/technical-details/api/).
