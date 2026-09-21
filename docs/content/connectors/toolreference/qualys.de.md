---
title: "Qualys"
description: "Einrichtung des Qualys Upstream-Connectors für DefectDojo"
weight: 109
audience: pro
---
Der Qualys-Connector importiert **VMDR-Host-Schwachstellendetektionen** — jeweils verknüpft mit den Metadaten der Qualys-KnowledgeBase (QID) — von der Qualys Cloud Platform. DefectDojo erstellt für jeden Qualys-**Host** in Ihrer Subscription einen Eintrag.

#### Voraussetzungen

Ein Qualys-Benutzerkonto mit **VMDR-API-Zugriff** sowie die **API-Server(Platform)-URL** Ihrer Subscription — diese unterscheidet sich je nach Subscription. Sie finden sie in der Qualys-Oberfläche unter **Help \> About** oder auf der Qualys-Seite [Platform Identification](https://www.qualys.com/platform-identification/) (zum Beispiel `https://qualysapi.qualys.com` für US Platform 1, oder `https://qualysapi.qg2.apps.qualys.com` für US Platform 2).

#### Connector-Zuordnungen

1. Geben Sie Ihre Qualys-API-Server-URL in das Feld **Location** ein (zum Beispiel `https://qualysapi.qualys.com`).
2. Geben Sie den Qualys-API-Benutzernamen in das Feld **Username** ein.
3. Geben Sie das Qualys-API-Passwort in das Feld **Secret** ein.
4. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jeder Qualys-Host wird zu einem Eintrag. Detektionen, die Qualys als **Fixed** markiert hat, werden ausgeschlossen, sodass ein erneuter Import behobene Befunde schließt.
