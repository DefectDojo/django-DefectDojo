---
title: "Bugcrowd"
description: "Einrichtung des Bugcrowd Upstream-Connectors für DefectDojo"
weight: 29
audience: pro
---
Der Bugcrowd-Connector verwendet die Bugcrowd-REST-API, um Einreichungen aus Ihren Bug-Bounty- und Vulnerability-Disclosure-Programmen zu importieren. DefectDojo ermittelt die Programme, auf die Ihr API-Token zugreifen kann, und erstellt für jedes einen Eintrag, wobei die Einreichungen des Programms als Befunde importiert werden.

#### Voraussetzungen

Sie benötigen ein Bugcrowd-**API-Token** mit Zugriff auf die zu importierenden Programme. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen, damit automatisierte Aktivitäten leicht von manuellen Team-Aktionen zu unterscheiden sind. Generieren Sie das Token in Bugcrowd unter **Organization settings \> API credentials**; Lesezugriff auf Submissions, Programme und Targets ist ausreichend.

#### Connector-Zuordnungen

1. Geben Sie `https://api.bugcrowd.com` in das Feld **Location** ein.
2. Geben Sie Ihr Bugcrowd-API-Token in das Feld **Secret** ein. Es wird als `Authorization: Token`-Header gesendet.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jedes Bugcrowd-**Programm** wird zu einem Eintrag, und seine Einreichungen werden mit dem beibehaltenen Bugcrowd-Schweregrad als Befunde importiert. Doppelte Einreichungen werden ausgeschlossen, sodass ein erneuter Import keine wiederholten Befunde für dasselbe Problem erzeugt.
