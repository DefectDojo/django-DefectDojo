---
title: "Intigriti"
description: "Einrichtung des Intigriti Upstream-Connectors für DefectDojo"
weight: 78
audience: pro
---
Der Intigriti-Connector verwendet die externe Unternehmens-API von Intigriti, um Bug-Bounty-/Pentest-**Submissions** in DefectDojo zu übertragen. Er synchronisiert das gesamte Unternehmenskonto: DefectDojo ermittelt jedes Programm, auf das das Token zugreifen kann, und erstellt für jedes einen Eintrag; anschließend werden die Submissions dieses Programms als Befunde importiert.

#### Voraussetzungen

Sie benötigen ein Intigriti-**Company-API-Token**. Generieren Sie im Intigriti-Unternehmensportal unter **Company Settings > API** (Scope `company_external_api`) ein Zugriffstoken mit Lesezugriff auf Ihre Programme und Submissions. Ein dediziertes Token für DefectDojo wird empfohlen. Das Token wird als Bearer-Token gesendet und nie protokolliert.

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL der externen Intigriti-Unternehmens-API in das Feld **Location** ein: `https://api.intigriti.com/external/company`. Die URL muss HTTPS verwenden.
2. Geben Sie das Unternehmens-API-Token in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ordnet jedes Intigriti-**Programm** einem Eintrag zu und jede **Submission** einem Befund, mit dem Submission-Code als Schlüssel. Der Schweregrad des Befunds folgt der Bewertung von Intigriti (Exceptional/Critical → Critical, dann High/Medium/Low, ansonsten Informational), und der Lifecycle-Status der Submission wird auf den Befundstatus abgebildet: offene/in Triage befindliche Submissions sind aktiv, akzeptierte Submissions sind verifiziert, und geschlossene Submissions werden je nach Schließungsgrund zu behoben, einem Duplikat, außerhalb des Geltungsbereichs, falsch-positiv oder risikoakzeptiert. Die Befundbeschreibung übernimmt den Schwachstellentyp des Reports, das betroffene Asset, den Proof of Concept und die Antworten des Forschers.

Weitere Informationen finden Sie in der [Intigriti-API-Dokumentation](https://kb.intigriti.com/en/articles/6117846-intigriti-api).
