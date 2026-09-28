---
title: Filter-Index
description: Referenz für alle Filter in DefectDojo
weight: 5
aliases:
- /de/en/working_with_findings/organizing_engagements_tests/filter_index
---

**Hinweis: Dieser Artikel behandelt derzeit nur die in der DefectDojo Pro-UI verfügbaren Befund-Filter, wird aber in Zukunft erweitert, um weitere Objekttypen sowie Open-Source-Filter abzudecken.** 

Hier ist eine Liste von Filtern, die in der DefectDojo Pro-UI angewendet werden können, um Listen von Befunden zu sortieren.  DefectDojo-Filter können dabei helfen, durch Objektlisten zu navigieren, individuelle [Dashboards](/metrics_reports/dashboards/custom-dashboards/) zu erstellen oder Automatisierung über die [Rules Engine](/automation/rules_engine/about) einzurichten.

## Wie Datumsfilter ausgewertet werden

Filter, die ein Datum verwenden — **Date Created**, **SLA Expiration Date**, **Last Status Update**, **Planned Remediation Date** sowie die unten aufgeführten Jira-Datumsfilter — bieten fünf Operatoren:

| Operator | Übereinstimmung |
| --- | --- |
| **On** | Der gesamte genannte Tag. |
| **Before** | Alles bis zum Beginn des genannten Tages. Der genannte Tag selbst ist **nicht** eingeschlossen. |
| **After** | Alles ab dem Beginn des genannten Tages — der genannte Tag **ist** also eingeschlossen. |
| **During** | Ein Starttag bis zu einem Endtag, beide **eingeschlossen**. |
| **Within** | Ein rollierendes Fenster, das jetzt endet: die letzten 7, 14, 30, 90 oder 180 Tage, oder das letzte Jahr. |

Beachten Sie, dass **Before** und **After** bewusst keine Spiegelbilder voneinander sind: *Before 8. August* schließt den 8. August aus, während *After 8. August* ihn einschließt.

### Tagesgrenzen und Ihre Zeitzone

**On**, **Before**, **After** und **During** ermitteln ihre Tagesgrenzen in **Ihrer eigenen Zeitzone**, die aus Ihrem Browser erkannt wird. Ein Datumsbereich umfasst daher Mitternacht bis Mitternacht so, wie *Sie* sie erleben, statt in UTC oder in der Zeitzone des Servers. Zwei Personen in unterschiedlichen Zeitzonen können bei Befunden, die nahe an einer Tagesgrenze liegen, für denselben Filter leicht unterschiedliche Ergebnisse sehen.

**Within** ist davon nicht betroffen — es handelt sich um ein rollierendes Fenster, das rückwärts vom aktuellen Zeitpunkt gemessen wird, sodass keine Tagesgrenze aufgelöst werden muss.

> **Wo dies nicht gilt.** Nur Anfragen aus der Pro-UI übermitteln Ihre Zeitzone. Alles, was ohne Browser läuft — die `/api/v2`-REST-API, geplante Berichte und die Rules Engine — greift auf die konfigurierte Zeitzone des Servers zurück (`DD_TIME_ZONE`, standardmäßig `UTC`, sofern Ihr Administrator dies nicht geändert hat). Wenn sich Ihre Browser-Zeitzone von der des Servers unterscheidet, können ein geplanter Bericht und ein Bildschirmfilter mit demselben Datum leicht unterschiedliche Zeilen liefern. Exporte, die aus einer gefilterten Tabelle in der UI gestartet werden, sind davon nicht betroffen — sie verwenden Ihre Zeitzone und stimmen mit dem überein, was Sie gerade angesehen haben.

## Wie Zahlenfilter ausgewertet werden

Numerische Filter — einschließlich **Age** und **SLA** — bieten neben dem Wert einen Vergleichsoperator: **Equals**, **Not Equals**, **Greater Than**, **Greater Than or Equal To**, **Less Than**, **Less Than or Equal To**, **In List** und **Not In List**. Wird ein Wert eingegeben, ohne einen Operator auszuwählen, gilt **Equals**.

## SLA-Filter

Drei Filter decken SLA ab, und sie beantworten unterschiedliche Fragen:

| Filter | Typ | Was er erfasst |
| --- | --- | --- |
| **SLA Expiration Date** | Datum, mit den obigen Operatoren | Das Datum, an dem die SLA des Befunds abläuft. |
| **SLA** | Zahl, mit Operatoren | **Verbleibende Tage** auf der SLA-Uhr. Negative Werte bedeuten überfällig, sodass `Less Than 0` alles findet, was seine Frist bereits überschritten hat, und `Less Than 7` alles findet, was innerhalb der Woche fällig ist. |
| **Mitigated Within SLA** | Wahr/Falsch | Ob ein Befund, der **behoben wurde**, vor Ablauf seiner SLA behoben wurde. |

**Mitigated Within SLA ist enger gefasst, als es klingt, und das führt oft zu Verwirrung.** Beide Werte erfassen ausschließlich Befunde, die **bereits behoben** sind und **nicht den Schweregrad Info** haben:

* **True** — behoben am oder vor dem SLA-Ablaufdatum.
* **False** — behoben nach dem SLA-Ablaufdatum.

Ein **offener** Befund, der bereits überfällig ist, erfüllt **keinen** der beiden Werte, da er noch nicht behoben wurde. Um solche Befunde zu finden, verwenden Sie stattdessen **SLA** `Less Than 0`. Befunde mit dem Schweregrad Info sind bei beiden Werten ausgeschlossen.

> Wenn bei der SLA-Konfiguration eines Befunds **Cap SLA by CISA KEV Due Date** aktiviert ist, spiegeln sowohl **SLA** als auch **SLA Expiration Date** die verkürzte, KEV-begrenzte Frist wider statt des einfachen, auf dem Schweregrad basierenden Zeitfensters. Es gibt dafür keinen separaten Hinweis in den Filtern — siehe [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/).

## Befunde
Diese Felder sind spezifisch für DefectDojo-Befunde und werden zur Organisation eines Befunds verwendet.  Jeder dieser Filter ist eine eigene Spalte in der Tabelle „All Findings“.

Befunde können in DefectDojo nach Folgendem gefiltert werden:

### DefectDojo-Metadaten
Diese Filter beziehen sich direkt auf die Kernfunktionalität von DefectDojo.

##### Kann nicht geändert werden
Diese Filter werden zum Zeitpunkt der Erstellung des Issues zugewiesen und können nicht direkt über Edit Finding geändert werden.

* Finding Severity (Info, Niedrig, Mittel, Hoch oder Kritisch)
* Product
* Product Type
* Engagement
* Engagement Version
* Test
* Test Type
* Test Version
* Date Created
* Age (Alter des Befunds in Tagen)
* SLA (verbleibende Tage auf der SLA-Uhr — negativ bedeutet überfällig; siehe [SLA-Filter](#sla-filters))
* SLA Expiration Date (siehe [SLA-Filter](#sla-filters))
* Mitigated Within SLA (True oder False — beachten Sie, dass dies nur auf Befunde zutrifft, die bereits behoben wurden; siehe [SLA-Filter](#sla-filters))
* Reporter (Benutzer oder Dienst, der den Befund erstellt hat)
* Found by (bezieht sich auf das Tool)

##### Kann geändert werden
Diese Felder werden bei der Erstellung eines Issues festgelegt, können aber im weiteren Verlauf geändert werden.

* [Status](/triage_findings/findings_workflows/finding_status_definitions/)
* Last Status Update (Zeitstempel)
* Mitigated (True oder False)

##### Zusätzliche Modellfunktionen
Diese DefectDojo-Funktionen können verwendet werden, um Ihre Befunde weiter zu organisieren oder die Behebung zu verfolgen.

* Finding Tags
* Reviewers (zugewiesener Benutzer)
* Has Notes (True/False)
* Group (bezieht sich auf die [Finding Group](/triage_findings/findings_workflows/editing_findings/#finding-group-actions), sofern vorhanden)
* Risk Acceptance (wählen Sie eine oder mehrere bestehende Risikoakzeptanzen aus der Liste aus)

### Tool-spezifische Metadaten
Diese Felder haben keinen direkten Einfluss auf die Funktionalität von DefectDojo, liefern aber zusätzliche Informationen, die helfen, Probleme zu erklären und zu beheben.  Sie können bei der ursprünglichen Erstellung eines Befunds (anhand von Informationen aus einem eingehenden Bericht) festgelegt oder von einem Benutzer geändert werden.

* CWE Value
* Vulnerability ID (in der Regel eine CVE)
* EPSS Score
* EPSS Percentile
* Service
* Planned Remediation Date
* Planned Remediation Version
* Has Component (True/False)
* Component Name
* Component Version
* File Path
* Effort for Fixing

### Jira-Metadaten
Bei Verwendung der Jira-Integration verfolgen diese Filter Aktualisierungen an verknüpften Jira-Issues.

* Jira Issue (kann danach filtern, ob der Befund eines hat oder nicht)
* Jira Age (Alter des Jira-Issues)
* Jira Change (letzter Zeitpunkt, an dem Änderungen an Jira übertragen wurden)
