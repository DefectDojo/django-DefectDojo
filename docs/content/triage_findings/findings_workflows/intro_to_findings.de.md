---
title: Einführung in Befunde
description: Der zentrale Workflow und das Schwachstellen-Tracking-System von DefectDojo
weight: 1
aliases:
- /en/working_with_findings/intro_to_findings
---

Befunde sind der wichtigste Weg, mit dem DefectDojo den Melde- und Behebungsprozess Ihrer Sicherheitstools standardisiert und steuert. Unabhängig davon, ob eine Schwachstelle in SonarQube, Acunetix oder dem individuellen Tool Ihres Teams gemeldet wurde, ermöglichen Ihnen Befunde, jede Schwachstelle auf die gleiche Weise zu verwalten.

## Was sind Befunde?

Befunde in DefectDojo bestehen aus den folgenden Komponenten:

* Die gemeldeten Schwachstellendaten
* Der „Status" des Befunds, mit dem die Behebung, Risikoakzeptanz oder andere Entscheidungen rund um die Schwachstelle nachverfolgt werden
* Weitere Metadaten zum Befund. Dazu können beispielsweise der Ort des Befunds in Ihrem Netzwerk, die Behebungsvorschläge eines Tools oder Links zu einem zugehörigen CWE- oder EPSS-Score gehören.

Zusätzlich zur Speicherung der Schwachstellendaten und der Bereitstellung eines Rahmens für die Behebung erweitert DefectDojo Ihre Befunde auf folgende Weise:

* Automatisches Hinzufügen zugehöriger EPSS-Scores zu einem Befund, um die Ausnutzbarkeit zu beschreiben
* Automatisches Übersetzen der Schweregrad-Metrik eines Sicherheitstools in einen Schweregrad-Wert für jeden Befund, der dem Befund gemäß der SLA-Konfiguration Ihres Produkts eine SLA zuweist.

Insgesamt sind DefectDojo-Befunde so konzipiert, dass sie mit der Produkthierarchie zusammenarbeiten, um Ihre Bemühungen zu standardisieren und eine einheitliche Methode auf jedes Produkt anzuwenden.

## Eine Befund-Seite

Die Befund-Seite enthält verschiedene Komponenten. Jede wird beim Erstellen des Befunds durch den Importprozess befüllt.

![image](images/Introduction_to_Findings.png)

1. **Der Titel des Befunds:** Dies ist normalerweise eine beschreibende Kurzform, die die erkannte Schwachstelle oder das Problem identifiziert. In diesem Bereich werden auch benutzerdefinierte Tags angezeigt, falls vorhanden.
​
2. **Befund-Übersicht:** Dieser Bereich enthält fünf separate Seiten mit relevanten Informationen zum Befund: Description, Mitigation, Impact, References und Notes. Diese Felder können automatisch anhand der eingehenden Schwachstellendaten befüllt werden, oder sie können von einem DefectDojo-Benutzer bearbeitet werden, um zusätzlichen Kontext bereitzustellen.
​
- ​**Description** ist eine detailliertere Zusammenfassung und Erläuterung des betreffenden Befunds.
- ​**Mitigation** ist eine vorgeschlagene Methode zur Behebung des Befunds, damit er in Ihrem System nicht mehr vorhanden ist.
- ​**Impact** beschreibt die Auswirkung der Schwachstelle auf Ihre Sicherheitslage. Diese Seite kann beschreibenden Text enthalten oder einen [CVSS Vector String](https://qualysguard.qualys.com/qwebhelp/fo_portal/setup/cvss_vector_strings.htm), eine Kurzform zur Kommunikation der allgemeinen Ausnutzbarkeit der Schwachstelle sowie der Folgen einer Ausnutzung für Ihre Organisation. Impact steht in engem Zusammenhang mit dem Feld „Severity" des Befunds.
- ​**References** listet alle Links oder zusätzlichen Informationen auf, die für diesen Befund relevant sind, sofern vorhanden.
- ​**Notes** ist eine Seite, auf der Sie weitere relevante Informationen zu diesem Befund festhalten können. Notes sind ausschließlich DefectDojo-interne Metadaten und werden nicht beim Import erstellt. Nutzen Sie dieses Feld, um Ihren Fortschritt bei der Behebung zu verfolgen oder um dem Befund genauere Details hinzuzufügen.
​
3. **Zusätzliche Details:** Dieser Bereich listet weitere Details zu diesem Befund auf, sofern relevant:


	* Request/Response-Paare, die mit der Schwachstelle verknüpft sind
	* Schritte zur Reproduktion der Schwachstelle
	* Severity Justification, in der Sie eine detailliertere Erklärung des Schweregrads oder der Auswirkung des Befunds festhalten können.
	​

4. **Metadaten: Dieser Bereich enthält filterbare Metadaten zum Befund:**


	* **ID:** der ID-Wert des Befunds in DefectDojo
	* **Severity:** der Schweregrad-Wert des Befunds. Kann Info, Niedrig, Mittel, Hoch oder Kritisch sein. Der Schweregrad eines Befunds steht in direktem Zusammenhang mit der berechneten SLA des Befunds, basierend auf dem Produkt, in dem der Befund gespeichert ist.
	* **Status:** der Status des Befunds. Kann entweder Aktiv oder Inaktiv sein. Zusätzlich dazu können Befunde auch den Status Duplikat, Behoben, Falsch-positiv, Außerhalb des Geltungsbereichs, Risiko akzeptiert oder In Prüfung haben. Diese Status erläutern den Zustand des Befunds genauer.
	* **Type:** dieses Feld beschreibt, wie der Befund gefunden wurde, entweder durch eine statische (SAST) Analyse des Quellcodes oder durch eine dynamische (DAST) Analyse des laufenden Produkts. Dieses Feld wird durch den Tool-Typ bestimmt.
	* **Location:** dieses Feld beschreibt den zugehörigen Dateipfad zu Ihrer Schwachstelle, sofern relevant.
	* **Line:** dieses Feld beschreibt die Codezeile, die die Schwachstelle enthält, sofern relevant.
	* **Date Discovered:** dieses Feld zeigt entweder das Datum, an dem der Befund in DefectDojo importiert wurde, oder das Datum, an dem der Befund vom Tool entdeckt wurde.
	* **Age:** dieses berechnete Feld zeigt die Anzahl der Tage, die der Befund bereits aktiv ist.
	* **Reporter:** dies ist der Benutzername des DefectDojo-Kontos, das diesen Befund erstellt hat.
	* **CWE:** dieses Feld ist ein Link zur externen CWE-Definition (Common Weakness Enumeration), die für diesen Befund gilt.
	* **Vulnerability ID:** falls es für diese Schwachstelle innerhalb des Tools selbst einen bestimmten ID-Wert gibt, wird dieser hier erfasst.
	* **EPSS Score / Percentile:** wenn die Quelldaten einen CWE-Wert enthalten, ruft DefectDojo automatisch einen [EPSS Score](https://www.first.org/epss/) und ein Percentile (Exploit Prediction Scoring System) ab. EPSS gibt die Wahrscheinlichkeit an, mit der eine Software-Schwachstelle ausgenutzt werden kann, basierend auf realen Exploit-Daten. EPSS-Scores werden laufend anhand der neuesten Exploit-Daten von First aktualisiert.
	* **Found By:** hier wird der Scanner aufgeführt, mit dem diese Schwachstelle gefunden wurde.
	​

## Notizen und @-Erwähnungen

Die Seite **Notes** eines Befunds ist der Ort, an dem Ihr Team Kontext festhält, der nicht Teil der importierten Scan-Daten ist — Fortschritt bei der Behebung, Triage-Entscheidungen oder sonstige Kommentare. Notes sind ausschließlich DefectDojo-interne Metadaten und werden nie zum Importzeitpunkt erstellt.

Notizen erscheinen als Feed, neueste zuerst, und Sie können die Reihenfolge auf älteste zuerst umstellen. Jede Notiz zeigt ihren Autor, den Zeitpunkt der Erstellung, ihren Notiztyp und ein **Private**-Badge, wenn die Notiz privat ist. Eine private Notiz wird immer nur der Person angezeigt, die sie verfasst hat.

### Notizen in Markdown schreiben

Notizeinträge unterstützen Markdown, sodass Sie Überschriften, **fetten** und *kursiven* Text, Aufzählungen und nummerierte Listen, Blockzitate, Tabellen, Links und Code-Blöcke verwenden können. Der Notizeditor ist derselbe, der auch für die Beschreibung eines Befunds verwendet wird, mit einer Symbolleiste für die gängigen Formatierungsoptionen. Um eine Notiz genau so zu lesen, wie sie eingegeben wurde, statt als formatierten Text, verwenden Sie den Umschalter oben rechts im Notiztext.

### Bearbeiten, Löschen und Verlauf

Jede Notiz verfügt über ein Aktionsmenü mit **Edit**, **View History** und **Delete**, wobei jeder Eintrag nur angezeigt wird, wenn Sie berechtigt sind, ihn zu verwenden:

* Eine von Ihnen selbst verfasste Notiz können Sie jederzeit bearbeiten, löschen und ihren Verlauf einsehen.
* Um die Notiz einer anderen Person zu verwalten, benötigen Sie die entsprechende Rollenberechtigung für das Objekt, zu dem die Notiz gehört: Note Edit, Note Delete oder Note View History.
* Zum Hinzufügen einer Notiz ist Note Add erforderlich, über das jede Rolle oberhalb von Reader verfügt — und auch Reader verfügen darüber.

Eine bearbeitete Notiz wird mit **(edited)** gekennzeichnet und erfasst, wer sie wann geändert hat. **View History** listet jede Version der Notiz auf, neueste zuerst, sodass beim Umschreiben einer Notiz nichts verloren geht. Nur der Eintrag selbst kann geändert werden: Der Typ einer Notiz und ihr Privat-Flag stehen fest, sobald die Notiz erstellt wurde.

### Einen Benutzer mit @ erwähnen

Wenn Sie eine Notiz hinzufügen, können Sie einen anderen DefectDojo-Benutzer **@erwähnen**, um ihn zu benachrichtigen. Geben Sie dazu an beliebiger Stelle in der Notiz `@` unmittelbar gefolgt vom Benutzernamen ein (zum Beispiel `@alice`). Beim Speichern der Notiz erhält jeder erwähnte Benutzer eine **user-mentioned**-Benachrichtigung, die zurück zur Notiz verlinkt.

Ein paar Details, die es zu wissen gilt:

* Das `@` muss am **Anfang der Notiz stehen oder direkt auf ein Leerzeichen folgen**. Das ist beabsichtigt — so wird verhindert, dass mitten im Satz geschriebene E-Mail-Adressen (wie `alice@example.com`) versehentlich Erwähnungen auslösen.
* Der Name nach `@` muss mit einem **vorhandenen, aktiven** DefectDojo-Benutzernamen übereinstimmen. Erwähnungen unbekannter oder deaktivierter Benutzer werden ignoriert.
* Ein abschließender Punkt wird ignoriert, sodass eine Erwähnung am Satzende (`thanks @alice.`) trotzdem aufgelöst wird.
* Sie können in einer einzigen Notiz mehr als einen Benutzer erwähnen.

Sie können Benutzer über die Benutzeroberfläche in Notizen zu **Findings**, **Tests**, **Engagements** und **Risk Acceptances** @erwähnen. Die Eingabe von `@` öffnet eine Liste passender Benutzer; die Auswahl aus dieser Liste ist der zuverlässige Weg, jemanden zu erwähnen, da dabei der Benutzername genau so eingefügt wird, wie ihn die Benachrichtigungssuche erwartet.

Die Erwähnung wird über das Benachrichtigungsereignis `user_mentioned` zugestellt. Siehe [Notifications](/admin/notifications/about_notifications/) für Informationen zur Zustellung und Konfiguration von Benachrichtigungen — insbesondere ist `user_mentioned` eines der Ereignisse, die eine systemweite Einstellung auch dann noch zustellen kann, wenn ein Benutzer seine Benachrichtigungen ansonsten stummgeschaltet hat (siehe [Specific overrides](/admin/notifications/about_notifications/#specific-overrides)).

## Beispiel-Workflows für Befunde

Wie Sie mit Befunden in DefectDojo arbeiten, hängt von den Verantwortlichkeiten Ihres Teams innerhalb Ihrer Organisation ab. Hier sind einige Beispiele für diese Prozesse und wie DefectDojo dabei helfen kann:

### Schwachstellen entdecken und melden

Wenn Sie für die Sicherheitsberichterstattung in vielen verschiedenen Kontexten, Software-Produkten oder Teams zuständig sind, kann DefectDojo über die aufgedeckten Schwachstellen berichten. Mithilfe der Produkthierarchie können Sie Ihre Befund-Daten dem passenden Kontext zuordnen. Zum Beispiel:

* Jedes Produkt in DefectDojo kann eine andere SLA-Konfiguration haben, sodass Sie Befunde, die in der Produktion oder anderen hochsensiblen Umgebungen entdeckt werden, sofort kennzeichnen können.
* Sie können einen Bericht direkt aus einem **Product Type, Product, Engagement oder Test** erstellen, um in Ihrem Sicherheitskontext „hinein- und herauszuzoomen". **Tests** enthalten Ergebnisse eines einzelnen Tools, **Engagements** können mehrere Tests kombinieren, **Products** können mehrere Engagements enthalten, **Product Types** können mehrere Products enthalten.

Weitere Informationen zum Erstellen eines Berichts finden Sie in unseren Anleitungen zu **[Custom Reporting](/metrics_reports/reports/)**.

### Schwachstellen mithilfe des Befund-Status triagieren

Wenn Ihr Team die entdeckten Befunde validieren muss, können Sie dies tun, indem Sie den Befunden bei der Überprüfung manuell den Status **Verified** zuweisen. Sie können auch andere Status anwenden, wie zum Beispiel:

* **False Positive:** Ein Tool hat die Bedrohung erkannt, aber die Bedrohung ist in der Umgebung nicht aktiv.
* **Out Of Scope:** Aktiv, aber irrelevant für den aktuellen Testaufwand.
* **Risk Accepted:** Aktiv, aber als nicht prioritär eingestuft, bis die Risikoakzeptanz abläuft.
* **Under Review:** kann aktiv oder inaktiv sein - Ihr Team untersucht den Sachverhalt noch.
* **Mitigated:** Dieses Problem wurde behoben, seit der Befund erstellt wurde.

Wenn ein Tool bei einem späteren Import einen bereits triagierten Befund erneut meldet, merkt sich DefectDojo den vorherigen Status des Befunds und aktualisiert ihn entsprechend. Befunde mit den Status **False Positive**, **Out Of Scope, Risk Accepted und Under Review** bleiben unverändert, aber jeder Befund, der **Mitigated** war, wird **reaktiviert**, um Sie darüber zu informieren, dass der Befund in die Testumgebung zurückgekehrt ist.

### Teamweiten Konsens und Verantwortlichkeit mit Risikoakzeptanzen sicherstellen

Ein Teil der Verantwortung eines Sicherheitsteams besteht darin, mit Entwicklern zusammenzuarbeiten, um die Behebung von Sicherheitsproblemen zu priorisieren oder zurückzustellen. Hier kommen Risikoakzeptanzen ins Spiel. Das Hinzufügen einer Risikoakzeptanz zu einem Befund ermöglicht Ihnen Folgendes:

* Aufzeichnungen und „Artefakt"-Dateien in DefectDojo speichern - dabei kann es sich um E-Mails von Kollegen handeln, die die Risikoakzeptanz bestätigen, um Besprechungsnotizen oder einfach um eine schriftliche Begründung Ihres eigenen Sicherheitsteams für die Akzeptanz des Risikos.
* Ein Ablaufdatum zur Risikoakzeptanz hinzufügen, sodass die Schwachstelle nach einem bestimmten Zeitraum erneut überprüft werden kann.

Jedes Mitglied eines Appsec-Teams weiß, dass die Priorisierung der Problembehebung nicht ausschließlich den Entwicklerteams überlassen werden kann. Risikoakzeptanzen helfen Ihnen daher, diese sensiblen Entscheidungen zu protokollieren, wenn sie getroffen werden.

### Aktuelle Schwachstellen mithilfe von CVEs und EPSS-Scores überwachen (Pro-Funktion)

Manchmal können sich die Ausnutzbarkeit und die Bedrohung durch eine bekannte Schwachstelle aufgrund neuer Daten ändern. Damit Ihre Arbeit stets aktuell bleibt, arbeitet DefectDojo Pro mit First.org zusammen, um eine Datenbank der neuesten, mit Befunden verknüpften EPSS-Scores zu pflegen. Alle Befunde in DefectDojo Pro werden automatisch anhand ihres EPSS-Werts aktuell gehalten, der direkt auf der CVE des Befunds basiert.

Wenn sich der EPSS-Score eines Befunds ändert (d. h. der zugehörige Befund wird stärker oder weniger ausnutzbar), passt sich der Schweregrad des Befunds entsprechend an.
