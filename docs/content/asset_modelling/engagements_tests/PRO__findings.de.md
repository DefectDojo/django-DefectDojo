---
title: Befunde
description: Befunde in DefectDojo Pro verstehen
audience: pro
weight: 5
---

Organisationen	→ Assets → Engagements → Tests → **BEFUNDE**

## Überblick
**Befunde** stellen die unterste Ebene der Produkthierarchie dar, auf der einzelne Schwachstellen erfasst und verwaltet werden. Sie sind die zentrale Methode, mit der DefectDojo den Melde- und Behebungsprozess Ihrer Sicherheitstools standardisiert und steuert. Unabhängig davon, ob eine Schwachstelle in SonarQube, Acunetix oder dem individuellen Tool Ihres Teams gemeldet wurde, ermöglichen Ihnen Befunde, jede Schwachstelle auf dieselbe Weise zu verwalten.

Beispiele für Befunde sind:
- **Cookie Not Marked as HttpOnly**
- **Out-of-Date Version (PHP)**
- **Out-of-Band Code Evaluation (PHP)**
- **Out-of-Date Version (MySQL)**
- **Backup Source Code Detected**
- **Blind Cross-Site Scripting**

Neben der Speicherung der Schwachstellendaten und der Bereitstellung eines Rahmens für die Behebung erweitert DefectDojo Ihre Befunde auch auf folgende Weise:
- Automatisches Hinzufügen zugehöriger EPSS-Werte zu einem Befund, um die Ausnutzbarkeit zu beschreiben
- Automatisches Übersetzen der Schweregrad-Metrik eines Sicherheitstools in einen Schweregrad-Wert für jeden Befund, wodurch dem Befund gemäß der SLA-Konfiguration Ihres Assets eine SLA zugewiesen wird. Weitere Informationen zur SLA-Konfiguration finden Sie [hier](/asset_modelling/pro_hierarchy/priority_sla/#working-with-slas).

Insgesamt sind Befunde so konzipiert, dass sie mit der Produkthierarchie zusammenarbeiten, um Ihre Bemühungen zu standardisieren und für jedes Asset eine einheitliche Methode anzuwenden.

## Zugriff auf Befunde
Befunde sind über die Seitenleiste zugänglich. Das Untermenü bietet Zugriff auf Aktive und Behobene Befunde, Alle Befunde (unabhängig vom Status Offen oder Geschlossen), Befundgruppen, Befundvorlagen und den Workflow für neue Befunde. Einzelne Befunde sind auch innerhalb des Tests zugänglich, der sie enthält.

[Risikoakzeptierte Befunde] (/triage_findings/findings_workflows/os__risk_acceptance/) sind über den Bereich **Risikoakzeptanzen** in der Seitenleiste zugänglich.

![image](images/profindings_ss1.png)

### Berechtigungen
Jeder Befund gehört zu einem Test, sodass DefectDojo nachvollziehen kann, welcher Scan oder welche Bewertung die Schwachstelle ursprünglich identifiziert hat.

Da Befunde zu Tests gehören, wird der Zugriff auf Befunde durch den Zugriff eines Benutzers auf das Asset bestimmt, das den Test enthält. Tests verfügen nicht über eigene Zugriffskontrolllisten.

## Befundansicht
Befundansichten enthalten verschiedene Tabellen, die dabei helfen, den Status eines Befunds auf einen Blick zu erfassen.

### Befundübersicht
- **Beschreibung**: Die Beschreibung des Befunds (je nach Art des Befunds automatisch hinzugefügt oder manuell erstellt).
- **Behebung**: Vorgeschlagene Schritte zur Behebung.
- **Allgemeine Behebungsrichtlinie**: Die standardisierte Behebungsrichtlinie für den ausgewählten Befund.
Behebungsrichtlinien finden Sie in der Seitenleiste unter **Konfiguration** → **Behebungsrichtlinien** und können dort bearbeitet werden.
- **Auswirkung**: Mögliche Auswirkung, wenn der Befund nicht behoben wird.
- **Referenzen**: URL, die auf die spezifische Beschreibung des Befunds durch das Drittanbieter-Scan-Tool verweist. Referenzen können beispielsweise Links zu einem relevanten Eintrag in einem Befundkatalog oder zu einer einzelnen Advisory-URL sein.
- **Dateien**: Alle Dateien, die zur Kontextualisierung des Befunds hinzugefügt wurden.
- **Notizen**: Von Benutzern hinterlassene Notizen zum Befund. Wenn eine Notiz als Privat markiert wird, ist sie in keinem generierten Bericht enthalten, der den ausgewählten Befund einschließt.

### Metadaten
- **ID**: Die eindeutige Befund-ID von DefectDojo.
- **Organisation, Asset, Engagement und Test**: Die übergeordneten Objekte des ausgewählten Befunds.
- **Status**: Der Status des Befunds (z. B. Aktiv, Verifiziert, Falsch-positiv, Duplikat, Außerhalb des Geltungsbereichs und In Fehlerprüfung).
- **Schweregrad**: Die Schweregradbewertung dieses Befunds, die automatisch angewendet wird.
    - Wie oben erwähnt, übersetzt DefectDojo automatisch die Schweregrad-Metrik eines Sicherheitstools in einen Schweregrad-Wert für jeden Befund, wodurch dem Befund gemäß der SLA-Konfiguration Ihres Assets eine SLA zugewiesen wird.
- **Risiko**: Ein vierstufiges Einstufungssystem, das die Ausnutzbarkeit eines Befunds berücksichtigt und automatisch angewendet wird.
    - Details dazu, wie Priorität, Risiko und SLAs berechnet werden, finden Sie [hier](/asset_modelling/pro_hierarchy/priority_sla/#main-content). Weitere Details zu den Definitionen von Befundstatus und Risikostufen finden Sie [hier](/triage_findings/findings_workflows/finding_status_definitions/).
- **Priorität**: Ein berechneter numerischer Rang, der auf alle Befunde angewendet wird und es Ihnen ermöglicht, Schwachstellen schnell im Kontext zu verstehen.
- **Alter**: Wie alt der ausgewählte Befund ist.
- **SLA**: Das Fälligkeitsdatum, bis zu dem der Befund behoben werden soll.
- **Typ**: Ob der Befund von einem statischen oder dynamischen Anwendungssicherheitstool erkannt wurde (Statisch, Dynamisch oder Statisch/Dynamisch).
- **Speicherort und Zeile**: Die Datei und Zeilennummer, in der der ausgewählte Befund gefunden wurde.
- **Komponentenname und -version**: Der Name und die Version der Komponente, in der der ausgewählte Befund gefunden wurde.
- **Entdeckungsdatum**: Das Datum, an dem der Befund entdeckt wurde.
- **Geplantes Behebungsdatum und -version**: Das Datum, an dem der Befund voraussichtlich behoben wird, sowie die Version der betroffenen Komponente, in der die Korrektur implementiert wird.
- **Dienst**: Verbundene Dienste (in sich geschlossene Funktionseinheiten innerhalb eines Assets), die vom ausgewählten Befund betroffen sind. Wenn dieses Feld ausgefüllt ist, wird es beim Deduplizierungsabgleich berücksichtigt (d. h. Befunde mit identischen Dienst-Feldern werden dedupliziert).
- **Melder**: Der Benutzer, der den Befund aufgedeckt hat.
- **CWE**: Die CWE-Schwachstellenklassifizierung des Befunds. Ein Befund kann **mehrere CWEs** tragen — eine primäre CWE sowie alle zusätzlichen CWEs, die vom meldenden Tool bereitgestellt wurden. Die primäre CWE wird für die klassische Deduplizierung und die Hash-Code-Berechnung verwendet; der vollständige CWE-Satz kann zusätzlich für den Abgleich über die mengenbasierten Hash-Code-Felder von Pro verwendet werden (siehe [Deduplizierungs-Tuning](/triage_findings/finding_deduplication/pro__deduplication_tuning/#set-based-hash-code-fields-vulnerability-ids-and-cwes)).
    - Eine CWE beschreibt eine Schwachstellen*klasse* (zum Beispiel „SQL Injection"), keine konkrete Schwachstelleninstanz — dafür sind Schwachstellen-IDs da.
- **Schwachstellen-IDs**: Öffentlich anerkannte Schwachstellenkennungen, die mit dem Befund verknüpft sind, wie z. B. CVE, GHSA oder andere standardisierte Advisory-Referenzen. In DefectDojo Pro werden sie außerdem für EPSS- und KEV-Abfragen verwendet.
    - Schwachstellen-IDs werden als eigenständige Datensätze gespeichert, sodass dieselbe CVE nur einmal erfasst und von jedem Befund gemeinsam genutzt wird, der auf sie verweist. Sie können sie — zusammen mit ihren EPSS- und KEV-Werten — im **Schwachstellen-Explorer** einsehen. Siehe [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/#viewing-kevepss-in-the-vulnerability-explorer).
- **Eindeutige ID vom Tool**: Eine stabile Kennung, die vom Quelltool einer bestimmten Befundinstanz zugewiesen wird. Eindeutige IDs sollen bei wiederholten Scans konsistent bleiben, sodass das Tool denselben Befund im Laufe der Zeit wiedererkennen kann.
    - Im Gegensatz zu Schwachstellen-IDs ist dieser Wert proprietär für das meldende Tool und keine öffentliche Schwachstellenreferenz.
        - Beispiel: `finding-12345`
- **Schwachstellen-ID vom Tool**: Eine proprietäre Schwachstellen- oder Regelkennung, die vom Quelltool zugewiesen wird, um die Art der erkannten Schwachstelle zu beschreiben.
    - Im Gegensatz zur eindeutigen ID vom Tool ist diese Kennung nicht für einen einzelnen Befund eindeutig und kann bei vielen Befunden auftreten, die derselben Erkennungsregel entsprechen.
    - Im Gegensatz zu Schwachstellen-IDs sind diese Kennungen spezifisch für das meldende Tool und nicht öffentlich standardisiert.
        - Beispiel: `semgrep.rule.lang.security.sql-injection`
- **EPSS-Score / Perzentil**: EPSS-Score und Perzentil für die CVE.
- **Bekannt ausgenutzt**: Ob bestätigt wurde, dass die Schwachstelle ausgenutzt wurde.
- **Ransomware eingesetzt**: Ob Ransomware bei der Ausnutzung der Schwachstelle beteiligt war.
- **KEV-Datum**: Das Datum, an dem der Befund dem KEV-Katalog hinzugefügt wurde.
- **Gefunden von**: Der Typ des Tools, das die Schwachstelle identifiziert hat.
- **CVSSv3- und CVSSv4-Vektor und -Score**: Der CVSS3- und CVSS4-Vektor und -Score des ausgewählten Befunds.
- **Integrator-Tickets**: Ticketnummern von Drittanbieter-Issue-Trackern, die mit dem Befund verknüpft sind.

### Betroffene Endpunkte
Dieser Abschnitt enthält eine Tabelle der Endpunkte, die vom ausgewählten Befund betroffen sind, zusammen mit allen relevanten Metadaten.

### Zusätzliche Details
- **Anfrage-/Antwort-Paare**: Eine Kopie der vom Client gesendeten Nachricht und der Antwort des Servers auf die Anfrage.
- **Schritte zur Reproduktion**: Schritte zur Reproduktion des Befunds.
- **Schweregrad-Begründung**: Schriftliche Beschreibung, warum dem Befund eine bestimmte Schweregradbewertung zugeordnet wurde.

## Befunddaten
Befunde erfordern die folgenden Metadaten:
- **Name**
- **Datum**
- **Schweregrad**
- **Beschreibung**

Zusätzlich zu den Metadaten, die den Tabellen in der Ansicht eines Befunds entsprechen, umfassen die optionalen Metadatenfelder:
- **Tags**: Alle Tags, die dem Befund hinzugefügt wurden.
- **Verantwortliche**: Die Gruppe von Benutzern, die für den ausgewählten Befund verantwortlich sein wird.
- **Push to Jira**: Überträgt den Befund zu Ticketzwecken an Jira.
- **Push to Integrator**: Überträgt den Befund an alle integrierten Drittanbieter-Issue-Tracker.
- **Risiko- und Prioritätseinstellungen**: Bietet die Möglichkeit, die automatische Berechnung von Risiko und Priorität des Befunds durch DefectDojo zu überschreiben.
- **Hinzuzufügende Endpunkte**: Betroffene Endpunkte, die vom ausgewählten Befund betroffen sein könnten und nicht in der vorstehenden Liste der Systeme/Endpunkte enthalten sind.
- **Fehlerprüfung angefordert von**: Erfasst, wer eine Fehlerprüfung für den betreffenden Mangel angefordert hat.
- **SAST-Quellobjekt, Zeilennummer und Dateipfad**: Quellobjekt, Zeilennummer und Dateipfad des Angriffsvektors.
- **SAST-Sink-Objekt**: Sink-Objekt des Angriffsvektors.
- **Anzahl der Vorkommen**: Anzahl der Vorkommen im Quelltool, wenn mehrere Schwachstellen gefunden und vom Scanner aggregiert wurden.
- **Veröffentlichungsdatum**: Das Datum, an dem die Schwachstelle veröffentlicht wurde.
- **Aufwandsschätzung**: Der Aufwand, der mit der Behebung des Befunds verbunden ist (z. B. Niedrig, Mittel oder Hoch).

Welche Metadaten genau verfügbar sind, hängt vom Parser/Scanner ab, der den Befund aufgedeckt hat. Manche liefern nur grundlegende Informationen wie Titel und Schweregrad, während andere CVSS-Vektoren, betroffene Komponenten, Endpunkte, Anfrage-/Antwort-Paare und weitere scannerspezifische Metadaten enthalten.

Diese Metadaten verbessern die Filterung, Berichterstellung und Priorisierung in Ihrem gesamten Sicherheitsprogramm und ermöglichen eine langfristige Nachverfolgung und Trendanalyse. Weitere Details und Beschreibungen der Metadaten finden Sie [hier](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page).

### Deduplizierung
DefectDojo verfügt über Deduplizierungsfunktionen, die dabei helfen, Befunde zu identifizieren und zu verwalten, die dieselbe zugrunde liegende Schwachstelle darstellen. Beim Import von Scan-Ergebnissen aus einem oder mehreren Tools verwendet DefectDojo eine konfigurierbare Abgleichlogik, um Befunde zu identifizieren, die dieselbe Schwachstelle darstellen.

Die Deduplizierung verhindert, dass dieselbe Schwachstelle mehrfach erscheint, wenn sie wiederholt von demselben oder verschiedenen Scannern entdeckt wird, sodass der Behebungsverlauf einem einzigen Befund zugeordnet bleibt.

Weitere Informationen zur Deduplizierung finden Sie [hier](/triage_findings/finding_deduplication/about_deduplication/).

### Reimport
Die Reimport-Funktion von DefectDojo ermöglicht die Aktualisierung von Befunden beim Import neuer Scan-Ergebnisse. Wird ein Scan reimportiert, vergleicht DefectDojo die eingehenden Ergebnisse mit bestehenden Befunden und aktualisiert übereinstimmende Datensätze, anstatt völlig neue zu erstellen. Dadurch bleiben wertvolle Kontextinformationen wie Statusänderungen, Behebungsverlauf, Kommentare und Zuständigkeitsinformationen erhalten, sodass ein durchgehender Verlauf des Lebenszyklus eines Befunds über mehrere Testzyklen hinweg entsteht.

Weitere Informationen zur Reimport-Funktion finden Sie [hier](/import_data/import_intro/reimport/).

### Risikoakzeptanzen
Risikoakzeptanzen sind ein besonderer Status, der auf Befunde angewendet werden kann, um die Entscheidung, sie anzuerkennen, ohne sie sofort zu beheben, formell zu dokumentieren und umzusetzen.

Weitere Informationen zu Risikoakzeptanzen finden Sie [hier](/triage_findings/findings_workflows/pro__risk_acceptance/).

### Status
Jeder in DefectDojo erstellte Befund verfügt über einen Status, der relevante Informationen vermittelt und Ihrem Team hilft, den Fortschritt bei der Behebung von Problemen zu verfolgen.

Weitere Informationen zu Status finden Sie [hier](/triage_findings/findings_workflows/finding_status_definitions/).

## Arbeiten mit Befunden

### Befunde erstellen
Während die meisten Befunde automatisch durch Scan-Importe und Integrationen erzeugt werden, unterstützt DefectDojo auch die manuelle Erstellung von Befunden. Manuelle Befunde sind nützlich, um Schwachstellen und Sicherheitsbedenken zu erfassen, die durch Penetrationstests, Architekturüberprüfungen, Compliance-Bewertungen, Bug-Bounty-Programme, Beratereinsätze oder andere Aktivitäten identifiziert wurden, die keine Scanner-Ausgabe erzeugen.

Befunde können manuell hinzugefügt werden, indem Sie entweder auf **Neuer Befund** im Bereich **Befunde** der Seitenleiste klicken oder **Befund hinzufügen** im Zahnradmenü des Tests auswählen, dem Sie den Befund hinzufügen möchten.

### Befunde bearbeiten
Das ⋮-Kebab-Menü neben Befunden enthält die folgenden Funktionen:
- **Befund bearbeiten**: Bearbeitet den Befund.
- **Befund kopieren**: Erstellt eine Kopie des Befunds in einem anderen Test. Die Kopie kann in jedem Test innerhalb desselben Engagements gespeichert werden, für den Sie über Bearbeitungsrechte verfügen. Das Kopieren ist nützlich, wenn dieselbe Schwachstelle in mehr als einem Testkontext separat verfolgt werden muss.
- **Befund schließen**: Startet den Prozess zum Schließen des Befunds.
- **Überprüfung anfordern**: Startet den Peer-Review-Prozess und ändert den Status des Befunds in „In Überprüfung". Weitere Informationen zu Peer-Reviews finden Sie [hier](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Risikoakzeptanz hinzufügen**: Startet den Risikoakzeptanzprozess. Weitere Informationen finden Sie [hier](/triage_findings/findings_workflows/pro__risk_acceptance/).
- **Datei hinzufügen**: Startet den Prozess zum Hinzufügen einer Datei zum Befund (siehe Abschnitt unten).
- **Notiz hinzufügen**: Startet den Prozess zum Hinzufügen einer Notiz zum Befund.
- **Benutzerdefiniertes Feld hinzufügen**: Öffnet ein Pop-up, mit dem Sie ein benutzerdefiniertes Feld hinzufügen und definieren können, das auf den Befund angewendet wird.
- **Push to Jira**: Überträgt den Befund zu Ticketzwecken an Jira.
- **Push to Integrator**: Überträgt den Befund an alle integrierten Drittanbieter-Issue-Tracker.
- **Befund löschen**: Löscht den ausgewählten Befund.
- **Befundverlauf**: Zeigt den Verlauf des ausgewählten Befunds an.

#### Dateien an Befunde anhängen
Sie können jedem Befund Dateien anhängen, um zusätzlichen Kontext bereitzustellen — zum Beispiel einen Screenshot einer Schwachstelle in Aktion oder ein Proof-of-Concept-Bild.

Unterstützte Dateitypen sind unter anderem:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Um einem Befund eine Datei anzuhängen, klicken Sie entweder im ⋮-Kebab-Menü oder im Zahnradmenü des ausgewählten Befunds auf **Datei hinzufügen**. Geben Sie einen Titel für die Datei ein, wählen Sie die Datei von Ihrem Computer aus und klicken Sie auf **Absenden**.

Die Datei erscheint anschließend im Abschnitt Dateien der Tabelle **Testübersicht** in der Ansicht des Befunds.

#### Befunde in großen Mengen bearbeiten
Befunde können aus einer Befundliste heraus in großen Mengen bearbeitet werden, z. B. aus der über die Seitenleiste zugänglichen Tabelle Alle Befunde oder aus der Tabelle der Befunde innerhalb eines bestimmten Tests.

Weitere Informationen zur Massenbearbeitung von Befunden finden Sie [hier](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings).

### Befunde schließen
Sobald die Arbeit an einem Befund abgeschlossen ist, können Sie ihn manuell schließen, indem Sie im ⋮-Kebab-Menü oder im Zahnradmenü des Befunds auf **Befund schließen** klicken. Alternativ wird ein zuvor erfasster Befund automatisch geschlossen, wenn ein Scan erneut in DefectDojo importiert wird, der diesen Befund nicht mehr enthält.

Wenn keine Befunde geschlossen werden sollen, können Sie dieses Verhalten im Formular Scan reimportieren deaktivieren:

- Deaktivieren Sie das Kontrollkästchen Alte Befunde schließen, wenn Sie die Benutzeroberfläche verwenden
- Setzen Sie close_old_findings auf False, wenn Sie die API verwenden ​

### Befunde löschen
Das Löschen eines Befunds kann über das ⋮-Kebab-Menü oder das Zahnradmenü des Befunds erfolgen. Diese Aktion kann nicht rückgängig gemacht werden.

Aus Audit-Gründen wird empfohlen, behobene Befunde zu schließen, anstatt sie zu löschen.

## Befundgruppen
**Befundgruppen** ermöglichen es Ihnen, mehrere zusammengehörige Befunde für Triage, Berichterstellung und Koordination der Behebung als eine einzige logische Einheit zu behandeln.

Ein Scan könnte beispielsweise 10 SQL-Injection-Befunde über verschiedene Endpunkte hinweg erzeugen. Anstatt jeden einzeln zu verwalten, können Sie sie zu einer einzigen Befundgruppe zusammenfassen, die das übergreifende SQL-Injection-Problem repräsentiert.

Eine Befundgruppe ersetzt nicht die einzelnen Befunde. Jeder Befund existiert weiterhin mit seinem eigenen Schweregrad, Status, seinen Metadaten, Kommentaren und seinem Behebungsverlauf. Eine Befundgruppe bietet lediglich eine zusätzliche organisatorische Ebene über den darin enthaltenen Befunden.

### Auf Befundgruppen zugreifen
Befundgruppen sind über die Seitenleiste zugänglich. Das Untermenü bietet Zugriff auf Offene und Geschlossene Befundgruppen sowie auf Alle Befundgruppen (unabhängig vom Status Offen).

![image](images/profindings_ss1.png)

### Befundgruppen erstellen
Befundgruppen können entweder manuell oder automatisch erstellt werden.

Zu beachten ist, dass Befundgruppen nur aus den Befunden erstellt werden können, die in einem einzigen Test enthalten sind. Befunde aus unterschiedlichen Tests, Engagements oder Produkten können nicht derselben Befundgruppe hinzugefügt werden.

#### Manuelle Befundgruppen
Um Befundgruppen-Aktionen manuell durchzuführen:
1. Navigieren Sie zu einer Liste von Befunden innerhalb eines Tests.
2. Wählen Sie die Befunde aus, die Sie einer Befundgruppe hinzufügen möchten, indem Sie das entsprechende Kontrollkästchen des Befunds anklicken.
3. Klicken Sie auf die Schaltfläche **Befundgruppe**, die oben in der Befundliste erscheint.
4. Klicken Sie auf die entsprechende Aktion, die Sie durchführen möchten.
    - **Add to New Finding Group**: Erstellt eine neue Befundgruppe, die die ausgewählten Befunde enthält.
    - **Add to Existing Finding Group**: Fügt die ausgewählten Befunde einer bereits vorhandenen Befundgruppe hinzu.
    - **Remove from Finding Group**: Entfernt die ausgewählten Befunde aus allen Befundgruppen, denen sie zuvor angehörten.
5. Klicken Sie auf **Absenden**.

Beachten Sie, dass die Gruppierung deaktiviert ist, sofern nicht jeder ausgewählte Befund bearbeitbar, ungruppiert und im selben Test ist.

Beachten Sie außerdem, dass bei der Auswahl von Befunden aus der Liste Alle Befunde nur die Aktion möglich ist, die ausgewählten Befunde aus einer Befundgruppe zu entfernen. Das liegt daran, dass Befundgruppen, wie bereits erwähnt, nur aus den Befunden erstellt werden können, die in einem einzigen Test enthalten sind.

#### Automatische Befundgruppen
Beim Import eines Scans kann die Funktion **Group By** im ausklappbaren Menü **Optional Fields** automatisch Befundgruppen basierend auf einer gewählten Gruppierungsmethode erstellen. Dies ist nützlich, wenn ein Scanner viele zusammengehörige Befunde erzeugt, die gemeinsam verwaltet werden sollten.

Das dazugehörige Kontrollkästchen **Create Finding Groups for all Findings** erfüllt zwei Funktionen:
- **Aktiviert**: Erstellt für jeden importierten Befund eine Befundgruppe, auch wenn dieser Befund das einzige Mitglied der Gruppe ist.
- **Deaktiviert**: Erstellt Befundgruppen nur, wenn tatsächlich mehrere Befunde zusammen gruppiert werden können.

![image](images/profindings_ss2.png)

Wenn beim Import keine Option aus dem Dropdown-Menü Group By ausgewählt wird (z. B. **Finding Title** im obigen Screenshot usw.), erfolgt keine Gruppierung.

Wenn das Gruppierungskriterium (z. B. Komponentenname, Schwachstellen-ID, Befundtitel usw.) im Befund nicht ausgefüllt ist, wird für ihn keine Gruppe erstellt und er wird auch keiner bestehenden Befundgruppe hinzugefügt.

Wenn ein Scan importiert wird, der 10 nicht gruppierte Befunde aufdeckt, und derselbe Scan anschließend reimportiert wird, wobei die Befunde diesmal gruppiert werden, werden die ersten 10 Befunde nicht dieser Befundgruppe hinzugefügt (d. h., die Befundgruppe enthält nur die 10 Befunde aus dem Reimport, nicht die 10 Befunde aus dem ursprünglichen Import).

## Befundvorlagen
**Befundvorlagen** ermöglichen es Benutzern, wiederverwendbare Vorlagen für häufig gemeldete Schwachstellen und Sicherheitsprobleme zu erstellen. Eine Vorlage kann standardisierte Informationen wie Titel, Beschreibung, Auswirkung, Schritte zur Reproduktion, Behebung, Referenzen und weitere Befund-Metadaten enthalten.

Befundvorlagen sind besonders nützlich in Situationen, in denen Benutzer wiederholt manuelle Befunde erstellen müssen und die erneute Eingabe derselben unterstützenden Informationen jedes Mal vermeiden möchten.

### Auf Befundvorlagen zugreifen
Befundvorlagen finden Sie im Untermenü Befunde in der Seitenleiste.

![image](images/profindings_ss1.png)

### Befundvorlagen erstellen
Befundvorlagen können erstellt werden, indem Sie oben links in der Ansicht Befundvorlagen auf die Schaltfläche **Neue Befundvorlage** klicken.

Die daraufhin angezeigte Seite bietet einen Überblick über die Metadaten, die auf einen Befund angewendet werden, wenn eine Befundvorlage verwendet wird.

### Befundvorlagen anwenden
Befundvorlagen unterscheiden sich zwischen OS DefectDojo und DefectDojo Pro. In Pro können Befundvorlagen nicht auf bereits vorhandene Befunde angewendet werden, und sie können auch nicht auf Grundlage bereits vorhandener Befunde erstellt werden.

Sie können jedoch manuell einen Befund basierend auf einer Befundvorlage zu einem Test hinzufügen, entweder über das ⋮-Kebab-Menü neben dem Test in der Ansicht des übergeordneten Engagements oder über das Zahnradmenü in der Ansicht des Tests.

![image](images/profindings_ss3.png)

![image](images/profindings_ss4.png)

## Berichterstellung
Mit dem Report-Builder von DefectDojo können Sie aus einer Reihe von Inhalts-Widgets einen benutzerdefinierten Bericht zusammenstellen, ihn ausführen und das Ergebnis exportieren (zum Beispiel durch Drucken als PDF). Benutzerdefinierte Berichte können die Befunde oder Endpunkte zusammenfassen, die Sie mit einem externen Publikum teilen möchten, und können Branding sowie Standardtexte enthalten.

Weitere Informationen zum Report-Builder von DefectDojo finden Sie [hier](/metrics_reports/reports/report-builder/).

### Befunde exportieren
Seiten, die eine Liste von Befunden oder eine Liste von Engagements anzeigen, verfügen oben links über eine CSV- und Excel-Exportoption. Bei Befunden gibt es außerdem die Möglichkeit eines Schnellexports, der einen neuen Tab mit Tabellen der Metadaten zu jedem Befund öffnet.
