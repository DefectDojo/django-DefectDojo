---
title: Befunde
description: Befunde in DefectDojo OS verstehen
audience: opensource
weight: 5
---

Organisationen	→ Assets → Engagements → Tests → **BEFUNDE**

## Überblick

**Befunde** repräsentieren die unterste Ebene der Produkthierarchie, auf der einzelne Schwachstellen erfasst und verwaltet werden, und sind die wichtigste Methode, mit der DefectDojo den Melde- und Behebungsprozess Ihrer Sicherheitstools standardisiert und steuert. Unabhängig davon, ob eine Schwachstelle in SonarQube, Acunetix oder dem individuellen Tool Ihres Teams gemeldet wurde, ermöglichen Ihnen Befunde, jede Schwachstelle auf die gleiche Weise zu verwalten.

Beispiele für Befunde sind:
- Cookie nicht als HttpOnly markiert
- Veraltete Version (PHP)
- Out-of-Band-Codeauswertung (PHP)
- Veraltete Version (MySQL)
- Backup-Quellcode entdeckt
- Blindes Cross-Site-Scripting

Zusätzlich zur Speicherung der Schwachstellendaten und zur Bereitstellung eines Behebungsrahmens verbessert DefectDojo Ihre Befunde auf folgende Weise:
- Automatisches Hinzufügen zugehöriger EPSS-Werte zu einem Befund, um dessen Ausnutzbarkeit zu beschreiben
- Automatische Übersetzung der Schweregradmetrik eines Sicherheitstools in einen Schweregrad-Wert für jeden Befund, der dem Befund gemäß der SLA-Konfiguration Ihres Assets eine SLA zuweist. Weitere Informationen zur SLA-Konfiguration finden Sie [hier](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content).

Insgesamt sind Befunde darauf ausgelegt, mit der Produkthierarchie zusammenzuarbeiten, um Ihre Bemühungen zu standardisieren und eine einheitliche Methode auf jedes Asset anzuwenden.

## Zugriff auf Befunde

Befunde sind über die Seitenleiste zugänglich. Das Untermenü bietet Zugriff auf Offene und Geschlossene Befunde, Alle Befunde (unabhängig vom Status Offen oder Geschlossen), [Risikoakzeptierte Befunde](/triage_findings/findings_workflows/os__risk_acceptance/), sowie Befundvorlagen. Einzelne Befunde sind auch innerhalb des Tests zugänglich, der sie enthält.

![image](images/osfindings_ss1.png)

### Berechtigungen

Jeder Befund gehört zu einem Test, wodurch DefectDojo nachverfolgen kann, welcher Scan oder welche Bewertung die Schwachstelle ursprünglich identifiziert hat.

Da Befunde zu Tests gehören, wird der Zugriff auf Befunde durch den Zugriff eines Benutzers auf das Asset bestimmt, das den Test enthält. Tests verfügen über keine eigenständigen Zugriffskontrolllisten.

## Befundansicht
Befundansichten enthalten eine Vielzahl von Tabellen, die dabei helfen, den Status eines Befunds auf einen Blick zu erfassen. Dazu gehören:
- **Überblick**
    - **ID**: Die eindeutige ID-Nummer dieses Befunds.
    - **Schweregrad**: Die Schweregrad-Bewertung dieses Befunds, die automatisch vergeben wird.
        - Wie oben erwähnt, übersetzt DefectDojo automatisch die Schweregradmetrik eines Sicherheitstools in einen Schweregrad-Wert für jeden Befund, der dem Befund gemäß der SLA-Konfiguration Ihres Assets eine SLA zuweist.
    - **SLA**: Das vorgesehene Fälligkeitsdatum, bis zu dem der Befund behoben sein soll.
    - **Status**: Der Status des Befunds (z. B. Aktiv, Verifiziert, Falsch-positiv, Duplikat, Außerhalb des Geltungsbereichs und Unter Fehlerprüfung).
    - **Befundtyp**: Ob der Befund Statisch (SAST) oder Dynamisch (DAST) ist.
    - **Entdeckungsdatum**: Das Datum, an dem der Befund entdeckt wurde.
    - **CWE**: Die CWE-Klassifizierung des Befunds.
    - **Schwachstellen-ID**: IDs von Schwachstellen in Sicherheitshinweisen, die dem Befund zugeordnet sind (z. B. CVE oder andere Quellen).
    - **Gefunden von**: Das Tool, das den Befund aufgedeckt hat.
- **Ähnliche Befunde**: Andere Befunde innerhalb desselben Assets, die keine exakten Duplikate sind, aber ähnliche Werte für Schwachstellen-ID, CWE, file_path, Zeilennummer usw. aufweisen.
- **Import-Verlauf**: Liste der Importe/Re-Importe, die diesen Befund in einem beliebigen Test erstellt/geschlossen/reaktiviert haben.
- **Verwundbare Endpunkte/Systeme**: Endpunkte/Systeme, die laut Befund verwundbar sind.
- **Beschreibung**: Die Beschreibung des Befunds (je nach Befundtyp automatisch hinzugefügt oder manuell erstellt).
- **Behebung**: Vorgeschlagene Schritte zur Behebung.
- **Auswirkung**: Mögliche Auswirkung, wenn der Befund unbehoben bleibt.
- **Schritte zur Reproduktion**: Schritte zur Reproduktion des Befunds.
- **Schweregrad-Begründung**: Schriftliche Beschreibung, warum dem Befund ein bestimmter Schweregrad zugeordnet wurde.
- **Referenzen**: URL zur Querverweisung auf die spezifische Beschreibung des Befunds durch das Drittanbieter-Scan-Tool. Referenzen können beispielsweise Links zu einem relevanten Eintrag in einem Befundkatalog oder eine einzelne Advisory-URL sein.
- **Notizen**: Von Benutzern zum Befund hinterlassene Notizen. Wird eine Notiz als Privat markiert, wird sie nicht in generierte Berichte aufgenommen, die den ausgewählten Befund enthalten.

## Befund-Daten

Für Befunde sind folgende Metadaten erforderlich:
**Titel**
**Datum**
**Schweregrad**
**Beschreibung**

Zusätzlich zu den Metadaten, die den Tabellen in der Ansicht eines Befunds entsprechen, gehören zu den optionalen Metadatenfeldern:
- **Gruppe**: Befundgruppen, die den ausgewählten Befund enthalten.
- **CVSS3/CVSS4-Vektor und -Wert**: Der CVSS3- und CVSS4-Vektor und -Wert des ausgewählten Befunds.
- **Request- und Response-Paare**: Eine Kopie der vom Client gesendeten Nachricht und der Antwort des Servers auf die Anfrage.
- **Hinzuzufügende Endpunkte**: Verwundbare Endpunkte, die vom ausgewählten Befund betroffen sein könnten und die nicht in der vorstehenden Liste der Systeme/Endpunkte erfasst sind.
- **EPSS-Wert und -Perzentil**: EPSS-Wert und -Perzentil für die CVE.
- **KEV-Hinzufügedatum**: Das Datum, an dem der Befund dem KEV-Katalog hinzugefügt wurde.
- **Verfügbarkeit und Version der Fehlerbehebung**: Legt fest, ob für die Schwachstelle eine Fehlerbehebung verfügbar ist, und die Version der betroffenen Komponente, in der die Behebung implementiert wurde.
- **Benutzer, der eine Fehlerprüfung angefordert hat**: Erfasst, wer eine Fehlerprüfung für den betreffenden Mangel angefordert hat.
- **Zeilennummer**: Quellzeilennummer des Angriffsvektors.
- **Dateipfad**: Identifizierte Dateien, die den Mangel enthalten.
- **Komponentenname und -version**: Name und Version der betroffenen Komponente.
- **Eindeutige ID vom Tool**: Technische Schwachstellen-ID aus dem Quelltool.
- **Schwachstellen-ID vom Tool**: Nicht eindeutige technische ID aus dem Quelltool.
- **SAST-Quellobjekt, Zeilennummer und Dateipfad**: Quellobjekt, Zeilennummer und Dateipfad des Angriffsvektors.
- **SAST-Zielobjekt (Sink)**: Zielobjekt (Sink) des Angriffsvektors.
- **Anzahl der Vorkommen**: Anzahl der Vorkommen im Quelltool, wenn mehrere Schwachstellen gefunden und vom Scanner aggregiert wurden.
- **Veröffentlichungsdatum**: Datum, an dem der Befund veröffentlicht wurde.
- **Service**: Verbundene Services (in sich geschlossene Funktionseinheiten innerhalb eines Assets), die vom ausgewählten Befund betroffen sind. Wenn dieses Feld ausgefüllt ist, wird es in den Deduplizierungsabgleich einbezogen (d. h. Befunde mit identischen Service-Feldern werden dedupliziert).
- **Geplantes Behebungsdatum und -version**: Das Datum, an dem der Befund voraussichtlich behoben wird, und die Version der betroffenen Komponente, in der die Behebung implementiert wird.
- **Aufwand für die Behebung**: Der Aufwand, der mit der Behebung des Befunds verbunden ist (z. B. Niedrig, Mittel oder Hoch).
- **Tags**: Alle Tags, die dem Befund hinzugefügt wurden.

Die genauen verfügbaren Metadaten hängen vom Parser/Scanner ab, der den Befund aufgedeckt hat. Manche liefern nur grundlegende Informationen wie Titel und Schweregrad, während andere CVSS-Vektoren, verwundbare Komponenten, Endpunkte, Request/Response-Paare und andere scannerspezifische Metadaten enthalten.

Diese Metadaten verbessern die Filterung, Berichterstattung und Priorisierung in Ihrem gesamten Sicherheitsprogramm und ermöglichen eine langfristige Nachverfolgung und Trendanalyse. Zusätzliche Details und Beschreibungen der Metadaten finden Sie [hier](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page).

### Deduplizierung

DefectDojo bietet Deduplizierungsfunktionen, die dabei helfen, Befunde zu identifizieren und zu verwalten, die dieselbe zugrunde liegende Schwachstelle darstellen. Wenn Scan-Ergebnisse aus einem oder mehreren Tools importiert werden, verwendet DefectDojo konfigurierbare Abgleichlogik, um Befunde zu identifizieren, die dieselbe Schwachstelle repräsentieren.

Die Deduplizierung verhindert, dass dieselbe Schwachstelle mehrfach erscheint, wenn sie wiederholt vom gleichen oder von unterschiedlichen Scannern entdeckt wird, und sorgt dafür, dass der Behebungsverlauf an einem einzigen Befund erhalten bleibt.

Weitere Informationen zur Deduplizierung finden Sie [hier](/triage_findings/finding_deduplication/about_deduplication/).

### Reimport

Die Reimport-Funktion von DefectDojo ermöglicht die Aktualisierung von Befunden, wenn neue Scan-Ergebnisse importiert werden. Beim Reimport eines Scans vergleicht DefectDojo die eingehenden Ergebnisse mit bestehenden Befunden und aktualisiert übereinstimmende Datensätze, anstatt völlig neue zu erstellen. Dadurch bleiben wertvolle Kontextinformationen wie Statusänderungen, Behebungsverlauf, Kommentare und Zuständigkeitsinformationen erhalten, sodass ein durchgehender Nachweis über den Lebenszyklus eines Befunds über mehrere Testzyklen hinweg entsteht.

Weitere Informationen zur Reimport-Funktion finden Sie [hier](/import_data/import_intro/reimport/#main-content).

### Risikoakzeptanzen

Risikoakzeptanzen sind ein besonderer Status, der Befunden zugewiesen werden kann, um die Entscheidung, sie ohne sofortige Behebung zu akzeptieren, formal zu dokumentieren und umzusetzen.

Weitere Informationen zu Risikoakzeptanzen finden Sie [hier](/triage_findings/findings_workflows/os__risk_acceptance/).

### Status

Jeder in DefectDojo erstellte Befund hat einen Status, der relevante Informationen vermittelt und Ihrem Team hilft, den Fortschritt bei der Behebung von Problemen im Blick zu behalten.

Weitere Informationen zu Status finden Sie [hier](/triage_findings/findings_workflows/finding_status_definitions/).

## Arbeiten mit Befunden

### Befunde erstellen

Während die meisten Befunde automatisch durch Scan-Importe und Integrationen erzeugt werden, unterstützt DefectDojo auch die manuelle Erstellung von Befunden. Manuelle Befunde eignen sich zur Nachverfolgung von Schwachstellen und Sicherheitsbedenken, die durch Penetrationstests, Architektur-Reviews, Compliance-Bewertungen, Bug-Bounty-Programme, Beratereinsätze oder andere Aktivitäten identifiziert wurden, die keine Scanner-Ausgabe erzeugen.

So erstellen Sie einen Befund manuell:
1. Navigieren Sie zu dem Test, in dem Sie den Befund manuell hinzufügen möchten, klicken Sie auf das Pluszeichen +, und klicken Sie dann auf **Neuer Befund**.

![image](images/osfindings_ss2.png)

2. Dadurch öffnet sich das Formular „Neuer Befund“, das Sie mit allen relevanten Informationen zu Ihrem Befund ausfüllen können.

3. Wählen Sie entweder **Weiteren Befund hinzufügen**, um manuell einen weiteren Befund hinzuzufügen, oder **Fertig**, um den Prozess der manuellen Befunderstellung abzuschließen.

Der Befund erscheint nun in der Liste der Befunde, die im ursprünglichen Test enthalten sind.

Wichtig: Wenn ein Befund manuell über die obere Leiste hinzugefügt wird, werden dadurch automatisch ein Ad-hoc-Engagement und ein Ad-hoc-Test erstellt, um den neuen Befund zu enthalten, anstatt ihn dem gerade angezeigten Test hinzuzufügen (siehe Abbildung unten). Dies liegt daran, dass sich die obere Leiste auf das Asset als Ganzes bezieht. Wenn Sie einem bestimmten, bereits vorhandenen Test manuell einen Befund hinzufügen möchten, sollten Sie dies am besten innerhalb des Tests selbst tun, wie in den obigen Schritten 1–3 beschrieben.

![image](images/osfindings_ss3.png)

### Befunde bearbeiten

#### ⋮ Kebab-Menü

Das ⋮-Kebab-Menü neben Befunden enthält folgende Funktionen:
- **Ansehen**: Den Befund öffnen und ansehen.
- **Bearbeiten**: Den Befund bearbeiten.
- **Kopieren**: Eine Kopie des Befunds erstellen. Die Kopie kann in einem beliebigen Test innerhalb des zugehörigen Engagements gespeichert werden.
- **Peer-Review anfordern**: Startet den Peer-Review-Prozess und ändert den Status des Befunds in „Unter Überprüfung“. Weitere Informationen zu Peer-Reviews finden Sie [hier](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Befund berühren (Touch)**: Protokolliert eine Interaktion mit dem Befund im Verlauf des Befunds.
- **Befund zu Vorlage machen**: Erstellt automatisch eine Befundvorlage auf Basis des ausgewählten Befunds.
- **Vorlage auf Befund anwenden**: Ermöglicht das Anwenden einer bereits vorhandenen Befundvorlage auf einen Befund.
- **Befund schließen**: Startet den Prozess zum Schließen des Befunds.
- **Risikoakzeptanz hinzufügen**: Startet den Prozess der Risikoakzeptanz. Weitere Informationen finden Sie [hier](/triage_findings/findings_workflows/os__risk_acceptance/#main-content).
- **Verlauf anzeigen**: Zeigt den Verlauf des ausgewählten Befunds an.
- **Löschen**: Löscht den ausgewählten Befund.

#### Dateien an Befunde anhängen
Sie können jedem Befund Dateien anhängen, um visuellen Kontext bereitzustellen — zum Beispiel einen Screenshot einer Schwachstelle in Aktion oder ein Proof-of-Concept-Bild.

Unterstützte Dateitypen sind:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

So hängen Sie eine Datei an einen Befund an:
1. Öffnen Sie den Befund, an den Sie eine Datei anhängen möchten.
2. Öffnen Sie das Aktionsmenü (die Schaltfläche ☰ oben rechts im Befund) und klicken Sie auf Dateien verwalten.

![image](images/OS_manage_files_menu.png)

3. Geben Sie auf der Seite „Dateien hinzufügen“ einen Titel für die Datei ein und wählen Sie die Datei von Ihrem Computer aus. Sie können bis zu drei Dateien gleichzeitig hinzufügen; speichern Sie und kehren Sie bei Bedarf zurück, um weitere hinzuzufügen.

![image](images/OS_manage_files_form.png)

4. Klicken Sie auf **Speichern**.

Die Datei wird anschließend im Bereich **Dateien** des Befunds aufgelistet. Bilddateien werden als Miniaturansichten angezeigt:

![image](images/OS_finding_files_panel.png)

#### Befunde in großen Mengen bearbeiten

Befunde können in großen Mengen aus einer Befundliste bearbeitet werden, z. B. aus der Tabelle Alle Befunde, die über die Seitenleiste zugänglich ist, oder aus der Tabelle der Befunde innerhalb eines bestimmten Tests.

Weitere Informationen zur Massenbearbeitung von Befunden finden Sie [hier](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings).

### Befunde schließen

Sobald die Arbeit an einem Befund abgeschlossen ist, können Sie ihn manuell schließen, indem Sie im ⋮-Kebab-Menü oder ☰-Aktionsmenü des Befunds auf **Befund schließen** klicken. Wird alternativ ein Scan erneut in DefectDojo importiert, der einen zuvor erfassten Befund nicht mehr enthält, wird dieser zuvor erfasste Befund automatisch geschlossen.

Wenn Sie nicht möchten, dass Befunde geschlossen werden, können Sie dieses Verhalten beim Reimport deaktivieren:

- Deaktivieren Sie das Kontrollkästchen Close Old Findings, wenn Sie die UI verwenden
- Setzen Sie close_old_findings auf False, wenn Sie die API verwenden ​

### Befunde löschen

Das Löschen eines Befunds kann über das ⋮-Kebab-Menü oder ☰-Aktionsmenü des Befunds erfolgen. Diese Aktion kann nicht rückgängig gemacht werden.

Aus Gründen der Nachvollziehbarkeit wird empfohlen, behobene Befunde zu schließen, anstatt sie zu löschen.

## Befundgruppen

**Befundgruppen** ermöglichen es Ihnen, mehrere zusammengehörige Befunde als eine einzige logische Einheit für Triage, Berichterstattung und Koordination der Behebung zu behandeln.

Ein Scan könnte beispielsweise 10 SQL-Injection-Befunde über verschiedene Endpunkte hinweg erzeugen. Anstatt jeden einzeln zu verwalten, können Sie diese in einer einzigen Befundgruppe zusammenfassen, die das übergeordnete SQL-Injection-Problem repräsentiert.

Eine Befundgruppe ersetzt nicht die einzelnen Befunde. Jeder Befund existiert weiterhin mit seinem eigenen Schweregrad, Status, Metadaten, Kommentaren und Behebungsverlauf. Eine Befundgruppe bietet lediglich eine zusätzliche organisatorische Ebene über den enthaltenen Befunden.

### Zugriff auf Befundgruppen

Befundgruppen sind über die Seitenleiste zugänglich. Das Untermenü bietet Zugriff auf Offene und Geschlossene Befundgruppen sowie Alle Befundgruppen (unabhängig vom Status Offen).

![image](images/osfindings_ss1.png)

### Befundgruppen erstellen


Befundgruppen können entweder manuell oder automatisch erstellt werden.

Wichtig: Befundgruppen können nur aus den Befunden erstellt werden, die in einem einzigen Test enthalten sind. Befunde aus unterschiedlichen Tests, Engagements oder Produkten können nicht derselben Befundgruppe hinzugefügt werden.

#### Manuelle Befundgruppen

So führen Sie Aktionen für Befundgruppen manuell durch:
1. Navigieren Sie zu einer Liste von Befunden innerhalb eines Tests.
2. Wählen Sie den/die Befund(e) aus, den/die Sie einer Befundgruppe hinzufügen möchten, indem Sie das entsprechende Kontrollkästchen anklicken.
3. Klicken Sie auf das Kontrollkästchen **Gruppe**.
4. Klicken Sie auf die entsprechende Aktion, die Sie ausführen möchten.
    - **Erstellen**: Erstellt eine Befundgruppe, die die ausgewählten Befunde enthält.
    - **Hinzufügen zu**: Fügt die ausgewählten Befunde einer bereits vorhandenen Befundgruppe hinzu.
    - **Aus jeder Gruppe entfernen**: Entfernt die ausgewählten Befunde aus allen Befundgruppen, denen sie zuvor angehörten.
    - **Gruppieren nach**: Gruppiert die ausgewählten Befunde basierend auf der gewählten Option (z. B. Komponentenname, Dateipfad, Befundtitel usw.)
5. Klicken Sie auf **Absenden**.

![image](images/osfindings_ss4.png)

Beachten Sie, dass beim Auswählen von Befunden aus der Liste Alle Befunde die einzig mögliche Aktion darin besteht, die ausgewählten Befunde aus einer beliebigen Befundgruppe zu entfernen. Dies liegt daran, dass Befundgruppen, wie bereits erwähnt, nur aus den Befunden erstellt werden können, die in einem einzigen Test enthalten sind.

#### Automatische Befundgruppen

Beim Importieren eines Scans kann die Funktion „Gruppieren nach“ automatisch Befundgruppen basierend auf einer gewählten Gruppierungsmethode erstellen. Dies ist nützlich, wenn ein Scanner viele zusammengehörige Befunde erzeugt, die gemeinsam verwaltet werden sollen.

Das dazugehörige Kontrollkästchen **Befundgruppen für alle Befunde erstellen** erfüllt zwei Funktionen:
- **Aktiviert**: Erstellt für jeden importierten Befund eine Befundgruppe, selbst wenn dieser Befund das einzige Mitglied der Gruppe ist.
- **Deaktiviert**: Erstellt Befundgruppen nur, wenn tatsächlich mehrere Befunde zum Gruppieren vorhanden sind.

![image](images/osfindings_ss5.png)

Wenn im Dropdown-Menü „Gruppieren nach“ während des Imports keine Option ausgewählt wird, erfolgt keine Gruppierung.

Wenn die Gruppierungskriterien (z. B. Komponentenname, Schwachstellen-ID usw.) im Befund nicht ausgefüllt sind, wird für ihn keine Gruppe erstellt und er wird auch keiner bereits vorhandenen Befundgruppe hinzugefügt.

Wenn ein Scan importiert wird, der 10 nicht gruppierte Befunde ergibt, und derselbe Scan erneut importiert wird, wobei die Befunde diesmal gruppiert werden, werden die ursprünglichen 10 Befunde nicht zu dieser Befundgruppe hinzugefügt (d. h. die Befundgruppe enthält nur die 10 Befunde aus dem Reimport, nicht die 10 Befunde aus dem ursprünglichen und den nachfolgenden Import).

## Befundvorlagen

**Befundvorlagen** ermöglichen es Benutzern, wiederverwendbare Vorlagen für häufig gemeldete Schwachstellen und Sicherheitsprobleme zu erstellen. Eine Vorlage kann standardisierte Informationen wie Titel, Beschreibung, Auswirkung, Schritte zur Reproduktion, Behebung, Referenzen und andere Befundmetadaten enthalten.

Befundvorlagen sind besonders nützlich in Situationen, in denen Benutzer wiederholt manuelle Befunde erstellen müssen und vermeiden möchten, jedes Mal dieselben unterstützenden Informationen erneut einzugeben.

### Zugriff auf Befundvorlagen

Befundvorlagen finden Sie im Untermenü Befunde in der Seitenleiste.

![image](images/osfindings_ss6.png)

### Befundvorlagen erstellen

Befundvorlagen können erstellt werden, indem Sie auf die Schaltfläche + oben rechts in der Ansicht Befundvorlagen klicken.

Die daraufhin angezeigte Seite bietet einen Überblick über die Metadaten, die auf einen Befund angewendet werden, wenn eine Befundvorlage verwendet wird.

Sie können auch einen bereits vorhandenen Befund als Grundlage für eine neue Befundvorlage verwenden, indem Sie im ⋮-Kebab-Menü des Befunds auf **Befund zu Vorlage machen** klicken.

### Befundvorlagen anwenden

Befundvorlagen können auf Befunde angewendet werden, indem Sie im ⋮-Kebab-Menü des ausgewählten Befunds auf die Schaltfläche **Vorlage auf Befund anwenden** klicken.

![image](images/osfindings_ss7.png)

Auf der daraufhin angezeigten Seite können Sie die Vorlage auswählen, die auf den betreffenden Befund angewendet werden soll, und anschließend festlegen, ob die Metadaten des Befunds beibehalten, durch die der Vorlage ersetzt oder mit ihr kombiniert werden sollen.

### Berichte

Der Berichts-Generator von DefectDojo ermöglicht es Ihnen, aus einer Reihe von Inhalts-Widgets einen individuellen Bericht zusammenzustellen, ihn auszuführen und das Ergebnis zu exportieren (zum Beispiel durch Drucken als PDF). Individuelle Berichte können die Befunde oder Endpunkte zusammenfassen, die Sie mit einem externen Publikum teilen möchten, und können Branding sowie Standardtexte enthalten.

Weitere Informationen zum Berichts-Generator von DefectDojo finden Sie [hier](/metrics_reports/reports/using-the-report-builder/).

#### Befunde exportieren

Seiten, die eine Liste von Befunden oder eine Liste von Engagements anzeigen, verfügen im Dropdown-Menü oben rechts über eine CSV- und Excel-Exportoption.

Öffnen Sie auf einer beliebigen Befundlisten-Seite das Dropdown-Menü oben rechts, um die sichtbaren Befunde als CSV- oder Excel-Datei zu exportieren. Die Liste der Engagements kann über dasselbe Dropdown-Menü auf der Engagements-Listenseite ebenfalls als CSV oder Excel exportiert werden.
