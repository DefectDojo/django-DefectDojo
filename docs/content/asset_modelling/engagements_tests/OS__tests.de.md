---
title: Tests
description: Tests in DefectDojo OS verstehen
audience: opensource
weight: 4
---

Organisationen → Assets → Engagements → **TESTS** → Befunde

## Überblick

Ein Test ist ein Container für eine oder mehrere Scan-Ausführungen, mit denen Schwachstellen in einem Produkt aufgedeckt werden. Tests sind die letzte, feingranularste Komponente der Produkthierarchie von DefectDojo und dienen als Container für die Befunde, die aus der Ausführung eines Sicherheitstools oder einer manuellen Bewertung resultieren. Gleichzeitig liefern sie den Kontext, in dem solche Befunde gefunden wurden (z. B. welches Tool sie gemeldet hat, wann dieses Tool zuletzt ausgeführt wurde usw.).

Beispiele für Tests sind:
- Static Application Security Testing
- Dynamic Application Security Testing
- Software Composition Analysis
- Container-Sicherheitsscans
- Infrastruktur-/Netzwerkscans
- Manuelle Penetrationstests
- CI/CD-Pipeline-Scans

### Testarten

Es gibt zwei primäre Möglichkeiten, Tests in DefectDojo zu erstellen:
1. **Herstellerspezifische Parser** (z. B. Burp, OWASP ZAP, Acunetix, Invicti)
2. **Generic Findings Import**

Je nach Konfiguration und Deduplizierungsstrategie kann jede Methode neue Tests erstellen oder Befunde in bestehende Tests reimportieren.

Auch wenn sich die Methoden vor allem darin unterscheiden, wie Scan-Daten geparst und aufgenommen werden, führen sie letztlich alle dazu, dass Befunde einem Test zugeordnet werden.

#### Parser

**Parser** sind Komponenten, die bestimmte Scan-Ausgabeformate (z. B. XML, JSON, CSV) verarbeiten und sie auf das interne Befund-Modell von DefectDojo abbilden. Beim Import von Scan-Ergebnissen verwendet DefectDojo den ausgewählten Parser, um Befunde zu extrahieren und sie einem neu erstellten oder bestehenden Test zuzuordnen.

#### Generic Findings Import

Wenn für ein bestimmtes Tool kein nativer Parser existiert, ermöglicht **Generic Findings Import** den Import von Befunden über ein standardisiertes JSON- oder CSV-Schema, unabhängig von der ursprünglichen Quelle.

DefectDojo parst die bereitgestellten Daten, erstellt einen neuen Test (oder importiert in einen bestehenden) und ordnet die Befunde zu. Basierend auf dem optionalen Feld `type` des Reports wird außerdem ein entsprechender Test-Typ erstellt: Wird `type` weggelassen (oder entspricht es dem Scan-Typ), lautet der Test-Typ „Generic Findings Import“; wird `type` angegeben, wird daraus „{type} Scan (Generic Findings Import)“ (ein `type`, der bereits auf das Suffix „(Generic Findings Import)“ endet, wird unverändert übernommen).

|  | **Native Parser** | **Generic Findings Import** |
|----------|---------------|------------------------|
| **Primärer Zweck** | Verarbeitung der Ausgaben unterstützter Tools | Import nicht unterstützter/benutzerdefinierter Daten über ein festes Schema |
| **Eingabeformat** | Tool-spezifisch (z. B. ZAP XML, SARIF) | Striktes JSON-/CSV-Schema |
| **Wer übernimmt die Normalisierung** | DefectDojo (integrierter Parser) | Benutzer (muss dem Schema entsprechen) |
| **Auslöser für Testerstellung** | Manueller Upload oder API-Import | Manueller Upload oder API-Import |
| **Test-Typ** | Vordefiniert (z. B. „ZAP Scan“) | Automatisch erstellter „Generic“-Typ |
| **Einrichtungsaufwand** | Gering | Moderat (Datentransformation erforderlich) |
| **Flexibilität** | Gering (nur unterstützte Tools) | Mittel |
| **Automatisierungsgrad** | Gering–Moderat | Gering–Moderat |
| **Typischer Anwendungsfall** | Standard-Scanner (SAST, DAST, SCA) | Benutzerdefinierte Skripte, nicht unterstützte Tools |

Unabhängig von der Importmethode werden alle Scan-Daten in DefectDojo letztlich als Befunde dargestellt, die einem Test zugeordnet sind, der als Einheit für Ausführung und Lebenszyklus-Tracking dient.

### Testdaten

Tests speichern eine Vielzahl von Metadaten, die dabei helfen, verschiedene Komponenten jeder Testaktivität zu dokumentieren, wie zum Beispiel:
- Testtitel / -name
- Testtyp
- Testbeschreibung / -notizen
- Start- und Enddatum
- Die Umgebung, in der der Test ausgeführt wurde (z. B. Development, Staging, Pre-Production, Production usw.)
- Version / Branch / Build-ID / Commit-Hash
- API-Scan-Konfiguration
- Zusätzliche Dateien, die für spätere Audits oder Reimporte verwendet werden können
- Das übergeordnete Engagement, Asset und die Organisation
- Import- und Reimport-Historie

Jeder Test führt eine Import-Historie, in der alle mit dem Test verbundenen Scan-Importe und -Reimporte erfasst werden. Dazu gehören Metadaten wie Scan-Datum, Version, Branch, Commit-Hash und Build-ID.

Diese Historie sorgt für Nachvollziehbarkeit über mehrere Scan-Ausführungen innerhalb desselben Tests hinweg.

### Berechtigungen

Mehrere Tests können in einem einzelnen Engagement gespeichert werden, und Engagements werden innerhalb von Produkten gespeichert. Daher gewährt der Zugriff auf ein Produkt automatisch Zugriff auf alle Tests (und Engagements) innerhalb dieses Produkts. Tests verfügen nicht über eigene Zugriffskontrolllisten.

### Zugriff auf Tests

Obwohl Tests in DefectDojo OS als eigenständiges Objekt existieren, gibt es für sie keinen eigenen Bereich in der Benutzeroberfläche. Daher ist jeder Test in erster Linie über das Produkt und/oder Engagement zugänglich, das ihn enthält.

### Testansicht

Die Testansicht enthält eine Vielzahl von Tabellen, darunter das übergeordnete Engagement, die Import- und Reimport-Historie, eine Liste der im Test enthaltenen Befunde sowie etwaige Befundgruppen.

Zudem gibt es Tabellen für potenzielle Befunde, Dateien und Notizen, die alle manuell hinzugefügt werden können.

#### Testeinstellungen

In jeder Testansicht stehen folgende Einstellungen zur Verfügung:
- **Test bearbeiten**
    - Ermöglicht die Bearbeitung von Testdaten wie Titel, Zeitplan, Umgebung und weiteren Details.
- **Test kopieren**
    - Dupliziert einen Test einschließlich aller zugehörigen Metadaten und Befunde und ermöglicht es, ihn einem anderen Engagement zuzuordnen.
- **Scan erneut hochladen**
    - Startet den Reimport-Prozess. Weitere Informationen zum Reimport finden Sie später in diesem Artikel.
- **Notizen hinzufügen**
    - Ermöglicht es dem Benutzer, eine Notiz hinzuzufügen. Am unteren Rand der Seite befindet sich außerdem eine Notizen-Tabelle.
        - Eine Notiz kann als Privat markiert werden; in diesem Fall wird sie nicht an Jira übertragen und nicht in Berichte oder Exporte von Befunden aufgenommen.
- **Bericht**
    - Startet den Prozess zur Erstellung eines Berichts, bei dem zahlreiche Filter angewendet werden können, um einen Bericht zu erstellen, der nur die gefilterten Befunde enthält.
- **Zum Kalender hinzufügen**
    - Lädt eine .ics-Datei des gewählten Tests herunter, die Sie zu einer externen Kalenderanwendung hinzufügen können.
- **Verlauf anzeigen**
    - Öffnet einen Verlauf der am Test vorgenommenen Änderungen zu Tracking-, Berichts- und Auditzwecken.

## Arbeiten mit Tests

### Tests erstellen

Tests können automatisch erstellt werden, wenn Scan-Daten direkt in ein Engagement importiert werden, wodurch ein neuer Test mit den Scan-Daten entsteht. Tests können auch im Vorgriff auf die Planung zukünftiger Engagements erstellt werden oder für manuell erfasste Sicherheitsbefunde, die Tracking und Behebung erfordern.

#### Manuelle Workflows

Es gibt mehrere Möglichkeiten, einen Test in der OS-Version zu erstellen:

- Wählen Sie ein Produkt aus und klicken Sie im Menü „Befunde“ der Navigationsleiste auf „Scan-Ergebnisse importieren“
    - Dadurch wird ein Ad-hoc-Engagement erstellt, das den Test enthält

![image](images/tests_ss5.png)

- Wählen Sie ein Engagement innerhalb eines Produkts aus, klicken Sie auf das Dropdown-Menü im Bereich „Tests“ und klicken Sie entweder auf „Tests hinzufügen“ oder „Scan-Ergebnisse importieren“
    - Dadurch wird der resultierende Test direkt innerhalb des gewählten Engagements erstellt

![image](images/tests_ss6.png)

- Beim Erstellen eines Engagements

![image](images/tests_ss7.png)

Mit der dritten oben genannten Methode können Sie beim Erstellen eines Engagements Folgendes tun:

- Scan-Ergebnisse sofort importieren
- Eine Test-Hülle erstellen (in die Sie später einen Scan importieren)
- Keines von beidem tun und das Engagement einfach durch Klicken auf „Fertig“ erstellen

Sie haben die Möglichkeit, beim Importieren eines Scans oder beim Erstellen einer Test-Hülle Metadaten hinzuzufügen. Alle Metadaten werden im Bereich „Import-Historie“ der Testansicht angezeigt.

#### Automatisierte Workflows

In automatisierten Workflows können Tests programmatisch als Teil des Scan-Importprozesses erstellt werden, sodass Pipelines Ergebnisse hochladen können, ohne dass zuvor manuell ein Test erstellt werden muss.

Wenn Sie die API zum Importieren von Scan-Ergebnissen verwenden, kann automatisch ein neuer Test erstellt werden, indem Sie ein Engagement anstelle eines Tests angeben.

##### API

curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`

Aufgrund der obigen Angaben wird ein neuer Test unter dem angegebenen Engagement erstellt, und die Scan-Ergebnisse werden diesem Test zugeordnet.

Wird stattdessen eine `test`-ID angegeben, werden die Scan-Ergebnisse zu einem bestehenden Test hinzugefügt, was bei Reimport-Workflows üblich ist.

### Tests bearbeiten

Tests können bearbeitet werden, indem Sie entweder in der Tests-Tabelle der Ansicht des übergeordneten Engagements über das ⋮-Kebab-Menü auf **Test bearbeiten** klicken, oder über das Einstellungsmenü in der Testansicht. Alle daraufhin bearbeitbaren Felder stehen auch bei der Erstellung des Tests zur Verfügung.

![image](images/tests_ss24.png)

![image](images/tests_ss12.png)

#### Befunde manuell zu einem Test hinzufügen

Ein Befund kann manuell zu einem Test hinzugefügt werden, indem Sie entweder im ⋮-Kebab-Menü neben dem Test in der Ansicht des übergeordneten Engagements auf **Befund zu Test hinzufügen** klicken, oder über die Einstellungen der Befunde-Tabelle in der Testansicht.

![image](images/tests_ss29.png)

![image](images/tests_ss30.png)

### Tests löschen

Um einen Test zu löschen, wählen Sie **Test löschen** entweder im ⋮-Kebab-Menü neben dem Test in der Ansicht des übergeordneten Engagements oder im Einstellungsmenü der Testansicht aus. Diese Aktion kann nicht rückgängig gemacht werden.

Beim Löschen eines Tests werden auch alle darin enthaltenen Befunde gelöscht.

![image](images/tests_ss25.png)

![image](images/tests_ss26.png)

## Reimport

Das Reimportieren von Scans innerhalb von Tests ist grundlegend für eine effektive Deduplizierung. Wenn Scan-Ergebnisse in denselben Test reimportiert werden:

- Bestehende Befunde können aktualisiert werden
- Doppelte Befunde können unterdrückt werden
- Neue Befunde können erstellt werden, wenn keine Übereinstimmung gefunden wird

Dieses Verhalten hängt von den konfigurierten Deduplizierungsregeln und dem Scan-Typ ab.

Wird ein neuer Test erstellt, anstatt in einen bestehenden zu reimportieren, kann dies dazu führen, dass doppelte Befunde erstellt statt aktualisiert werden.

#### Reimport vs. Import

Reimport wird typischerweise verwendet, wenn:

- Wiederkehrende Scans gegen dasselbe Ziel durchgeführt werden
- Die Entwicklung von Befunden im Zeitverlauf nachverfolgt wird
- Eine kontinuierliche Sicht auf die Sicherheitslage der Anwendung aufrechterhalten wird

Im Gegensatz dazu eignet sich der Import (Erstellung eines neuen Tests) eher für einmalige oder unabhängige Scan-Ausführungen.

### Reimportieren von Scan-Ergebnissen (UI)

Um neue Daten zu einem bestehenden Test hinzuzufügen, klicken Sie entweder im ⋮-Kebab-Menü neben dem Test in der Ansicht des übergeordneten Engagements auf **Scan-Ergebnisse erneut hochladen**, oder klicken Sie im Einstellungsmenü der Testansicht auf **Scan erneut hochladen**.

![image](images/tests_ss27.png)

![image](images/tests_ss10.png)

Beim Ausfüllen des Reimport-Scan-Formulars haben Sie die Möglichkeit, Metadaten für den reimportierten Scan zu aktualisieren, einschließlich Version, Branch-Tag, Commit-Hash und Build-ID.

Diese Änderungen werden im Bereich „Import-Historie“ der Testansicht angezeigt, der auch dieselben Metadaten aus vorherigen Scan-Importen enthält.

Im folgenden Screenshot beispielsweise wurden Branch-Tag, Build-ID, Commit-Hash und Version zwischen dem ursprünglichen Import und dem anschließenden Reimport alle manuell aktualisiert.

![image](images/tests_ss28.png)

Um die Metadaten des zuletzt reimportierten Scans zu bearbeiten, folgen Sie den vorherigen Anweisungen im Abschnitt „Tests bearbeiten“ oben und aktualisieren Sie die Metadaten nach Bedarf. Es können nur die Metadaten des jeweils letzten Imports bearbeitet werden.

### Reimportieren von Scan-Ergebnissen (API)

Wenn Tests über eine CI/CD-Pipeline erstellt oder aktualisiert werden, können Sie Metadaten aus dem Pipeline-Lauf einbeziehen, damit Tests korrekt mit dem gescannten Code verknüpft werden können. Dadurch können Sie:
- Scan-Ergebnisse einem bestimmten Commit oder Branch zuordnen.
- Nachverfolgen, wie sich Befunde im Zuge von Codeänderungen entwickeln.
- Die Deduplizierung verbessern, indem Sie nachvollziehen, wann sich zwei Scans auf dieselbe oder unterschiedliche Codeversionen beziehen.
- Die Auditierbarkeit unterstützen, indem genau gezeigt wird, welcher Code wann gescannt wurde.

Die API von DefectDojo akzeptiert diese Werte während des Imports oder Reimports, sodass sie als Teil des Scan-Imports gespeichert und in der Import-Historie des Tests angezeigt werden können. Diese Metadaten können verwendet werden, um Commit-Hashes oder andere relevante Repository-Informationen im Zusammenhang mit einem CI/CD-Lauf zu identifizieren.

#### Unterstützte Metadatenfelder

Die API unterstützt eine definierte Reihe von Metadatenfeldern, die beim Reimport angegeben werden können. Dazu gehören:

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- `active / verified` flags

Diese Felder stellen den primären Mechanismus dar, um während eines Reimport-Vorgangs kontextbezogene Metadaten anzuhängen.

In automatisierten Pipelines gehören zu den am häufigsten bereitgestellten Metadaten:
- build_id (CI-Job-Kennung)
- commit_hash (Versionskontroll-Referenz)
- branch_tag (Branch- oder Umgebungskontext)
- tags (z. B. nightly, staging, production)

Diese Felder sorgen für Nachvollziehbarkeit über mehrere Scans hinweg, ohne dass ein manueller Eingriff erforderlich ist.

Obwohl Metadaten manuell über das Reimport-Scan-Formular aktualisiert werden können, erledigen die meisten automatisierten Umgebungen dies, indem sie direkt den Endpunkt `/api/v2/reimport-scan/` aufrufen. Dieser Ansatz ermöglicht es der Pipeline, Metadaten beim Reimport automatisch anzuhängen.

##### API-Reimport mit Metadaten

curl -X POST `"https://<your-instance>/api/v2/reimport-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"test=123"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"` \
  -F `"tags=nightly,api-scan"` \
  -F `"version=1.4.2"` \
  -F `"build_id=jenkins-842"` \
  -F `"branch_tag=main"` \
  -F `"commit_hash=a1b2c3d4"`

##### Metadaten, Reimport und geplante Scans

Scans können auch so geplant werden, dass sie in regelmäßigen Abständen ausgeführt werden, etwa ausgelöst durch Cron-Jobs. Geplante Scans sind nicht an Repository-Aktivitäten gebunden, wodurch Metadaten wie Commit-Hashes oder Branch-Namen irrelevant werden, sofern sie nicht explizit vom Skript selbst eingefügt werden. Dennoch kann die Verwendung von Reimport sinnvoll sein, wenn Sie einen fortlaufenden Verlauf Ihrer Sicherheitslage innerhalb eines einzelnen Tests führen möchten. 