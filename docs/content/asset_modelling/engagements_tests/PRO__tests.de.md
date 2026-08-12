---
title: Tests
description: Tests in DefectDojo Pro verstehen
audience: pro
weight: 4
---

Organizations → Assets → Engagements → **TESTS** → Findings

## Übersicht

Ein Test ist ein Container für eine oder mehrere Scan-Ausführungen, mit denen Schwachstellen in einem Asset aufgedeckt werden. Tests sind die letzte, granularste Komponente der Objekthierarchie von DefectDojo. Sie dienen als Container für die Befunde, die aus der Ausführung eines Sicherheitstools oder einer manuellen Bewertung resultieren, und liefern zugleich den Kontext, in dem diese Befunde gefunden wurden (z. B. welches Tool sie gemeldet hat, wann dieses Tool zuletzt ausgeführt wurde usw.).

Beispiele für Tests sind:
- Static Application Security Testing
- Dynamic Application Security Testing
- Software Composition Analysis
- Container-Sicherheitsscans
- Infrastruktur- / Netzwerkscans
- Manuelle Penetrationstests
- CI/CD-Pipeline-Scans

### Testtypen

Es gibt mehrere Möglichkeiten, Tests in DefectDojo zu erstellen, darunter **herstellerspezifische Parser** (z. B. Burp, OWASP ZAP, Acunetix, Invicti), **Generic Findings Import**, **Universal Parser** und **Connectors**.

Je nach Konfiguration und Deduplizierungsstrategie können diese Methoden neue Tests erstellen oder Befunde in bestehende Tests reimportieren.

Auch wenn sich die Methoden vor allem darin unterscheiden, wie Scan-Daten geparst und aufgenommen werden, führen sie letztlich alle dazu, dass Befunde einem Test zugeordnet werden.

#### Parser

**Parser** sind Komponenten, die bestimmte Scan-Ausgabeformate (z. B. XML, JSON, CSV) verarbeiten und in das interne Finding-Modell von DefectDojo überführen. Beim Import von Scan-Ergebnissen verwendet DefectDojo den ausgewählten Parser, um Befunde zu extrahieren und sie einem neu erstellten oder bestehenden Test zuzuordnen.

#### Generic Findings Import

Wenn für ein bestimmtes Tool kein nativer Parser existiert, können Sie mit [**Generic Findings Import**](/supported_tools/parsers/generic_findings_import) Findings unabhängig von der ursprünglichen Quelle über ein standardisiertes JSON- oder CSV-Schema importieren.

DefectDojo parst die bereitgestellten Daten, erstellt einen neuen Test (oder importiert in einen bestehenden) und ordnet die Befunde zu. Basierend auf dem optionalen Feld `type` im Bericht wird außerdem ein entsprechender Test-Typ erstellt: Wird `type` weggelassen (oder entspricht es dem Scan-Typ), lautet der Test-Typ „Generic Findings Import“; wird `type` angegeben, wird daraus „`{type}` Scan (Generic Findings Import)“ (ein `type`, der bereits auf das Suffix „(Generic Findings Import)“ endet, wird unverändert übernommen).

#### Universal Parser

Mit [**Universal Parser**](/supported_tools/parsers/universal_parser) können Benutzer festlegen, wie beliebige Eingabedaten auf das Finding-Modell von DefectDojo abgebildet werden. Nach der Konfiguration des Parsers und dem Hochladen der Scan-Daten wendet DefectDojo die Mapping-Regeln an, um Befunde zu extrahieren, erstellt einen Test (oder aktualisiert einen bestehenden) und ordnet diesem Test die Befunde zu.

#### Connectors

Mit [**Connectors**](/connectors/upstream/about/) können Schwachstellendaten aus externen Tools automatisch per API-Aufrufe abgerufen und organisiert werden. Nach der Konfiguration ruft ein Connector Scan-Ergebnisse ab, parst die Daten und erstellt je nach Konfiguration neue Tests oder aktualisiert bestehende Tests. Die Befunde werden anschließend dem entsprechenden Test zugeordnet.

#### Vergleich der Mechanismen zur Testerstellung

| | **Native Parser** | **Generic Findings Import** | **Universal Parser (Pro)** | **Connectors** |
|----------|---------------|------------------------|------------------------|------------|
| **Primärer Zweck** | Ausgaben unterstützter Tools aufnehmen | Nicht unterstützte/benutzerdefinierte Daten über festes Schema aufnehmen | Beliebige Formate über konfigurierbare Mappings aufnehmen | Externe Systeme kontinuierlich synchronisieren |
| **Eingabeformat** | Tool-spezifisch (z. B. ZAP XML, SARIF) | Striktes JSON/CSV-Schema | Beliebig (JSON, XML usw.) | Externe API-Antworten |
| **Wer übernimmt die Normalisierung** | DefectDojo (integrierter Parser) | Benutzer (muss dem Schema entsprechen) | DefectDojo (über Parser-Konfiguration) | Externes Tool + DefectDojo |
| **Auslöser der Testerstellung** | Manueller Upload oder API-Import | Manueller Upload oder API-Import | Manueller Upload oder API-Import | Automatisierte Synchronisierung (geplant oder ereignisgesteuert) |
| **Test-Typ** | Vordefiniert (z. B. „ZAP Scan“) | Automatisch erstellter Typ „Generic“ | Aus der Parser-Konfiguration abgeleitet | Abhängig vom Connector / zugrunde liegenden Parser |
| **Einrichtungsaufwand** | Gering | Moderat (Datentransformation erforderlich) | Hoch (Parser-Konfiguration) | Moderat–hoch (Integrationseinrichtung) |
| **Flexibilität** | Gering (nur unterstützte Tools) | Mittel | Hoch | Mittel–hoch |
| **Automatisierungsgrad** | Gering–moderat | Gering–moderat | Gering–moderat | Hoch |
| **Typischer Anwendungsfall** | Standard-Scanner (SAST, DAST, SCA) | Eigene Skripte, nicht unterstützte Tools | Komplexe/benutzerdefinierte Formate im großen Maßstab | CI/CD-, SCM- oder Plattformintegrationen |

Unabhängig von der Ingestion-Methode werden alle Scan-Daten in DefectDojo letztlich als Befunde dargestellt, die einem Test zugeordnet sind, der als Einheit für Ausführung und Lifecycle-Tracking dient.

### Testdaten

Tests speichern eine Vielzahl von Metadaten, die dabei helfen, verschiedene Bestandteile jedes Testvorgangs zu dokumentieren, wie zum Beispiel:
- Testtitel / -name
- Testtyp
- Testbeschreibung / Notizen
- Start- und Enddatum
- Die Umgebung, in der der Test ausgeführt wurde (z. B. Development, Staging, Pre-Production, Production usw.)
- Version / Branch / Build-ID / Commit-Hash
- API-Scan-Konfiguration
- Mit dem Test verknüpftes Personal
- Zusätzliche Dateien, die für spätere Audits oder Reimporte verwendet werden können
- Das übergeordnete Engagement, Asset und die Organisation
- Import- und Reimport-Verlauf

Jeder Test führt einen Importverlauf, in dem alle mit dem Test verknüpften Scan-Importe und -Reimporte erfasst werden. Jeder Verlaufseintrag enthält Metadaten wie Scan-Datum, Version, Branch, Commit-Hash und Build-ID.

Dieser Verlauf ermöglicht Nachvollziehbarkeit über mehrere Scan-Ausführungen innerhalb desselben Tests hinweg.

### Berechtigungen

Mehrere Tests können innerhalb eines einzigen Engagements gespeichert werden, und Engagements werden innerhalb von Assets gespeichert. Der Zugriff auf ein Asset gewährt daher automatisch Zugriff auf alle Tests (und Engagements) innerhalb dieses Assets. Tests verfügen über keine eigenen Zugriffskontrolllisten.

## Zugriff auf Tests

Auf Tests kann von verschiedenen Bereichen der DefectDojo-Benutzeroberfläche aus zugegriffen werden.

- Die Seitenleiste

![image](images/tests_ss13.png)

- Innerhalb eines Engagements

![image](images/tests_ss14.png)

- Die obere Leiste eines Assets

![image](images/tests_ss15.png)

- Die Metadatentabelle in der Ansicht eines Befunds

![image](images/tests_ss16.png)

## Arbeiten mit Tests

### Tests erstellen

Tests können automatisch erstellt werden, wenn Scan-Daten direkt in ein Engagement importiert werden, wodurch ein neuer Test mit den Scan-Daten entsteht. Tests können auch im Vorgriff auf die Planung zukünftiger Engagements erstellt werden oder für manuell eingegebene Sicherheitsbefunde, die nachverfolgt und behoben werden müssen.

#### Manuelle Workflows

Um einen Test zu erstellen, muss zunächst ein Engagement vorhanden sein, das ihn enthält, sowie ein Asset, das dieses Engagement enthält. Danach gibt es mehrere Möglichkeiten, einen Test zu erstellen:

- In der Seitenleiste, unter Tests im Unterbereich **Manage**
    - Beim Ausfüllen des Formulars „New Test“ müssen Sie das bereits vorhandene Engagement auswählen, dem der Test zugeordnet werden soll.

![image](images/tests_ss1.png)

- Das Einstellungs-Dropdown oben rechts in einer Asset-Ansicht
    - **Import Scan** erstellt automatisch einen Test, sobald dem Formular „Import Scan“ eine Scan-Datei hinzugefügt wurde. Sie haben die Möglichkeit, den Test entweder einem bereits vorhandenen Engagement zuzuordnen oder ein neues Engagement zu erstellen und zu benennen, das den neuen Test enthält.
        - Beim Ausfüllen des Formulars „Import Scan“ können Sie Metadaten wie Version, Branch-Tag, Commit-Hash und Build-ID hinzufügen. Diese werden im Abschnitt „Import History“ der Testansicht angezeigt.

![image](images/tests_ss2.png)

- Das Einstellungs-Dropdown oben rechts in einer Engagement-Ansicht
    - **Import Scan** folgt demselben Workflow wie bei Assets, platziert das Testobjekt jedoch automatisch innerhalb des Engagements, in dem Sie auf Import Scan geklickt haben.
    - **Add Test** erstellt ein Testobjekt, erfordert jedoch nicht, dass dem Test selbst ein Scan hochgeladen wird. Das ist nützlich im Vorgriff auf die Planung zukünftiger Tests oder für manuell eingegebene Sicherheitsbefunde, die nachverfolgt und behoben werden müssen.

![image](images/tests_ss3.png)

Wenn Sie Add Test auswählen und später die Ergebnisse eines Scans manuell in einen Test importieren möchten, können Sie dies tun, indem Sie den Test öffnen und in dessen Einstellungen auf die Schaltfläche Reimport Findings oder in der Befunde-Tabelle auf die Schaltfläche Reimport Scan klicken.

![image](images/tests_ss21.png)

#### Automatisierte Workflows

In automatisierten Workflows können Tests programmatisch als Teil des Scan-Importprozesses erstellt werden, sodass Pipelines Ergebnisse hochladen können, ohne dass vorab manuell ein Test erstellt werden muss.

Bei der Verwendung der API oder CLI zum Importieren von Scan-Ergebnissen kann automatisch ein neuer Test erstellt werden, indem ein `engagement` statt eines `test` angegeben wird.

##### API

curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`

Angesichts des Obigen wird ein neuer Test unter dem angegebenen Engagement erstellt, und die Scan-Ergebnisse werden diesem Test zugeordnet.

Wird stattdessen eine `test`-ID angegeben, werden die Scan-Ergebnisse einem bestehenden Test hinzugefügt, was in Reimport-Workflows üblich ist.

##### CLI

Bei Verwendung der DefectDojo-CLI wird dieses Verhalten automatisch anhand der angegebenen Argumente gesteuert.

defectdojo-cli import \
  --engagement-id 45 \
  --scan-type `"ZAP Scan"` \
GOog  --file report.xml

Angesichts des Obigen erstellt die Angabe einer `engagement-id` einen neuen Test, während die Angabe einer `test-id` einen bestehenden Test wiederverwendet und Scan-Ergebnisse in diesen Test reimportiert.

Weitere Details zu den erforderlichen Flags finden Sie unter [DefectDojo-CLI](/import_data/pro/specialized_import/external_tools/#defectdojo-cli).

### Tests bearbeiten

Tests können bearbeitet werden, indem Sie im Zahnrad-Menü auf **Edit Test** klicken. Alle daraufhin bearbeitbaren Felder stehen auch bei der Erstellung des Tests zur Verfügung.

### Tests löschen

Ein Test kann gelöscht werden, indem Sie in den Einstellungen des Tests **Delete Test** auswählen. Diese Aktion kann nicht rückgängig gemacht werden.

Beim Löschen eines Tests werden auch alle darin enthaltenen Befunde gelöscht.

### Scan-Ergebnisse reimportieren (UI)

Um einem bestehenden Test neue Daten hinzuzufügen, öffnen Sie den betreffenden Test und klicken Sie in dessen Einstellungen auf die Schaltfläche Reimport Findings oder in der Befunde-Tabelle auf die Schaltfläche Reimport Scan.

![image](images/tests_ss21.png)

Beim Ausfüllen des Formulars „Reimport Scan“ haben Sie die Möglichkeit, Metadaten für den reimportierten Scan zu aktualisieren, darunter Version, Branch-Tag, Commit-Hash und Build-ID. Diese Änderungen werden im Abschnitt „Import History“ der Testansicht angezeigt, der auch die entsprechenden Metadaten früherer Scan-Importe enthält.

Im folgenden Screenshot beispielsweise wurden Branch-Tag, Build-ID, Commit-Hash und Version zwischen dem ursprünglichen Import und dem anschließenden Reimport alle manuell aktualisiert.

![image](images/tests_ss23.png)

Um die Metadaten des zuletzt reimportierten Scans zu bearbeiten, klicken Sie auf das Zahnrad-Symbol oben rechts in einer Engagement-Ansicht und wählen Sie „Edit Test“. Es können nur die Metadaten des letzten Imports bearbeitet werden.

### Scan-Ergebnisse reimportieren (API/CLI)

Wenn Tests über eine CI/CD-Pipeline erstellt oder aktualisiert werden, können Sie Metadaten aus dem Pipeline-Lauf einbeziehen, damit Tests korrekt mit dem gescannten Code verknüpft werden können. Dadurch können Sie:
- Scan-Ergebnisse mit einem bestimmten Commit oder Branch verknüpfen.
- Nachverfolgen, wie sich Befunde im Zuge von Codeänderungen entwickeln.
- Die Deduplizierung verbessern, indem Sie nachvollziehen, wann sich zwei Scans auf dieselbe oder unterschiedliche Codeversionen beziehen.
- Die Auditierbarkeit unterstützen, indem genau gezeigt wird, welcher Code wann gescannt wurde.

Die CLI und API von DefectDojo akzeptieren diese Werte während des Imports oder Reimports, sodass sie als Teil des Scan-Imports gespeichert und im Importverlauf des Tests angezeigt werden. Diese Metadaten können verwendet werden, um Commit-Hashes oder alles, was mit relevanten Repository-Informationen zu einem CI/CD-Lauf zusammenhängt, zu identifizieren.

#### Unterstützte Metadatenfelder

Die API und CLI unterstützen einen definierten Satz von Metadatenfeldern, die beim Reimport angegeben werden können. Dazu gehören:

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- `active / verified`-Flags

Diese Felder stellen den primären Mechanismus dar, um bei einem Reimport-Vorgang kontextbezogene Metadaten anzuhängen.

In automatisierten Pipelines gehören zu den am häufigsten angegebenen Metadaten:
- `build_id` (CI-Job-Kennung)
- `commit_hash` (Versionskontroll-Referenz)
- `branch_tag` (Branch- oder Umgebungskontext)
- `tags` (z. B. `nightly`, `staging`, `production`)

Diese Felder ermöglichen Nachvollziehbarkeit über mehrere Scans hinweg, ohne dass ein manueller Eingriff erforderlich ist.

Obwohl Metadaten manuell über das Formular „Reimport Scan“ aktualisiert werden können, erledigen die meisten automatisierten Umgebungen dies, indem sie den Endpunkt `/api/v2/reimport-scan/` direkt aufrufen oder die DefectDojo-CLI (`defectdojo-cli reimport`) als Teil des Build-Prozesses verwenden. Dieser Ansatz ermöglicht es der Pipeline, beim Reimport automatisch Metadaten anzuhängen.

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

##### CLI-Reimport mit Metadaten

defectdojo-cli import \
  --test-id 123 \
  --scan-type "ZAP Scan" \
  --file report.xml \
  --tag nightly \
  --tag api \
  --build-id jenkins-842 \
  --branch main \
  --commit a1b2c3d4

Die CLI wird direkt auf denselben API-Endpunkt abgebildet und unterstützt denselben Satz von Metadatenfeldern.

Bei der Arbeit mit Metadaten während des Reimports sind einige Einschränkungen zu beachten:
- Die API/CLI unterstützt nur vordefinierte Parameter. Benutzerdefinierte Schlüssel-Wert-Metadaten können beim Reimport nicht hinzugefügt werden
- Zusätzliche Metadaten können je nach Scan-Typ und Parser aus der Scan-Datei selbst extrahiert werden.
- Beim Reimport angegebene Metadaten wirken sich nicht in gleicher Weise als direktes Update auf das Testobjekt aus wie manuelle Änderungen in der UI.

##### Metadaten, Reimport und geplante Scans

Scans können auch so geplant werden, dass sie in routinemäßigen Intervallen ausgeführt werden, etwa durch Cron-Jobs ausgelöst. Geplante Scans sind nicht an Repository-Aktivität gebunden, weshalb Metadaten wie Commit-Hashes oder Branch-Namen irrelevant sind, sofern sie nicht explizit vom Skript selbst eingefügt werden. Dennoch kann die Verwendung von Reimport sinnvoll sein, wenn Sie einen fortlaufenden Datensatz Ihrer Sicherheitslage innerhalb eines einzigen Tests führen möchten.

## Reimport und Deduplizierung

Das Reimportieren von Scans innerhalb von Tests ist grundlegend für eine effektive Deduplizierung. Wenn Scan-Ergebnisse in denselben Test reimportiert werden:

- Bestehende Befunde können aktualisiert werden
- Doppelte Befunde können unterdrückt werden
- Neue Befunde können erstellt werden, wenn keine Übereinstimmung gefunden wird

Dieses Verhalten hängt von den konfigurierten Deduplizierungsregeln und dem Scan-Typ ab.

Das Erstellen eines neuen Tests anstelle des Reimports in einen bestehenden kann dazu führen, dass doppelte Befunde erstellt statt aktualisiert werden.

### Reimport vs. Import

Reimport wird typischerweise verwendet, wenn:

- Wiederkehrende Scans gegen dasselbe Ziel ausgeführt werden
- Nachverfolgt wird, wie sich Befunde im Zeitverlauf entwickeln
- Eine kontinuierliche Sicht auf die Sicherheitslage der Anwendung aufrechterhalten wird

Im Gegensatz dazu eignet sich Import (das Erstellen eines neuen Tests) besser für einmalige oder unabhängige Scan-Ausführungen.
