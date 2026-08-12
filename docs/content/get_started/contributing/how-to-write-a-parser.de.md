---
title: Zu Parsern beitragen
description: Wie man zu Parsern beiträgt
draft: false
weight: 1
audience: opensource
aliases:
- /en/open_source/contributing/how-to-write-a-parser
---

Alle Befehle setzen voraus, dass Sie sich im Root-Verzeichnis des geklonten django-DefectDojo-Repos befinden.

## Voraussetzungen

- Sie haben https://github.com/DefectDojo/django-DefectDojo geforkt und lokal geklont.
- Wechseln Sie zu `dev` und stellen Sie sicher, dass Sie mit den neuesten Änderungen auf dem aktuellen Stand sind.
- Es wird empfohlen, für Ihre Entwicklung einen eigenen Branch zu erstellen, etwa mit `git checkout -b parser-name`.

Am einfachsten ist die Verwendung des Docker-Compose-Deployments, da dieses eine Hot-Reload-Funktion für uWSGI bietet.
Richten Sie Ihre Umgebung für die Verwendung der Dev-Umgebung ein:

`$ docker/setEnv.sh dev`

Weitere Details finden Sie in [DOCKER.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md).

### Docker-Images

Sie sollten Ihre Docker-Images lokal bauen und dabei die `uid` Ihres lokalen Benutzers übergeben, damit Sie in das Image schreiben können (nützlich für Datenbank-Migrationsdateien). Angenommen, die `uid` Ihres Benutzers ist `1000`, dann:

{{< highlight bash >}}
$ docker compose build --build-arg uid=1000
{{< /highlight >}}

## Welche Dateien müssen Sie ändern?

| Datei                                          | Zweck
|-------                                        |--------
|`dojo/tools/<parser_dir>/__init__.py`          | Leere Datei zur Klasseninitialisierung
|`dojo/tools/<parser_dir>/parser.py`            | Das Kernstück. Hier schreiben Sie Ihren eigentlichen Parser. Der Klassenname muss dem Python-Modulnamen ohne Unterstriche plus `Parser` entsprechen. **Beispiel:** Wenn der Name des Python-Moduls `dependency_check` lautet, muss der Klassenname `DependencyCheckParser` lauten
|`unittests/scans/<parser_dir>/{many_vulns,no_vuln,one_vuln}.json` | Beispieldateien mit aussagekräftigen Daten für Unit-Tests. Der minimale Satz.
|`unittests/tools/test_<parser_name>_parser.py` | Unit-Tests des Parsers.
|`dojo/settings/settings.dist.py`               | Falls Sie einen modernen, hashcode-basierten Deduplizierungsalgorithmus verwenden möchten
|`docs/content/supported_tools/<file/api>/<parser_file>.md` | Dokumentation, welches Dateiformat benötigt wird und wie es beschafft werden kann


## Factory-Vertrag

Parser werden dynamisch mit einem Factory-Pattern geladen. Damit Ihr Parser geladen wird und korrekt funktioniert, müssen Sie den Vertrag implementieren.

1. Ihr Parser **MUSS** sich in einem Untermodul des Moduls `dojo.tools` befinden
   - Bsp.: Modul `dojo.tools.my_tool.parser`
2. Ihr Parser **MUSS** eine Klasse in diesem Untermodul sein.
   - Bsp.: `dojo.tools.my_tool.parser.MyToolParser`
3. Der Name dieser Klasse **MUSS** dem Python-Modulnamen ohne Unterstriche und mit dem Suffix `Parser` entsprechen.
   - Bsp.: `dojo.tools.my_tool.parser.MyToolParser`
4. Diese Klasse **MUSS** einen leeren Konstruktor oder keinen Konstruktor haben
5. Diese Klasse **MUSS** 4 Methoden implementieren:
   1. `def get_scan_types(self)` Diese Funktion gibt eine Liste aller von Ihrem Parser unterstützten *scan_type* zurück. Diese Bezeichner werden intern verwendet. Ihr Parser kann mehr als einen *scan_type* unterstützen. Manche Parser verwenden beispielsweise unterschiedliche Bezeichner, um das Verhalten des Parsers zu ändern (aggregieren, filtern usw.)
   2. `def get_label_for_scan_types(self, scan_type):` Diese Funktion gibt einen String zurück, der Text in der UI liefert (kurze Bezeichnung)
   3. `def get_description_for_scan_types(self, scan_type):` Diese Funktion gibt einen String zurück, der Text in der UI liefert (lange Beschreibung)
   4. `def get_findings(self, file, test)` Diese Funktion gibt eine Liste von Findings zurück
6. Wenn Ihr Parser mehr als 1 scan_type hat (für den detaillierten Modus), **MÜSSEN** Sie die Methode `def set_mode(self, mode)` implementieren
7. Die Parser-Instanz wird für alle Importe dieses scan_type wiederverwendet, speichern Sie daher keine Daten auf Klassenebene

Beispiel:

```Python

class MyToolParser(object):
    def get_scan_types(self):
        return ["My Tool Scan", "My Tool Scan detailed"]

    def get_label_for_scan_types(self, scan_type):
        if scan_type == "My Tool Scan":
            return "My Tool XML Scan aggregated by ..."
        else:
            return "My Tool XML Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Aggregates findings per cwe, title, description, file_path. SonarQube output file can be imported in HTML format. Generate with https://github.com/soprasteria/sonar-report version >= 1.1.0"

    def requires_file(self, scan_type):
        return False

    # mode:
    # None (default): aggregates vulnerabilites per sink filename (legacy behavior)
    # 'detailed' : No aggregation
    mode = None

    def set_mode(self, mode):
        self.mode = mode

    def get_findings(self, file, test):
        <...>

```

## API-Parser

DefectDojo verfügt über eine begrenzte Anzahl von API-Parsern. Wir werden diese Connectoren zwar nicht entfernen, aber das Hinzufügen von API-Connectoren hat sich als problematisch erwiesen, weshalb wir aus Gründen der Supportfähigkeit derzeit keine neuen API-Parser/Connectoren aus der Community annehmen können. Um einen API-Connector von hoher Qualität zu erhalten, ist eine Lizenz für das Tool erforderlich. Um diese Lizenz zu erhalten, ist eine Partnerschaft mit dem Autor oder Anbieter nötig. Wir stehen kurz davor, ein neues Programm anzukündigen, das dieses Problem adressiert und API-Connectoren zu DefectDojo bringt.

## Template-Generator

Verwenden Sie den [Template](https://github.com/DefectDojo/cookiecutter-scanner-parser)-Parser, um die benötigten Dateien schnell zu erzeugen. Dazu müssen Sie zunächst [cookiecutter](https://github.com/cookiecutter/cookiecutter) installieren.

{{< highlight bash >}}
$ pip install cookiecutter
{{< /highlight >}}

Generieren Sie dann Ihren Scanner-Parser vom Root-Verzeichnis von django-DefectDojo aus:

{{< highlight bash >}}
$ cookiecutter https://github.com/DefectDojo/cookiecutter-scanner-parser
{{< /highlight >}}

Lesen Sie [mehr](https://github.com/DefectDojo/cookiecutter-scanner-parser) über die Konfigurationsvariablen der Vorlage.

## Worauf Sie achten sollten

Hier ist eine Liste von Überlegungen, die den Parser sowohl für häufige Fälle als auch für Randfälle robust machen.

### URLs nicht von Hand parsen

Wir verwenden 2 Module zur Verarbeitung von Endpunkten:
 - `hyperlink`
 - `dojo.models` mit einer speziellen Klasse zur Verarbeitung von URLs zur Erstellung von Endpunkten, `Endpoint`.

Alle vorhandenen Parser verwenden denselben Code, um URLs zu parsen und Endpunkte zu erstellen.
Die Verwendung von `Endpoint.from_uri()` ist der beste Weg, um Endpunkte zu erstellen.
Wenn Sie wirklich eine URL parsen müssen, verwenden Sie das Modul `hyperlink`.

Gutes Beispiel:

```python
    if "url" in item:
        endpoint = Endpoint.from_uri(item["url"])
        finding.unsaved_endpoints = [endpoint]
```

Sehr schlechtes Beispiel:

```python
    u = urlparse(item["url"])
    endpoint = Endpoint(host=u.host)
    finding.unsaved_endpoints = [endpoint]
```

### Verwenden Sie die richtigen Bibliotheken zum Parsen von Informationen
Verschiedene Dateiformate werden über Bibliotheken verarbeitet. Um DefectDojo schlank zu halten und die Angriffsfläche nicht zu vergrößern, halten Sie die Anzahl der verwendeten Bibliotheken minimal und orientieren Sie sich an anderen Parsern.

#### defusedXML statt lxml
Da XML standardmäßig ein unsicheres Format ist, müssen die aus verschiedenen XML-Ausgaben geparsten Informationen auf sichere Weise verarbeitet werden. Im Rahmen einer Evaluierung haben wir festgestellt, dass defusedXML die Bibliothek ist, die wir künftig zum Parsen von XML-Dateien in Parsern verwenden werden, da diese Bibliothek als sicherer eingestuft wird. Daher werden wir nur PRs mit der defusedxml-Bibliothek akzeptieren.

### Nicht alle Attribute sind verpflichtend

Parser können viele Felder haben, von denen viele optional sein können.
Es ist besser, ein Attribut nicht zu setzen, wenn Sie keine Daten haben, anstatt es mit Werten wie `NA`, `No data` usw. zu füllen.

Sehen Sie sich die Klasse `dojo.models.Finding` an

### Im Quellbericht können Daten fehlen

Stellen Sie immer sicher, dass Sie Prüfungen einbauen, um mögliche `KeyError`-Fehler zu vermeiden (z. B. wenn ein Feld nicht existiert), bei Feldern, von denen Sie nicht absolut sicher sind, dass sie immer in der hochgeladenen Datei vorhanden sind. Diese führen zu einem 500-Fehler und machen keinen guten Eindruck.

Gutes Beispiel:

```python
   if "mykey" in data:
       finding.cwe = data["mykey"]
```

```python
   finding.cwe = data.get("mykey", 123)
```

```python
   some_list = data.get("key_of_the_list") or []
```

Das letzte Beispiel schützt vor Fällen, in denen `key_of_the_list` zwar vorhanden, aber `null` ist.


### Parsen von CVSS-Vektoren

Daten können `CVSS`-Vektoren oder -Werte enthalten. Defect Dojo verwendet das von RedHat Security bereitgestellte `cvss`-Modul.
Es gibt außerdem eine Hilfsmethode, um den Vektor zu validieren und den Basiswert sowie den Schweregrad daraus zu extrahieren.

```python
    from dojo.utils import parse_cvss_data

    cvss_vector = <get CVSS3 or CVSS4 vector from the report>
    cvss_data = parse_cvss_data(cvss_vector)
    if cvss_data:
        finding.severity = cvss_data["severity"]
        finding.cvssv3 = cvss_data["cvssv3"]
        finding.cvssv4 = cvss_data["cvssv4"]
        # we don't set any score fields as those will be overwritten by Defect Dojo
```
Es müssen nicht alle Werte verwendet werden, da Scanberichte üblicherweise ihren eigenen Wert für `severity` liefern.
Manchmal auch für `cvss_score`. Defect Dojo überschreibt kein `cvss3_score` oder `cvss4_score`.
Wenn kein Wert gesetzt ist, verwendet Defect Dojo die `cvss`-Bibliothek, um den Wert zu berechnen.
Die Antwort enthält außerdem die erkannte Hauptversion des CVSS-Vektors in `cvss_data["major_version"]`.


Wenn Sie mehr manuelle Verarbeitung benötigen, können Sie den `CVSS`-Vektor direkt parsen.

Verwendungsbeispiel:

```python
    import cvss.parser
    from cvss import CVSS2, CVSS3, CVSS4

    # TEMPORARY: Use Defect Dojo implementation of `parse_cvss_from_text` white waiting for https://github.com/RedHatProductSecurity/cvss/pull/75 to be released
    vectors = cvss.parser.parse_cvss_from_text("CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X")
        if len(vectors) > 0 and type(vectors[0]) is CVSS3:
            print(vectors[0].severities())  # this is the 3 severities

            cvssv3 = vectors[0].clean_vector()
            severity = vectors[0].severities()[0]
            vectors[0].compute_base_score()
            cvssv3_score = vectors[0].scores()[0]
            finding.severity = severity
            finding.cvssv3_score = cvssv3_score
```

Machen Sie es nicht so:

```
    def get_severity(self, cvss, cvss_version="2.0"):
        cvss = float(cvss)
        cvss_version = float(cvss_version[:1])
        # If CVSS Version 3 and above
        if cvss_version >= 3:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss < 9:
                return "High"
            elif cvss >= 9:
                return "Critical"
            else:
                return "Informational"
        # If CVSS Version prior to 3
        else:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss <= 10:
                return "High"
            else:
                return "Informational"
```

## Deduplizierungsalgorithmus

Standardmäßig verwendet ein neuer Parser den in [Über Deduplizierung](/triage_findings/finding_deduplication/about_deduplication/) dokumentierten Deduplizierungsalgorithmus „legacy“

Bitte verwenden Sie, wo anwendbar, einen vordefinierten Deduplizierungsalgorithmus. Wenn Sie die Felder `unique_id_from_tool` oder `vuln_id_from_tool` in der Hashcode-Konfiguration verwenden, ist es wichtig, dass diese für das Finding eindeutig sind und über aufeinanderfolgende Scans hinweg konstant bleiben. Ist dies nicht der Fall, können die Werte dennoch nützlich sein, um sie im Finding-Modell zu setzen, ohne sie für die Deduplizierung zu verwenden.
Die Werte müssen direkt aus dem Bericht stammen und dürfen nicht etwas sein, das intern vom Parser berechnet wird.

## Unit-Tests

Jeder Parser muss Unit-Tests haben, mindestens um 0 Schwachstellen, 1 Schwachstelle und viele Schwachstellen zu testen. Sie können sich ansehen, wie andere Parser das für den Einstieg gelöst haben. Je mehr hochwertige Tests, desto besser.

Es ist wichtig, Prüfungen für Attribute von Findings hinzuzufügen.
Bsp.:

```python
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("test title", finding.title)
            self.assertEqual(True, finding.active)
            self.assertEqual(True, finding.verified)
            self.assertEqual(False, finding.duplicate)
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("CVE-2020-36234", finding.vulnerability_ids[0])
            self.assertEqual(261, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
            self.assertIn("security", finding.tags)
            self.assertIn("network", finding.tags)
            self.assertEqual("3287f2d0-554f-491b-8516-3c349ead8ee5", finding.unique_id_from_tool)
            self.assertEqual("TEST1", finding.vuln_id_from_tool)
```

### Verwenden Sie with, um Beispieldateien zu öffnen

Um sicherzustellen, dass Dateihandles ordnungsgemäß geschlossen werden, verwenden Sie bitte das with-Muster zum Öffnen von Dateien.
Anstatt:
```python
    testfile = open("path_to_file.json")
    ...
    testfile.close()
```

verwenden Sie:
```python
    with open("path_to_file.json") as testfile:
        ...
```

Dies stellt sicher, dass die Datei am Ende der with-Anweisung geschlossen wird, selbst wenn irgendwo im Block eine Ausnahme auftritt.

### Testdatenbank

Django verwendet für die Ausführung von Unit-Tests eine separate Testdatenbank namens `test_defectdojo`. Sie wird automatisch erstellt und mit einem grundlegenden Satz an Testdaten initialisiert.

### Führen Sie Ihre Tests aus

Dieser lokale Befehl startet den Unit-Test für Ihren neuen Parser

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.<your_unittest_py_file>.<main_class_name> -v2'
{{< /highlight >}}

oder so:

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.<your_unittest_py_file>.<main_class_name>
{{< /highlight >}}

Beispiel für den aqua-Parser:

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.test_aqua_parser.TestAquaParser -v2'
{{< /highlight >}}

oder so:

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.test_aqua_parser.TestAquaParser
{{< /highlight >}}

Wenn Sie alle Parser-Unit-Tests ausführen möchten, führen Sie einfach `$ docker-compose exec uwsgi bash -c 'python manage.py test -p "test_*_parser.py" -v2'` aus

### Endpunktvalidierung

Manche Arten von Parsern erstellen eine Liste verwundbarer Endpunkte (diese werden in `finding.unsaved_endpoints` gespeichert). DefectDojo erfordert die Speicherung von Endpunkten in einem bestimmten Format (gemäß RFCs). Endpunkte, die diesem Format nicht entsprechen, können zwar gespeichert werden, werden aber als fehlerhaft markiert (rote Flagge 🚩 in der UI). Um sicherzustellen, dass Ihr Parser Endpunkte im korrekten Format speichert, führen Sie in den Unit-Tests die Funktion `.clean()` für alle Endpunkte aus

```python
findings = parser.get_findings(testfile, Test())
for finding in findings:
    for endpoint in finding.unsaved_endpoints:
        endpoint.clean()
```

### Tests von API-Parsern

Nicht nur der Parser, sondern auch der Importer sollte getestet werden.
Die Methode `patch` aus `unittest.mock` ist in der Regel nützlich, um API-Antworten zu simulieren.
Es wird dringend empfohlen, sie zu verwenden.

## Weitere möglicherweise betroffene Dateien

### Änderung am Modell

Falls Sie das Modell ändern müssen, z. B. um die Größe einer Datenbankspalte zu erhöhen, damit eine längere Zeichenkette gespeichert werden kann
* Ändern Sie, was Sie in `dojo/models.py` benötigen
* Erstellen Sie eine neue Migrationsdatei in dojo/db_migrations, indem Sie Folgendes ausführen, und nehmen Sie sie in Ihren PR auf

    {{< highlight bash >}}
    $ docker compose exec uwsgi bash -c 'python manage.py makemigrations -v2'
    {{< /highlight >}}

### Einen anderen Dateityp zum Hochladen akzeptieren

Wenn Sie für Ihren Parser einen neuen Dateityp akzeptieren möchten, schauen Sie sich `dojo/forms.py` um Zeile 436 (Stand dieses Textes) an, oder suchen Sie die 2 Stellen (für Import und Re-Import), an denen der String `attrs={"accept":` vorkommt.

Aktuell akzeptierte Formate: .xml, .csv, .nessus, .json, .html, .js, .zip.

### Wenn mehr als nur die parser.py benötigt wird

Natürlich hindert Sie nichts daran, mehr Dateien als die Datei `parser.py` zu haben. Es ist schließlich Python :-)

## Beispiele für Pull Requests

Wenn Sie sich frühere Parser ansehen möchten, die inzwischen Teil von DefectDojo sind, schauen Sie sich https://github.com/DefectDojo/django-DefectDojo/pulls?q=is%3Apr+sort%3Aupdated-desc+label%3A%22Import+Scans%22+is%3Aclosed an

## Aktualisieren der Dokumentation der Import-Seite

Bitte fügen Sie eine neue .md-Datei in [`docs/content/en/connecting_your_tools/parsers`] mit den Details zu Ihrem neuen Parser hinzu. Fügen Sie folgende Inhaltsüberschriften ein:

* Akzeptierte(r) Dateityp(en) - bitte geben Sie an, wie dieser Dateityp aus dem betreffenden Tool erzeugt wird, da manche Tools mehrere Methoden bieten oder bestimmte Befehle erfordern.
* Ein Beispiel-Unit-Test-Block, falls zutreffend.
* Ein Link zum entsprechenden Unit-Tests-Ordner, damit Nutzer von der Dokumentation aus schnell dorthin navigieren können.
* Ein Link zum Scanner selbst - (z. B. GitHub- oder Anbieterlink)

Hier ist ein Beispiel für eine vollständige Parser-Dokumentationsseite: [https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md)
