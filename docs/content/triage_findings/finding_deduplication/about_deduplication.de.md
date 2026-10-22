---
title: Über Deduplizierung
description: Grundlagen und Schlüsselkonzepte der Deduplizierung
weight: 1
aliases:
- /de/en/working_with_findings/finding_deduplication/about_deduplication
- /de/en/working_with_findings/finding_deduplication/delete_deduplicates
- /de/en/working_with_findings/findings_workflows/manage_duplicate_findings
---

DefectDojo ist darauf ausgelegt, Massenberichte von Tools zu importieren und basierend auf dem Inhalt des Berichts einen oder mehrere Befunde zu erstellen. Bei der Verwendung von DefectDojo werden Sie höchstwahrscheinlich regelmäßig Berichte desselben Tools importieren, wodurch doppelte Befunde sehr wahrscheinlich sind. 

Hier kommt die Deduplizierung ins Spiel, eine intelligente Funktion, die Sie einrichten können, um doppelte Befunde automatisch zu verwalten.

## Wie DefectDojo mit Duplikaten umgeht

1. Zuerst importieren Sie **Test 1\.** Ihr Bericht enthält eine Schwachstelle, die als Befund A erfasst wird.
2. **Später importieren Sie Test 2, der dieselbe Schwachstelle enthält. Dies wird als Befund B erfasst, und Befund B wird als Duplikat von Befund A markiert.**
3. Noch später importieren Sie **Test 3**, der ebenfalls diese Schwachstelle enthält. Dies wird als Befund C erfasst, der als Duplikat von Befund A markiert wird.

Durch das Erstellen und Markieren von Duplikaten auf diese Weise stellt DefectDojo sicher, dass die gesamte Arbeit für die „ursprüngliche“ Schwachstelle auf der Seite des Original-Befunds zentralisiert wird, ohne separate Kontexte zu erzeugen oder Ihrem Team den Eindruck zu vermitteln, dass mehrere separate Schwachstellen behoben werden müssen.

### Welcher Befund wird zum Original

Die Deduplizierung behandelt in einer Duplikatkette immer den **zuerst erstellten** Befund als das maßgebliche Original, sodass ein Befund aus einem früheren Import niemals zu einem Duplikat eines neueren Befunds herabgestuft wird — ein bereits etabliertes Original wechselt nicht den Besitzer.

Innerhalb *eines einzelnen* Berichts entscheidet die Reihenfolge, in der der Scanner seine Befunde zufällig auflistet, nicht darüber, welcher gewinnt. Befunde aus einem Import werden in einer stabilen, aus dem Inhalt abgeleiteten Reihenfolge erstellt, sodass ein Bericht, der mehrere Befunde enthält, die auf denselben Deduplizierungsschlüssel treffen, **bei jedem Import dasselbe Original** erzeugt. Erneutes Scannen und erneutes Importieren derselben Ergebnisse vertauscht nicht, an welchem Befund Ihr Team gearbeitet hat.

Standardmäßig müssten diese Tests unter demselben Produkt verschachtelt sein, damit die Deduplizierung angewendet wird. Falls gewünscht, können Sie den Deduplizierungsbereich weiter auf ein einzelnes Engagement beschränken.

![Deduplizierung auf Produkt- und Engagement-Ebene](images/deduplication.png)

Doppelte Befunde werden standardmäßig auf Inaktiv gesetzt. Das bedeutet nicht, dass der doppelte Befund selbst inaktiv ist. Vielmehr soll dadurch sichergestellt werden, dass Ihr Team nur an einem einzigen aktiven Befund arbeitet und diesen behebt, mit der Konsequenz, dass die Duplikate ebenfalls als Behoben markiert werden, sobald der Original-Befund Behoben ist.

## Reimport-Deduplizierung

Deduplizierung und Reimport sind ähnliche Prozesse, verwenden jedoch unterschiedliche Algorithmen, um übereinstimmende Befunde zu identifizieren.

* Wenn Sie einen Reimport in einen Test durchführen, betrachtet der Reimport-Prozess eingehende Befunde, **vergleicht Hash-Codes und verwirft dann alle Übereinstimmungen**. Diese Übereinstimmungen werden niemals als Befunde oder doppelte Befunde erstellt.

Alle Befunde, die nach der Reimport-Deduplizierung übrig bleiben, unterliegen jedoch weiterhin der Same-Tool-Deduplizierung. Wenn Sie also für die Same-Tool-Deduplizierung einen engeren Geltungsbereich verwenden, können innerhalb einer Reimport-Pipeline dennoch Duplikate entstehen.

### Beispiel

Hier ist ein Tool mit einem Reimport-Deduplizierungsalgorithmus, der sich vom Same-Tool-Deduplizierungsalgorithmus unterscheidet.

| Deduplizierungsalgorithmus | Hash-Code-Felder |
| ----- | ---- |
| Reimport | Title, CWE, Severity, Description, Line Number |
| Same-Tool | Title, CWE, Severity, Description |

Angenommen, Sie hatten einen Befund in DefectDojo mit einer bestimmten Zeilennummer. Sie haben Ihre Umgebung erneut gescannt, und die Zeilennummer dieser Schwachstelle hat sich geändert. Sie führen einen Reimport in denselben Test durch. Hier ist, was während des Reimports und der Deduplizierung passiert:

* Während des Reimports wird der Befund keinem bereits vorhandenen Befund zugeordnet, da sich die Zeilennummer unterscheidet. Daher wird ein neuer Befund im Test erstellt.
* Nach Abschluss des Reimports wird der Same-Tool-Deduplizierungsalgorithmus ausgeführt. Die Same-Tool-Deduplizierung berücksichtigt in dieser Konfiguration keine Zeilennummer, sodass der neue Befund als Duplikat gekennzeichnet wird.

Der Reimport kann Befunde vollständig verwerfen, bevor sie erfasst werden. Daher sollten die Einstellungen der Reimport-Deduplizierung mit Vorsicht angepasst werden.

## Wann sind Duplikate sinnvoll?

Duplikate sind nützlich, wenn Sie es mit gemeinsamen, aber eigenständigen Testkontexten zu tun haben. Wenn Ihr Produkt beispielsweise Testergebnisse für zwei verschiedene Repositories hochlädt, die verglichen werden müssen, ist es hilfreich zu wissen, welche Schwachstellen in beiden Repositories vorkommen.

Wenn DefectDojo jedoch übermäßig viele Duplikate erzeugt, kann dies auch ein Zeichen dafür sein, dass Sie Ihre Pipelines oder Importprozesse anpassen müssen.

## Was sagen meine Duplikate aus?

* **Dieselbe Schwachstelle, aber in einem anderen Kontext gefunden:** Dies ist die geeignete Art, doppelte Befunde zu verwenden. Wenn viele Komponenten von derselben Schwachstelle betroffen sind, möchten Sie wahrscheinlich wissen, welche Komponenten betroffen sind, um das Ausmaß des Problems zu verstehen.  
​
* **Dieselbe Schwachstelle, im selben Kontext gefunden**: Für diesen Fall gibt es bessere Optionen. Wenn der doppelte Befund Ihnen keinen neuen Kontext zur Schwachstelle liefert oder Sie feststellen, dass Sie Ihre doppelten Befunde häufig ignorieren oder löschen, ist dies ein Zeichen dafür, dass Ihr Prozess verbessert werden kann. Reimport ermöglicht es Ihnen beispielsweise, eingehende Berichte aus einer CI/CD-Pipeline effektiv zu verwalten. Anstatt für jedes Duplikat ein komplett neues Befundobjekt zu erstellen, vermerkt Reimport das eingehende Duplikat, ohne den doppelten Befund überhaupt zu erstellen.

## Überblick

DefectDojo Open Source unterstützt vier Deduplizierungsalgorithmen, die pro Parser (Testtyp) ausgewählt werden können:

- **Unique ID From Tool**: Verwendet die vom Scanner bereitgestellte eindeutige ID.
- **Hash Code**: Verwendet einen konfigurierten Satz von Feldern, um einen Hash zu berechnen.
- **Unique ID From Tool or Hash Code**: Bevorzugt die eindeutige ID des Tools; greift auf den Hash zurück, wenn keine passende eindeutige ID gefunden wird.
- **Legacy**: Historischer Algorithmus mit mehreren Bedingungen; nur in der Open-Source-Version verfügbar.

**DefectDojo Pro bietet mehr.** Zwei zusätzliche Algorithmen finden Übereinstimmungen über **alle Produkte** der Instanz hinweg statt innerhalb eines einzelnen Produkts oder Engagements — **Global Component** (nach Komponentenname und -version) und **Global Vulnerability ID** (nach CVE, GHSA, …). Beide sind standardmäßig deaktiviert und werden vom DefectDojo-Support aktiviert. Pro erlaubt es dem Hash-Code-Algorithmus außerdem, die Schwachstellen-IDs und CWEs eines Befunds als **Mengen** zu behandeln, wobei die genaue Menge, ein beliebiger gemeinsamer Wert (`_partial`) oder die Eigenschaft, dass eine Menge eine Teilmenge der anderen ist (`_subset`), abgeglichen wird. Die vollständige Liste, die mengenbasierten Felder und die dafür geltenden Regeln finden Sie unter [Deduplication Tuning (Pro)](/triage_findings/finding_deduplication/pro__deduplication_tuning/).

### Eine Alternative zur Deduplizierung: False Positive History

Instanzen, die bewusst **nicht** deduplizieren, können stattdessen [False Positive History](/triage_findings/finding_deduplication/false_positive_history/) verwenden, die einen eingehenden Befund automatisch als Falsch-positiv markiert, wenn ein übereinstimmender Befund im selben Produkt bereits so eingestuft wurde. Sie schließt sich **gegenseitig mit der Deduplizierung aus** — DefectDojo erlaubt es nicht, beide gleichzeitig zu aktivieren — und ist weiterhin als experimentell gekennzeichnet.

## Wie Endpunkte pro Algorithmus bewertet werden

Endpunkte können die Deduplizierung je nach Algorithmus und Konfiguration auf unterschiedliche Weise beeinflussen.

### Unique ID From Tool

- Die Deduplizierung verwendet `unique_id_from_tool` (oder `vuln_id_from_tool`).
- **Endpunkte werden ignoriert**, wenn nach Duplikaten gesucht wird.
- Der Hash eines Befunds kann für andere Funktionen weiterhin berechnet werden, wirkt sich bei diesem Algorithmus jedoch nicht auf die Deduplizierung aus.

### Hash Code

- Die Deduplizierung verwendet einen Hash, der aus den in `HASHCODE_FIELDS_PER_SCANNER` für den jeweiligen Parser angegebenen Feldern berechnet wird.
- Der Hash enthält außerdem Felder aus `HASH_CODE_FIELDS_ALWAYS` (siehe Abschnitt „Service-Feld“ weiter unten).
- Endpunkte können die Deduplizierung auf zwei Arten beeinflussen:
  - Wenn die Hash-Felder des Scanners `endpoints` enthalten, sind sie Teil des Hashs und müssen entsprechend übereinstimmen.
- Wenn die Hash-Felder des Scanners `endpoints` nicht enthalten, kann ein optionaler endpunktbasierter Abgleich über `DEDUPE_ALGO_ENDPOINT_FIELDS` (OS-Einstellung) aktiviert werden. Bei entsprechender Konfiguration:
    - Setzen Sie sie auf eine leere Liste `[]`, um Endpunkte vollständig zu ignorieren.
    - Setzen Sie sie auf eine Liste von Endpunkt-Attributen (z. B. `["host", "port"]`). Wenn mindestens ein Endpunktpaar zwischen den beiden Befunden bei allen aufgeführten Attributen übereinstimmt, kann eine Deduplizierung erfolgen.

### Unique ID From Tool or Hash Code
Ein Befund ist ein Duplikat eines anderen, wenn beide dieselbe unique_id_from_tool ODER denselben hash_code haben.

Damit die Befunde als Duplikate gelten, müssen außerdem die Endpunkte übereinstimmen, siehe den Hash-Code-Algorithmus oben.

### Legacy (Open Source only)

- Die Deduplizierung berücksichtigt mehrere Attribute, einschließlich Endpunkte.
- Das Verhalten unterscheidet sich bei statischen und dynamischen Befunden:
  - **Statische Befunde**: Der neue Befund muss alle Endpunkte des Originals enthalten. Zusätzliche Endpunkte beim neuen Befund sind zulässig.
  - **Dynamische Befunde**: Endpunkte müssen exakt übereinstimmen (üblicherweise nach Host und Port); abweichende Endpunkte verhindern die Deduplizierung.
- Wenn keine Endpunkte vorhanden sind und sowohl `file_path` als auch `line` leer sind, findet in der Regel keine Deduplizierung statt.

## Hintergrundverarbeitung

- Die Deduplizierung wird beim Import/Reimport sowie bei bestimmten Updates ausgelöst, die im Hintergrund über Celery ausgeführt werden.

### Ausführungsmodus der Import-/Reimport-Deduplizierung

Für Import und Reimport können Sie steuern, wie die Deduplizierungs-Nachbearbeitung eingeplant wird und ob die API-Antwort darauf wartet. Legen Sie dies pro Benutzer auf der Profilseite fest (**Deduplication execution mode**), oder überschreiben Sie es pro Anfrage mit dem Feld `deduplication_execution_mode` an den Import-/Reimport-Endpunkten (der Wert der Anfrage hat Vorrang vor dem Profil).

- `async` (Standard): Die Deduplizierung und der Rest der Nachbearbeitung laufen im Hintergrund, und die Antwort wird sofort zurückgegeben. Dies ist das historische Verhalten; die Antwort wird erzeugt, bevor die Befunde dedupliziert sind.
- `async_wait`: Die Nachbearbeitung wird weiterhin an den Hintergrund übergeben, aber die Anfrage wartet, bis die Deduplizierung abgeschlossen ist, bevor sie antwortet. Die `scan_added`-Benachrichtigung und die Statistiken in der Antwort spiegeln dann den deduplizierten Zustand wider (Befunde, die sich als Duplikate herausstellen, werden nicht mehr als neu gezählt/aufgeführt). JIRA-Push, Produktbewertung und andere Aufgaben außerhalb der Deduplizierung bleiben asynchron und werden nicht abgewartet. Die Wartezeit ist durch `DD_DEDUPLICATION_ASYNC_WAIT_TIMEOUT` begrenzt (Standard `60` Sekunden); übernimmt kein Worker die Arbeit rechtzeitig, antwortet die Anfrage trotzdem, anstatt zu blockieren.
- `sync`: Die Import-Deduplizierung läuft direkt innerhalb der Web-Anfrage.

Die Import-/Reimport-Antwort enthält einen booleschen Wert `deduplication_complete`, der angibt, ob die Deduplizierung zum Zeitpunkt der Antworterstellung bereits abgeschlossen war (`true` bei `sync` und bei einem abgeschlossenen `async_wait`, `false` bei `async`).

Dies ist unabhängig von der globalen Profil-Flag `block_execution`, die **alle** asynchronen Aufgaben eines Benutzers (Benachrichtigungen, JIRA-Push, Produktbewertung, Deduplizierung, ...) in den Vordergrund zwingt. Wenn kein Ausführungsmodus festgelegt ist, greift `block_execution=True` auf `sync` zurück.

## Das Service-Feld und seine Auswirkung

- Standardmäßig gilt `HASH_CODE_FIELDS_ALWAYS = ["service"]`, was bedeutet, dass der mit einem Befund verknüpfte `service` bei allen Scannern an den Hash angehängt wird.
- Praktische Auswirkungen:
  - Zwei ansonsten identische Befunde mit unterschiedlichen `service`-Werten erzeugen unterschiedliche Hashes und werden bei hash-basierten Verfahren nicht dedupliziert.
  - Während des Imports/Reimports kann das in der Benutzeroberfläche eingegebene Feld `Service` den vom Parser bereitgestellten Service überschreiben. Eine Änderung kann den Hash und damit das Deduplizierungsergebnis beeinflussen.
  - Wenn der Service keine Auswirkung auf die Deduplizierung haben soll, konfigurieren Sie `HASH_CODE_FIELDS_ALWAYS` entsprechend (siehe die OS-Tuning-Seite). Entfernen Sie `service` aus der stets enthaltenen Liste, damit er die Hashes nicht mehr beeinflusst.

## Delete Deduplicate Findings

Wenn Sie eine übermäßige Anzahl doppelter Befunde haben, die Sie löschen möchten, können Sie **Delete Deduplicate Findings** als Option in den **System Settings** aktivieren.

**Delete Deduplicate Findings** ermöglicht es DefectDojo in Kombination mit dem Feld **Maximum Duplicates**, die Anzahl der gespeicherten doppelten Befunde zu begrenzen. Wenn dieses Feld aktiviert ist, behält DefectDojo nur eine bestimmte Anzahl doppelter Befunde.

### Welche Duplikate werden gelöscht?

Der Original-Befund wird niemals automatisch aus DefectDojo gelöscht. Sobald jedoch der Schwellenwert für Maximum Duplicates überschritten wird, löscht DefectDojo automatisch den ältesten doppelten Befund.

Angenommen, Sie hätten das Feld Maximum Duplicates auf „1“ gesetzt.

1. Zuerst importieren Sie **Test 1\.** Ihr Bericht enthält eine Schwachstelle, die als Befund A erfasst wird.
2. **Später importieren Sie Test 2, der dieselbe Schwachstelle enthält. Dies wird als Befund B erfasst, und Befund B wird als Duplikat von Befund A markiert.**
3. Noch später importieren Sie **Test 3**, der ebenfalls diese Schwachstelle enthält. Dies wird als Befund C erfasst, der als Duplikat von Befund A markiert wird. Zu diesem Zeitpunkt wird Befund B aus DefectDojo gelöscht, da der Schwellenwert für Maximum Duplicates überschritten wurde.

### Anwenden dieser Einstellung

Das Aktivieren von **Delete Deduplicate Findings** startet sofort einen Löschvorgang. Diese Einstellung kann auf der Seite **System Settings** vorgenommen werden. Weitere Informationen finden Sie unter Enabling Deduplication.

## Fehlerbehebung bei der Deduplizierung

Manchmal funktioniert die Deduplizierung nicht wie erwartet. Im Folgenden finden Sie einige Beispiele dafür, wie die Deduplizierung möglicherweise nicht korrekt funktioniert, sowie mögliche Lösungen.

| Was Sie sehen | Wahrscheinlichste Ursache | Was angepasst werden sollte |
| --- | --- | --- |
| Der Reimport schließt einen alten Befund und erstellt einen neuen, obwohl sich nur die Zeilennummer geändert hat | Der Reimport-Abgleich verwendet instabile Felder (z. B. Zeilennummer) | <strong>Reimport Deduplication</strong> (stabile IDs oder stabile Hash-Felder bevorzugen) |
| Im selben Test werden mehrere Befunde erstellt, die Ihrer Meinung nach Duplikate sein sollten | Der Deduplizierungsabgleich ist für dieses Tool oder diesen Geltungsbereich nicht konfiguriert | <strong>Same Tool Deduplication</strong> (und das Verhalten von „Delete Deduplicate Findings“ berücksichtigen) |
| Es werden Duplikate über verschiedene Tools hinweg erstellt | Der Tool-übergreifende Abgleich ist deaktiviert oder zu strikt | <strong>Cross Tool Deduplication (Pro only)</strong> (hash-basierter Abgleich) |
| Dieselbe SCA-Abhängigkeit, die in mehrere Produkte importiert wird, erzeugt separate Befunde statt Duplikate | Die Deduplizierung ist standardmäßig auf das jeweilige Produkt beschränkt | <strong>Global Component Deduplication (Pro only)</strong> ([für Ihre SCA-Tools aktivieren](/triage_findings/finding_deduplication/pro__global_component_deduplication/)), oder, im Locations-Datenmodell, <strong>Global Locations Deduplication (Pro only)</strong> ([Abgleich anhand des gemeinsamen Standorts](/triage_findings/finding_deduplication/pro__global_locations_deduplication/)) |
| Derselbe URL-/Web-Befund, der in mehrere Produkte importiert wird, erzeugt separate Befunde statt Duplikate | Die Deduplizierung ist standardmäßig auf das jeweilige Produkt beschränkt, und Global Component gleicht nur Komponenten ab | <strong>Global Locations Deduplication (Pro only)</strong> ([DAST-/URL-Befunde produktübergreifend abgleichen](/triage_findings/finding_deduplication/pro__global_locations_deduplication/)) |
| Es werden testübergreifend übermäßig viele Duplikate desselben Befunds erstellt | Die Asset-Hierarchie ist nicht korrekt eingerichtet | [Reimport für fortlaufendes Testen in Betracht ziehen](/triage_findings/finding_deduplication/avoid_excess_duplicates/) |

Wenn die automatische Deduplizierung Befunde übersieht, die Ihrer Meinung nach zusammengehören, können Sie diese manuell über die Seite View Finding verknüpfen. Unter Similar Findings erfahren Sie, wie Sie verwandte Befunde finden und manuell als Duplikate markieren können ([Open Source](/triage_findings/finding_deduplication/os__similar_findings/) | [Pro](/triage_findings/finding_deduplication/pro__similar_findings/)).
