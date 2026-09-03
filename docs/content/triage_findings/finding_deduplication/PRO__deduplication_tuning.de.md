---
title: Deduplizierungs-Tuning
description: Konfigurieren Sie, wie DefectDojo doppelte Befunde erkennt und verwaltet
weight: 4
audience: pro
aliases:
- /de/en/working_with_findings/finding_deduplication/tune_deduplication
---

Deduplizierungs-Tuning ist eine DefectDojo-Pro-Funktion, die Ihnen eine feingranulare Kontrolle darüber gibt, wie Befunde dedupliziert werden, sodass Sie die Duplikaterkennung für Ihren spezifischen Sicherheitstest-Workflow optimieren können.

## Deduplizierungseinstellungen

In DefectDojo Pro erreichen Sie das Deduplizierungs-Tuning über:
**Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** bei Instanzen, die noch das vorherige Menülayout verwenden)

![image](images/deduplication_tuning.png)

Die Seite mit den Deduplizierungseinstellungen bietet drei zentrale Konfigurationsbereiche:
- Same Tool Deduplication
- Cross Tool Deduplication
- Reimport Deduplication

## Same Tool Deduplication

Same Tool Deduplication ist standardmäßig für alle Parser von Sicherheitstools aktiviert. Dadurch wird sichergestellt, dass Befunde aus aufeinanderfolgenden Scans mit demselben Tool korrekt dedupliziert werden.

So passen Sie Same Tool Deduplication an:

1. Wählen Sie ein bestimmtes **Security Tool** aus dem Dropdown-Menü aus
2. Wählen Sie einen **Deduplication Algorithm** aus den verfügbaren Optionen aus

![image](images/same_tool_deduplication.png)

### Verfügbare Deduplizierungsalgorithmen

DefectDojo Pro bietet die folgenden Deduplizierungsmethoden für die Same-Tool-Deduplizierung:

#### Hash Code
Verwendet eine Kombination ausgewählter Felder, um einen eindeutigen Hash zu erzeugen. Bei Auswahl erscheint ein drittes Dropdown-Menü, das die zur Hash-Berechnung verwendeten Felder anzeigt.

##### Content Fingerprint

**Content Fingerprint** ist ein auswählbares Hash-Feld (in allen drei Konfigurationsbereichen verfügbar), das eine *ortsunabhängige* Identität für Befunde aus der statischen Analyse bereitstellt. Es wird aus dem verwundbaren Code-Snippet abgeleitet, das ein Tool im Befund enthält — normalisiert, sodass Einrückung, Zeilennummer-Anmerkungen und Formatierungsunterschiede den Wert nicht verändern. Zwei Befunde zum selben verwundbaren Code ergeben denselben Hash, selbst wenn der Code in eine andere Zeile oder Datei verschoben wurde.

Content Fingerprint wird für Tools berechnet, die ein Code-Snippet in der Befundbeschreibung enthalten — darunter **Bandit**, **Gosec**, **Brakeman**, **Checkmarx One** sowie jedes Tool, dessen Beschreibung einen eingezäunten Codeblock oder ein SARIF-Snippet enthält.

> **Bevor Sie Content Fingerprint als Hash-Feld auswählen**, befüllen Sie die Fingerabdrücke für vorhandene Befunde, indem Sie `./manage.py backfill_fingerprints` ausführen. Befunde, die nach Einführung der Funktion importiert werden, erhalten Fingerabdrücke automatisch, aber bereits vorhandene Befunde haben keine — wählen Sie das Feld ohne vorheriges Backfill aus, ergeben sich für vorhandene und eingehende Befunde unterschiedliche Hashes, wodurch jede Übereinstimmung aufgesplittet wird, bis das Backfill ausgeführt wurde.

Content Fingerprint eignet sich gut in Kombination mit **CWE** für Tools, die Dateipfade oder Zeilennummern in ihre Titel einbetten, wo sich andere Identitätsfelder bei jeder Codeverschiebung ändern. Siehe [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#choosing-hash-fields-for-tracked-tools).

#### Unique ID From Tool
Nutzt die interne Kennung des Sicherheitstools für Befunde und gewährleistet eine perfekte Deduplizierung, wenn der Scanner zuverlässige eindeutige IDs liefert.

Dieser Algorithmus kann bei SAST-Scannern nützlich sein oder in Situationen, in denen sich ein Befund im Quellcode „verschieben“ kann, während die Entwicklung fortschreitet.

#### Unique ID From Tool or Hash Code
Versucht zunächst, die eindeutige ID des Tools zu verwenden, und greift auf den Hash Code zurück, falls keine eindeutige ID verfügbar ist. Dies bietet die flexibelste Deduplizierungsoption.

#### Global Component
Gleicht Befunde anhand von Komponentenname und -version über **alle Produkte** der Instanz hinweg ab, statt innerhalb eines einzelnen Produkts oder Engagements. Gedacht für SCA-Tools, bei denen dieselbe verwundbare Abhängigkeit in vielen Produkten auftritt. Dieser Algorithmus ist standardmäßig deaktiviert und muss vom DefectDojo Support aktiviert werden. Einzelheiten finden Sie unter [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/).

#### Global Vulnerability ID
Gleicht Befunde anhand ihrer **Schwachstellen-IDs** (CVE, GHSA, …) über **alle Produkte** der Instanz hinweg ab, statt innerhalb eines einzelnen Produkts oder Engagements. Gedacht für Tools, die dieselbe CVE in vielen Produkten melden. Standardmäßig deaktiviert und wird vom DefectDojo Support aktiviert.

> **Zwei Tools mit demselben instanzweiten Algorithmus werden zu gegenseitigen Deduplizierungskandidaten.** Wenn zwei *unterschiedliche* Tools beide mit einem instanzweiten Algorithmus (Global Component oder Global Vulnerability ID) konfiguriert sind, teilen sich ihre Befunde einen konstanten Gruppierungs-Hash, sodass ein Befund des einen Tools für die Deduplizierung gegen das andere auf dieser gemeinsamen Dimension (Komponente oder Schwachstellen-ID) berücksichtigt wird. Dies ist das beabsichtigte Cross-Tool-Verhalten — aktivieren Sie es nur, wenn diese Tools gemeinsam deduplizieren sollen.

### Mengenbasierte Hash-Code-Felder (Schwachstellen-IDs und CWEs)

Zwei Befundattribute enthalten eine *Menge* von Werten statt eines einzelnen Werts: Schwachstellen-IDs (CVE, GHSA, …) und CWEs. Bei Verwendung des **Hash Code**-Algorithmus (Same Tool oder Cross Tool) können Sie die folgenden Felder zu **Hash Code Fields** hinzufügen, um zu steuern, wie diese Mengen verglichen werden:

| Feld | Befunde sind Duplikate, wenn … |
|-------|-------------------------------|
| `vulnerability_ids` | sie die **exakt gleiche Menge** an Schwachstellen-IDs haben |
| `vulnerability_ids_partial` | sie sich **mindestens eine** Schwachstellen-ID teilen |
| `vulnerability_ids_subset` | die Schwachstellen-IDs eines Befunds eine **Teilmenge** der des anderen sind |
| `cwes` | sie die **exakt gleiche Menge** an CWEs haben |
| `cwes_partial` | sie sich **mindestens eine** CWE teilen |
| `cwes_subset` | die CWEs eines Befunds eine **Teilmenge** der des anderen sind |

Die Felder `_partial` und `_subset` werden pro Befundpaar verglichen, statt in den Hash eingerechnet zu werden: Die übrigen Hash Code Fields gruppieren die Kandidatenbefunde, und der Mengenvergleich grenzt diese Gruppe anschließend weiter ein. (Der exakte Abgleich — `vulnerability_ids` und `cwes` — wird direkt in den Hash eingerechnet.)

**Leere Werte.** Wenn ein Befund keine Schwachstellen-IDs (oder keine CWEs) für den konfigurierten Matcher hat:

- Wenn die Hash Code Fields zusätzlich ein gewöhnliches Feld enthalten (zum Beispiel `title`), übernimmt dieses Feld die Identität — der Mengen-Matcher wird für dieses Paar übersprungen, und die Befunde können weiterhin über den Rest des Hashes übereinstimmen.
- Wenn ein Mengen-Matcher das **einzige** Feld ist, stimmt ein Befund ohne Werte mit nichts überein: Da nichts anderes zur Identifizierung vorhanden ist, wird eine leere Menge nicht so behandelt, als stimme sie mit jeder anderen Menge überein.

**Konfigurationsregeln** (werden beim Speichern der Einstellungen durchgesetzt):

- Ein Schwachstellen-ID-Feld (`vulnerability_ids`, `vulnerability_ids_partial` oder `vulnerability_ids_subset`) kann allein verwendet werden — eine CVE oder GHSA identifiziert eine konkrete Schwachstelleninstanz.
- CWE-Felder (`cwes`, `cwes_partial`, `cwes_subset`) dürfen **nicht** das alleinige Kriterium sein. Eine CWE ist eine Schwachstellen*klasse*, keine konkrete Instanz, sodass ein Abgleich allein anhand der CWE nicht zusammengehörige Befunde zusammenführen würde. Kombinieren Sie einen CWE-Matcher mit einem identifizierenden Feld wie `title` oder `file_path`.

## Cross Tool Deduplication

Cross Tool Deduplication ist standardmäßig deaktiviert, da die Deduplizierung zwischen unterschiedlichen Sicherheitstools aufgrund von Unterschieden in der Art, wie Tools dieselben Schwachstellen melden, eine sorgfältige Konfiguration erfordert.

![image](images/cross_tool_deduplication.png)

So aktivieren Sie Cross Tool Deduplication:

1. Wählen Sie ein **Security Tool** aus dem Dropdown-Menü aus
2. Ändern Sie den **Deduplication Algorithm** von „Disabled“ auf „Hash Code“
3. Wählen Sie im Dropdown-Menü **Hash Code Fields** aus, welche Felder für die Hash-Erzeugung verwendet werden sollen

Cross Tool Deduplication unterstützt den Hash-Code-Algorithmus, der für die meisten Workflows geeignet ist, da unterschiedliche Tools nur selten kompatible eindeutige Kennungen teilen. Für SCA-Tools, die dieselben Abhängigkeiten melden, steht auch [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) als Cross-Tool-Option zur Verfügung (standardmäßig deaktiviert).

Beachten Sie, dass Cross Tool Deduplication ebenfalls nur auf einzelne Assets beschränkt ist.

## Reimport Deduplication

**⚠️ Reimport-Vorgänge können Befunde vollständig verwerfen, bevor sie erfasst werden. Dies kann bei falscher Einstellung zu Datenverlust führen, weshalb die Reimport-Deduplizierungseinstellungen mit Vorsicht angepasst werden sollten.**

Mit den Reimport-Deduplizierungseinstellungen kann ein Algorithmus für Universal Parser oder für einen Generic Findings Import Parser festgelegt werden.

Reimport Deduplication kann für andere Tools standardmäßig nicht angepasst werden. Benutzer, die den Reimport-Deduplizierungsalgorithmus für andere Tools in ihrer Instanz anpassen möchten, sollten sich an den [DefectDojo Support](mailto:support@defectdojo.com) wenden.

![image](images/reimport_deduplication.png)

Beim Konfigurieren von Reimport Deduplication:

1. Wählen Sie das **Security Tool** aus (Universal oder Generic Parser)
2. Wählen Sie den passenden **Deduplication Algorithm** aus

Für Reimport Deduplication stehen folgende Algorithmusoptionen zur Verfügung:
- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Reimport kann Befunde vollständig verwerfen, bevor sie erfasst werden, weshalb die Reimport-Deduplizierungseinstellungen mit Vorsicht angepasst werden sollten.

### Befunde bei Standortänderungen nachverfolgen

Wenn der Reimport-Deduplizierungsalgorithmus eines Tools **Hash Code** ist, erscheint ein zusätzlicher Schalter: **Track findings as locations change**. Ist dieser aktiviert, wird ein Befund, dessen Standort sich zwischen Reimports verändert hat — eine Zeilenverschiebung oder Dateiumbenennung, ein URL-Wechsel oder eine Erhöhung der Abhängigkeitsversion — als *derselbe* Befund behandelt, selbst wenn das Tool dessen Schweregrad neu bewertet hat. Ein Befund wird an Ort und Stelle beibehalten, und sein Standortverlauf bleibt erhalten, statt dass der alte Befund geschlossen und ein identischer neuer erstellt wird.

Der Schalter ist standardmäßig deaktiviert und gilt nur für den Hash-Code-Reimport-Algorithmus (Tools mit einer zuverlässigen Unique ID From Tool verfolgen Verschiebungen bereits über ihre stabilen IDs). Beim Aktivieren werden die vorhandenen Befunde des Tools automatisch im Hintergrund neu gehasht, sodass historische Daten sofort einbezogen werden.

Wie der Abgleich funktioniert, was dabei erhalten bleibt, und Hinweise zur Aktivierung auf großen Instanzen finden Sie unter [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/).

## Deduplizierung rückwirkend auf vorhandene Daten anwenden

Eine häufige Situation beim erstmaligen Aktivieren des Deduplizierungs-Tunings ist ein großer Bestand an Befunden, die *vor* der Änderung der Dedup-Konfiguration importiert wurden. In DefectDojo Pro müssen Sie keinen separaten Befehl ausführen, um diese historischen Daten zu deduplizieren — **das Ändern der Deduplizierungseinstellungen für ein Tool löst automatisch ein Neu-Hashing aller vorhandenen Befunde dieses Testtyps im Hintergrund aus**.

Was das in der Praxis bedeutet:

- Wenn Sie den **Deduplication Algorithm** oder die **Hash Code Fields** für ein Tool ändern, stellt DefectDojo einen Hintergrundjob in die Warteschlange, der die Hashes für jeden bereits in der Instanz vorhandenen Befund dieses Tools neu berechnet.
- Der Job läuft asynchron. Auf großen Instanzen (Millionen von Befunden) kann dies einige Zeit in Anspruch nehmen, und Sie sehen möglicherweise nicht sofort Änderungen in der Befundtabelle.
- Neu berechnete Hashes gelten für nachfolgende Dedup-Entscheidungen im gesamten Bestand.

Wenn Sie mehrere Konfigurationsänderungen kurz hintereinander vornehmen, stellt jede ihren eigenen Neu-Hashing-Job in die Warteschlange. Lassen Sie den vorherigen Job abschließen, bevor Sie Ergebnisse auswerten, insbesondere wenn Sie die Befundanzahl vor und nach der Änderung vergleichen.

> **Hinweis für selbst gehostetes Pro:** Der Hintergrundjob läuft im Celery-Worker-Pool. Bei ausgehungerten oder überlasteten Workern kann das Neu-Hashing länger dauern als erwartet — prüfen Sie den Zustand der Worker, wenn Ergebnisse nicht innerhalb des für Ihre Instanzgröße erwarteten Zeitrahmens erscheinen.

> **Feature-Flags setzen eine bestehende Konfiguration nicht außer Kraft.** Die gespeicherten Deduplizierungseinstellungen eines Tools bleiben so lange in Kraft, wie sie konfiguriert sind; das Deaktivieren eines zugehörigen Feature-Flags setzt dieses Tool **nicht** rückwirkend auf die Standard-Deduplizierung zurück. Um das Deduplizierungsverhalten eines Tools zu ändern oder zu beenden, aktualisieren Sie dessen Deduplizierungseinstellungen direkt (wodurch ebenfalls das oben beschriebene Neu-Hashing im Hintergrund ausgelöst wird).

## Best Practices für die Deduplizierung

Für optimale Ergebnisse mit dem Deduplizierungs-Tuning:

- **Mit den Standardeinstellungen beginnen**: Die vorkonfigurierten Deduplizierungseinstellungen funktionieren für die meisten Szenarien gut
- **Änderungen sorgfältig testen**: Überwachen Sie nach dem Anpassen der Deduplizierungseinstellungen einige Importe, um korrektes Verhalten sicherzustellen.
- **Rückwirkendes Neu-Hashing einplanen**: Das Ändern der Dedup-Einstellungen hasht jeden vorhandenen Befund dieses Tools im Hintergrund neu. Siehe oben [Deduplizierung rückwirkend auf vorhandene Daten anwenden](#running-deduplication-retroactively-on-existing-data).
- **Hash Code für Cross-Tool-Deduplizierung verwenden**: Wählen Sie beim Aktivieren der Cross-Tool-Deduplizierung Felder aus, die denselben Befund über verschiedene Tools hinweg zuverlässig identifizieren (etwa Schwachstellenname, Standort und Schweregrad). **WICHTIG** Jedes für die Cross-Tool-Deduplizierung aktivierte Tool **MUSS** dieselben Felder ausgewählt haben.
- **Cross-Tool-Quellen im selben Asset halten**: Cross-Tool Deduplication ist auf Asset-Ebene beschränkt. Befunde, die über getrennte Assets verteilt sind, werden auch bei übereinstimmenden Hash-Feldern nicht dedupliziert. Siehe oben [Cross Tool Deduplication](#cross-tool-deduplication).
- **Zu breite Deduplizierung vermeiden**: Cross-Tool-Deduplizierung mit zu wenigen Hash-Feldern kann zu falschen Duplikaten führen
- **Vor Auswahl von Content Fingerprint ein Backfill durchführen**: Führen Sie zuerst `./manage.py backfill_fingerprints` aus und wählen Sie dann das Feld aus — so stehen dem ausgelösten Neu-Hashing bereits Fingerabdrücke zur Verfügung. Siehe oben [Content Fingerprint](#content-fingerprint).
- **Standortverfolgung zwischen Scan-Läufen aktivieren**: Das automatische Neu-Hashing des Schalters umfasst den gesamten Bestand des Tools; lassen Sie es auf großen Instanzen vor dem nächsten geplanten Reimport abschließen. Siehe [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#enabling-on-existing-data-upgrades).

Durch die Anpassung der Deduplizierungseinstellungen an Ihre spezifischen Tools können Sie doppelten Rauschen deutlich reduzieren.

## Gesperrte Befunde 

Immer wenn die Deduplizierungseinstellungen für ein bestimmtes Tool geändert werden, werden die Deduplizierungs-Hashes für dieses Tool über die gesamte DefectDojo-Instanz hinweg neu berechnet.
