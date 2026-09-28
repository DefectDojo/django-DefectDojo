---
title: Deduplizierungs-Tuning
description: 'Deduplizierung in DefectDojo Open Source konfigurieren: Algorithmen,
  Hash-Felder, Endpunkte und Service'
weight: 5
audience: opensource
aliases:
- /de/en/working_with_findings/finding_deduplication/deduplication_tuning_os
- /de/en/working_with_findings/finding_deduplication/deduplication_algorithms
---

Die Open-Source-Edition von DefectDojo verwendet Einstellungsdateien und Umgebungsvariablen, um die Deduplizierung zu optimieren.

Siehe auch: [Open-Source-Konfiguration](/get_started/open_source/configuration/) für Details zu Umgebungsvariablen und Überschreibungen in `local_settings.py`.

## Was Sie konfigurieren können

- **Algorithmus pro Parser**: Wählen Sie zwischen Unique ID From Tool, Hash Code, Unique ID From Tool or Hash Code oder Legacy (nur OS).
- **Hash-Felder pro Scanner**: Legen Sie fest, welche Felder für jeden Parser zum Hash beitragen.
- **Null-CWE zulassen**: Legt fest, ob ein fehlender/nullwertiger CWE beim Hashing akzeptiert wird.
- **Endpunkt-Berücksichtigung**: Verwenden Sie Endpunkte optional für die Deduplizierung, wenn sie nicht Teil des Hashes sind.
- **Immer enthaltene Felder**: Fügen Sie allen Hashes Felder hinzu (z. B. `service`), unabhängig von den scannerspezifischen Einstellungen.

## Wichtige Einstellungen (Standardwerte angezeigt)

Alle Standardwerte sind in `dojo/settings/settings.dist.py` definiert. Überschreiben Sie sie über Umgebungsvariablen oder `local_settings.py`.

### Algorithmus pro Parser

- Einstellung: `DEDUPLICATION_ALGORITHM_PER_PARSER`
- Werte pro Parser: eines von `unique_id_from_tool`, `hash_code`, `unique_id_from_tool_or_hash_code`, `legacy`.
- Beispiel (Umgebungsvariable als JSON-String):

```bash
DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Trivy Scan": "hash_code", "Veracode Scan": "unique_id_from_tool_or_hash_code"}'
```

### Hash-Felder pro Scanner

- Einstellung: `HASHCODE_FIELDS_PER_SCANNER`
- Beispiel-Standardwert für Trivy in OS:

```startLine:endLine:dojo/settings/settings.dist.py
1318:1321:dojo/settings/settings.dist.py
    "Trivy Operator Scan": ["title", "severity", "vulnerability_ids", "description"],
    "Trivy Scan": ["title", "severity", "vulnerability_ids", "cwe", "description"],
    "TFSec Scan": ["severity", "vuln_id_from_tool", "file_path", "line"],
    "Snyk Scan": ["vuln_id_from_tool", "file_path", "component_name", "component_version"],
```

- Beispiel für eine Überschreibung (Umgebungsvariable als JSON-String):

```bash
DD_HASHCODE_FIELDS_PER_SCANNER='{"ZAP Scan":["title","cwe","severity"],"Trivy Scan":["title","severity","vulnerability_ids","description"]}'
```

### Null-CWE pro Scanner zulassen

- Einstellung: `HASHCODE_ALLOWS_NULL_CWE`
- Legt pro Parser fest, ob ein nullwertiger/leerer CWE beim Hashing akzeptabel ist. Ist dies False und der Befund hat `cwe = 0`, fällt der Hash für diesen Befund auf die Legacy-Berechnung zurück.

### Immer im Hash enthaltene Felder

- Einstellung: `HASH_CODE_FIELDS_ALWAYS`
- Standard: `["service"]`
- Auswirkung: Wird für jeden Scanner an den Hash angehängt. Wenn Sie `service` hier entfernen, wirkt es sich nicht mehr durchgängig auf die Hashes aus.

```startLine:endLine:dojo/settings/settings.dist.py
1464:1466:dojo/settings/settings.dist.py
# Adding fields to the hash_code calculation regardless of the previous settings
HASH_CODE_FIELDS_ALWAYS = ["service"]
```

### Optionale endpunktbasierte Deduplizierung

- Einstellung: `DEDUPE_ALGO_ENDPOINT_FIELDS`
- Standard: `["host", "path"]`
- Zweck: Wenn Endpunkte nicht Teil der Hash-Felder sind, können Sie dennoch eine minimale Endpunktübereinstimmung für die Deduplizierung verlangen. Ist die Liste leer `[]`, werden Endpunkte im Dedupe-Pfad ignoriert.

```startLine:endLine:dojo/settings/settings.dist.py
1491:1499:dojo/settings/settings.dist.py
# Allows to deduplicate with endpoints if endpoints is not included in the hashcode.
# Possible values are: scheme, host, port, path, query, fragment, userinfo, and user.
# If a finding has more than one endpoint, only one endpoint pair must match to mark the finding as duplicate.
DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "path"]
```

## Endpunkte: Wie man sie optimiert

Endpunkte können die Deduplizierung über zwei Mechanismen beeinflussen:

1) Nehmen Sie `endpoints` in `HASHCODE_FIELDS_PER_SCANNER` für einen Parser auf. Dann sind Endpunkte Teil des Hashes und müssen gemäß den Hashing-Regeln des Parsers exakt übereinstimmen.
2) Wenn Endpunkte nicht in den Hash-Feldern enthalten sind, verwenden Sie `DEDUPLE_ALGO_ENDPOINT_FIELDS`, um die zu vergleichenden Attribute festzulegen. Beispiele:
   - `[]`: Endpunkte werden für die Deduplizierung ignoriert.
   - `["host"]`: Befunde werden dedupliziert, wenn ein Endpunktpaar anhand des Hosts übereinstimmt.
   - `["host", "port"]`: Befunde werden dedupliziert, wenn ein Endpunktpaar anhand von Host UND Port übereinstimmt.

Hinweise:

- Beim Legacy-Algorithmus gelten für statische und dynamische Befunde unterschiedliche Regeln zur Endpunktübereinstimmung (siehe die Seite zu den Algorithmen). Die Einstellung `DEDUPLE_ALGO_ENDPOINT_FIELDS` gilt für den Hash-Code-Pfad, nicht für die intrinsische Logik des Legacy-Algorithmus.
- Bei der (ID-basierten) Übereinstimmung mit `unique_id_from_tool` werden Endpunkte für die Dedupe-Entscheidung ignoriert.

## Service-Feld: Deduplizierung und Reimport

- Mit dem Standardwert `HASH_CODE_FIELDS_ALWAYS = ["service"]` wird das Feld `service` an den Hash angehängt. Zwei ansonsten gleiche Befunde mit unterschiedlichen `service`-Werten werden auf hashbasierten Pfaden nicht dedupliziert.
- Beim Import über UI/API kann das Eingabefeld `Service` den vom Parser bereitgestellten Service überschreiben. Eine Änderung ändert den Hash und kann das Dedupe-Verhalten sowie den Reimport-Abgleich beeinflussen.
- Wenn Sie die Deduplizierung unabhängig vom Service haben möchten, entfernen Sie `service` aus `HASH_CODE_FIELDS_ALWAYS` oder lassen Sie das Feld `Service` beim Import leer.

## Nach dem Ändern der Deduplizierungseinstellungen

Nach dem Ändern von Algorithmen oder der Hash-Berechnung müssen Sie die Hashes für den betroffenen Parser/Testtyp **neu berechnen**, bevor das neue Abgleichverhalten durchgängig auf bestehende Daten angewendet wird.

Hinweis: Die Neuberechnung von Hashes kann bei großen Instanzen zu langen Wartezeiten führen. Planen Sie Wartungsfenster entsprechend ein.

- Änderungen an der Dedupe-Konfiguration (z. B. `HASHCODE_FIELDS_PER_SCANNER`, `HASH_CODE_FIELDS_ALWAYS`, `DEDUPLICATION_ALGORITHM_PER_PARSER`) werden nicht automatisch rückwirkend angewendet. Um bestehende Befunde neu zu bewerten, müssen Sie den unten stehenden Management-Befehl ausführen.

### Dedup für einen Bestand an vorhandenen Daten ausführen

Wenn Sie die Dedupe-Einstellungen zum ersten Mal konfigurieren (oder sie später ändern), behalten Befunde, die vor der Änderung importiert wurden, ihre alten Hashes, bis Sie Dedupe explizit erneut ausführen.  Verwenden Sie den Management-Befehl `dedupe`, um bestehende Befunde neu zu hashen und/oder neu zu bewerten.

Innerhalb des uwsgi-Containers ausführen. Beispiel (nur Hash-Codes, keine Deduplizierung):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --hash_code_only"
```

Um für alle Parser **Hashes neu zu berechnen und Dedupe auszuführen** (der typische Workflow „I just turned on dedup and want to clean up the backlog"):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe"
```

Um nur einen bestimmten Parser anzusprechen:

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --parser 'Trivy Scan'"
```

Hilfe/Verwendung:
```
options:
  --parser PARSER       List of parsers for which hash_code needs recomputing
                        (defaults to all parsers)
  --hash_code_only      Only compute hash codes
  --dedupe_only         Only run deduplication
  --dedupe_sync         Run dedupe in the foreground, default false
```

Wenn Sie Dedupe an Celery übergeben (ohne `--dedupe_sync`), lassen Sie den Tasks Zeit, um abzuschließen, bevor Sie die Ergebnisse auswerten.  Bei großen Instanzen kann dies erheblich viel Zeit in Anspruch nehmen — überwachen Sie die Celery-Worker-Logs, um den Fortschritt zu verfolgen.

## Wo konfiguriert wird

- Bevorzugen Sie in Deployments Umgebungsvariablen. Verwenden Sie für die lokale Entwicklung oder erweiterte Überschreibungen `local_settings.py`.
- Siehe `configuration.md` für Details zum Setzen von Umgebungsvariablen und zur Konfiguration lokaler Überschreibungen.

### Fehlerbehebung

Verwenden Sie die folgenden Tools, um die Fehlerbehebung bei der Deduplizierung zu unterstützen:

- Beobachten Sie die Log-Ausgabe in der Kategorie `dojo.specific-loggers.deduplication`. Dies ist ein klassenunabhängiger Logger, der beim Verarbeiten von Befunden Details zum Deduplizierungsprozess und den Einstellungen ausgibt.
- Beobachten Sie die Werte von `unique_id_from_tool` und `hash_code`, indem Sie mit der Maus über das Feld `ID` oder die Spalte `Status` fahren:

![Unique ID From Tool und Hash Code auf der Seite "Befund anzeigen"](images/hash_code_id_field.png)

![Unique ID From Tool und Hash Code in der Status-Spalte der Befundliste](images/hash_code_status_column.png)
