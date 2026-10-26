---
title: Import aus GitHub Actions
description: Importieren Sie Scan-Ergebnisse aus einem GitHub Actions-Workflow mit
  der offiziellen DefectDojo-Action
weight: 3
---

Die offizielle [DefectDojo-Action](https://github.com/DefectDojo/defectdojo-action) importiert einen Scan-Bericht aus einem GitHub Actions-Workflow in DefectDojo. Sie funktioniert mit DefectDojo Pro und der Open-Source-Edition und liest jedes von DefectDojo unterstützte Berichtsformat, einschließlich SARIF.

Jeder Lauf führt einen Reimport in denselben Test durch. Befunde, die der Scanner nicht mehr meldet, werden daher geschlossen, und jeder Befund behält seinen Verlauf. Die Action erfasst Build, Branch, Commit und Repository im Test und kann den Workflow-Schritt fehlschlagen lassen, wenn Befunde mit einem gewählten Schweregrad aktiv bleiben.

## Bevor Sie beginnen

1. Erstellen Sie einen API v2-Schlüssel für einen Benutzer, der in das Asset importieren darf (und es anlegen darf, wenn Sie die Action Assets erstellen lassen). Den Schlüssel finden Sie im Benutzermenü unter **API v2 Token** (in der Open-Source-Oberfläche unter **API v2 Key**).
2. Fügen Sie den Schlüssel im GitHub-Repository als Secret mit dem Namen `DEFECTDOJO_API_TOKEN` unter **Settings > Secrets and variables > Actions** hinzu.

## Die Action zu einem Workflow hinzufügen

Führen Sie Ihren Scanner aus und übergeben Sie dessen Bericht anschließend an die Action:

```yaml
name: Security scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Scan
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy.json
      - name: Import into DefectDojo
        uses: DefectDojo/defectdojo-action@v1
        with:
          defectdojo-url: https://defectdojo.example.com
          api-token: ${{ secrets.DEFECTDOJO_API_TOKEN }}
          file: trivy.json
          scan-type: Trivy Scan
          fail-on: critical
```

`scan-type` ist der Name des Berichtsformats, wie DefectDojo es auflistet, zum Beispiel `SARIF`, `Trivy Scan` oder `Semgrep JSON Report`. Alle Namen finden Sie unter [Unterstützte Tools](/supported_tools/).

## Wohin die Befunde gelangen

Sofern Sie nichts anderes festlegen, verwendet die Action Namen aus dem Repository und legt alle an, die noch nicht existieren:

| DefectDojo-Objekt | Standardwert | Eingabe |
| --- | --- | --- |
| Organization (Produkttyp) | Eigentümer des Repositorys | `organization-name` oder `product-type-name` |
| Asset (Produkt) | Name des Repositorys | `asset-name` oder `product-name` |
| Engagement | Branch-Name | `engagement-name` |
| Test | Scan-Typ | `test-title` |

Wenn ein Engagement mehrere Berichte desselben Scan-Typs erhält, vergeben Sie für jeden einen eigenen `test-title`, damit jeder Reimport seinen eigenen Test findet.

### Branches, Pull Requests und Tags

Jeder Branch erhält ein eigenes Engagement, sodass der Scan eines Pull Requests nie Befunde auf dem Standard-Branch schließt oder wiedereröffnet. Pull Requests verwenden ihren Quell-Branch, Tags verwenden den Tag-Namen, und die Merge Queue verwendet ein Engagement pro Basis-Branch.

Engagements, die die Action für einen anderen Branch als den Standard-Branch anlegt, werden nur innerhalb ihrer selbst dedupliziert (**Deduplizierung nur innerhalb dieses Engagements**). Ohne diese Einstellung würde ein Befund, der zuerst auf einem Branch auftaucht, die Kopie auf dem Standard-Branch als Duplikat markieren. Wenn Sie `engagement-name` oder `deduplication-on-engagement` selbst setzen, wird dies abgeschaltet, sodass ein von Ihnen benanntes Engagement wie üblich über das gesamte Asset hinweg dedupliziert. Branch-Engagements bleiben nach dem Merge des Branches in DefectDojo erhalten. Führen Sie den Import daher nur auf dem Standard-Branch aus, wenn sie nicht in die Zählungen des Assets einfließen sollen.

## Den Build fehlschlagen lassen

Setzen Sie `fail-on` auf `low`, `medium`, `high` oder `critical`, damit der Schritt fehlschlägt, wenn der Test nach dem Import aktive Befunde mit diesem oder einem höheren Schweregrad enthält. Duplikate zählen nicht mit. Die Job-Zusammenfassung zeigt die Anzahl nach Schweregrad und einen Link zum Test.

## Pro-Funktionen

In DefectDojo Pro kann die Action zusätzlich:

- Neue Befunde an die für das Asset eingerichteten Connectors übertragen (`push-to-connector: true`).
- Große Berichte im Hintergrund importieren (`background-import: true`). Die Action wartet, bis der Test die Verarbeitung abgeschlossen hat, bevor sie Zählungen meldet oder `fail-on` anwendet.
- Warnen, wenn ein Asset umbenannt oder verschoben wurde, damit Sie die Namen im Workflow aktualisieren können.

In der Open-Source-Edition werden `push-to-connector` und `background-import` mit einer Warnung übersprungen, und der Import läuft trotzdem durch. Setzen Sie `strict: true`, damit stattdessen der Schritt fehlschlägt.

## Pull Requests aus Forks

GitHub stellt Workflows, die bei Pull Requests aus Forks laufen, keine Secrets zur Verfügung. Die Action kann sich dort daher nicht authentifizieren, und der Schritt schlägt fehl. Führen Sie den Import bei `push` aus oder überspringen Sie ihn für Pull Requests aus Forks:

```yaml
      - name: Import into DefectDojo
        if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
        uses: DefectDojo/defectdojo-action@v1
```

Verwenden Sie `pull_request_target` nicht, um dies zu umgehen: Es läuft mit Ihren Secrets, während Code ausgecheckt wird, den Sie nicht kontrollieren.

## Alle Eingaben und Ausgaben

Die [README der Action](https://github.com/DefectDojo/defectdojo-action#inputs) listet jede Eingabe und jede Ausgabe auf. Die meisten Eingaben entsprechen einem Feld des Endpunkts **/reimport**, der unter [Import über die API](/import_data/import_scan_files/api_pipeline_modelling/) beschrieben ist.
