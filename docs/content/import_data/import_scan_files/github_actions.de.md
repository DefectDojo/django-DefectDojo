---
title: Import aus GitHub Actions
description: Importieren Sie Scan-Ergebnisse aus einem GitHub Actions-Workflow mit
  der offiziellen DefectDojo-Action
weight: 3
---

Die offizielle [DefectDojo-Action](https://github.com/DefectDojo/defectdojo-action) importiert einen Scan-Bericht aus einem GitHub Actions-Workflow in DefectDojo. Sie funktioniert mit DefectDojo Pro und der Open-Source-Edition und liest jedes von DefectDojo unterstützte Berichtsformat, einschließlich SARIF.

Jeder Lauf führt einen Reimport in denselben Test durch. Befunde, die der Scanner nicht mehr meldet, werden daher geschlossen, und jeder Befund behält seinen Verlauf. Die Action erfasst Build, Branch, Commit und Repository im Test und kann den Workflow-Schritt fehlschlagen lassen, wenn Befunde mit einem festgelegten Schweregrad weiterhin aktiv sind.

## Vor dem Start

1. Erstellen Sie einen API-v2-Schlüssel für einen Benutzer, der in das Asset importieren darf (und es anlegen darf, falls die Action Assets erstellen soll). Den Schlüssel finden Sie unter **API v2 Token** im Benutzermenü.
2. Fügen Sie den Schlüssel im GitHub-Repository als Secret mit dem Namen `DEFECTDOJO_API_TOKEN` unter **Settings > Secrets and variables > Actions** hinzu.

## Die Action zu einem Workflow hinzufügen

Führen Sie Ihren Scanner aus und übergeben Sie seinen Bericht anschließend an die Action:

```yaml
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

`scan-type` ist der Name des Berichtsformats, wie ihn DefectDojo auflistet, zum Beispiel `SARIF`, `Trivy Scan` oder `Semgrep JSON Report`. Alle Namen finden Sie unter [Unterstützte Tools](/supported_tools/).

## Wohin die Befunde gelangen

Sofern Sie nichts anderes festlegen, verwendet die Action Namen aus dem Repository und legt alle an, die noch nicht existieren:

| DefectDojo-Objekt | Standardwert | Eingabe |
| --- | --- | --- |
| Organization (Produkttyp) | Repository-Eigentümer | `organization-name` oder `product-type-name` |
| Asset (Produkt) | Repository-Name | `asset-name` oder `product-name` |
| Engagement | Branch-Name | `engagement-name` |
| Test | Scan-Typ | `test-title` |

Wenn ein Engagement mehrere Berichte desselben Scan-Typs erhält, geben Sie jedem einen eigenen `test-title`, damit jeder Reimport seinen eigenen Test findet.

### Branches, Pull Requests und Tags

Jeder Branch erhält ein eigenes Engagement, sodass der Scan eines Pull Requests nie Befunde auf dem Standard-Branch schließt oder wiedereröffnet. Pull Requests verwenden ihren Quell-Branch, Tags verwenden den Tag-Namen, und die Merge-Queue verwendet ein Engagement pro Basis-Branch.

Engagements, die die Action für andere Branches als den Standard-Branch erstellt, führen die Deduplizierung nur innerhalb ihrer selbst durch (**Deduplizierung nur innerhalb dieses Engagements**). Andernfalls würde ein Befund, der zuerst auf einem Branch gesehen wurde, die Kopie auf dem Standard-Branch als Duplikat markieren. Branch-Engagements bleiben auch nach dem Merge des Branches in DefectDojo erhalten. Führen Sie den Import daher nur auf dem Standard-Branch aus, wenn Sie sie aus den Zählungen des Assets heraushalten möchten.

## Den Build fehlschlagen lassen

Setzen Sie `fail-on` auf `low`, `medium`, `high` oder `critical`, damit der Schritt fehlschlägt, wenn der Test nach dem Import aktive Befunde mit diesem oder einem höheren Schweregrad enthält. Duplikate zählen nicht mit. Die Job-Zusammenfassung zeigt die Anzahl nach Schweregrad und einen Link zum Test.

## Pro-Funktionen

Mit DefectDojo Pro kann die Action außerdem:

- neue Befunde an die für das Asset eingerichteten Connectors senden (`push-to-connector: true`).
- große Berichte im Hintergrund importieren (`background-import: true`). Die Action wartet, bis der Test die Verarbeitung abgeschlossen hat, bevor sie die Zählungen meldet oder `fail-on` anwendet.
- warnen, wenn ein Asset umbenannt oder verschoben wurde, damit Sie die Namen im Workflow aktualisieren können.

In der Open-Source-Edition werden diese Eingaben mit einer Warnung übersprungen, und der Import läuft trotzdem. Setzen Sie `strict: true`, damit stattdessen der Schritt fehlschlägt.

## Pull Requests aus Forks

GitHub stellt Workflows, die bei Pull Requests aus Forks laufen, keine Secrets zur Verfügung, daher kann sich die Action dort nicht authentifizieren. Führen Sie den Import bei `push` oder bei Pull Requests aus Branches im selben Repository aus. Verwenden Sie `pull_request_target` nicht, um dies zu umgehen: Es läuft mit Ihren Secrets und checkt dabei Code aus, den Sie nicht kontrollieren.

## Alle Eingaben und Ausgaben

Die [README der Action](https://github.com/DefectDojo/defectdojo-action#inputs) listet jede Eingabe und jede Ausgabe auf. Die meisten Eingaben entsprechen einem Feld des Endpunkts **/reimport**, der unter [Import über die API](/import_data/import_scan_files/api_pipeline_modelling/) beschrieben wird.
