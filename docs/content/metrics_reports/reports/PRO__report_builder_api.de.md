---
title: Berichte über die API automatisieren
description: Erstellen Sie Themes, Blöcke und Vorlagen, und führen Sie Berichte aus
  und laden Sie die Ergebnisse über die DefectDojo Pro REST API herunter
draft: false
audience: pro
weight: 21
slug: report-builder-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Die Report-Builder-REST-API (Report-Themes, -Blöcke, -Vorlagen und generierte Berichte) ist eine DefectDojo-Pro-Funktion, die sich derzeit in der Beta-Phase befindet.</span>

Mit der Report-Builder-REST-API können Sie dieselben Themes, Blöcke und Vorlagen automatisieren, die Sie in der [Report-Builder-Benutzeroberfläche](../report-builder/) von Hand zusammenstellen — und sie geht noch einen Schritt weiter, indem sie es Ihnen ermöglicht, eine Vorlage **auszuführen** und das fertige PDF oder HTML **herunterzuladen**. Dieser Leitfaden begleitet Sie durch den gesamten Ablauf: authentifizieren, das Vokabular für Felder und Filter erkunden, die Bausteine erstellen und anschließend einen Bericht generieren und abrufen.

> **Suchen Sie stattdessen einen schnellen Befunde-Export?** Wenn Sie nur eine einfache Liste von Befunden als JSON, HTML, CSV oder Excel benötigen — ohne Themes, Blöcke oder Vorlagen einzurichten —, verwenden Sie den einfacheren Endpunkt `generate_report/`, der unter [Generating Reports](/automation/api/api-v2-docs/#generating-reports) dokumentiert ist. Die auf dieser Seite beschriebene Report-Builder-API dient dem Erstellen gestalteter, mehrteiliger Berichte.

## Authentifizierung

Jede Anfrage authentifiziert sich mit einem persönlichen API-Token, das im Header `Authorization` mit dem Präfix `Token` gesendet wird (nicht `Bearer`).

Sie erhalten Ihr Token in der DefectDojo Pro-Benutzeroberfläche unter **User Settings → API v2 Key**. Speichern Sie es in einer Umgebungsvariable, damit es nicht in Ihrem Shell-Verlauf oder einem committeten Skript landet:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

Die Basis-URL für alle Aufrufe ist Ihre Instanz plus `/api/v2`:

```text
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

Erforderliche Header:

| Header | Wert | Wann |
|--------|------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | Bei jeder Anfrage |
| `Accept` | `application/json` | Bei jeder Anfrage |
| `Content-Type` | `application/json` | Bei `POST` / `PATCH` mit JSON-Body |

Eine minimale authentifizierte Anfrage sieht so aus:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/"
```

Listen-Endpunkte werden mit den Query-Parametern `limit` und `offset` paginiert.

> **⚠️ Sicherheitshinweis:** Ihr API-Token gewährt vollen Zugriff auf Ihre DefectDojo-Daten. Fügen Sie es niemals in einen Chat, Screenshot, ein Ticket oder eine committete Datei ein. Lesen Sie es aus einer Umgebungsvariable aus, rotieren Sie es, falls es jemals offengelegt wird, und beschränken Sie Tokens nach Möglichkeit auf Service-Accounts.

## Die Reporting-API im Überblick

Die Report-Builder-API besteht aus vier Ressourcen. Jede unterstützt die Standardoperationen Liste (`GET`), Erstellen (`POST`), Abrufen (`GET {id}/`), Aktualisieren (`PATCH {id}/`) und Löschen (`DELETE {id}/`) sowie einige zusätzliche benutzerdefinierte Aktionen.

| Ressource | Pfad | Was es ist | Benutzerdefinierte Aktionen |
|-----------|------|------------|------------------------------|
| Themes | `/report_themes/` | Farben, Schriftarten, Kopf-/Fußzeilenbilder, Seitenzahlen | — |
| Blocks | `/report_blocks/` | Ein einzelner Inhaltsbaustein: eine Titelseite, eine Tabelle oder ein Detailabschnitt | `field_options/`, `preview/`, `{id}/preview/`, `{id}/duplicate/` |
| Templates | `/report_templates/` | Eine geordnete Liste von Blöcken plus ein Theme | `{id}/duplicate/` |
| Generated reports | `/generated_reports/` | Ein Lauf einer Vorlage, der eine herunterladbare Datei erzeugt | `{id}/download/` |

Zwei weitere Endpunkte helfen Ihnen, das benötigte Vokabular zu erkunden:

| Endpunkt | Zweck |
|----------|-------|
| `GET /report_blocks/field_options/` | Gültige Spalten-Feldpfade und Sortieroptionen für jedes Modell |
| `GET /oa3/schema/?format=json` | Das vollständige OpenAPI-Schema — dient zum Ermitteln gültiger Filternamen |

## Schritt 1: Das Vokabular erkunden

Zwei Dinge in einem Block lassen sich leicht falsch raten: die aufgelisteten **Spaltenfelder** und die angewendeten **Filter**. Die API liefert für beides eine verbindliche Quelle. Rufen Sie diese zuerst ab und bauen Sie dann auf dem auf, was der Server tatsächlich akzeptiert.

### Spaltenfelder und Sortierung

`field_options` liefert die gültigen `fields` (Spaltenpfade) und `ordering_fields` für jedes Modell, das Sie in einen tabellarischen Block oder einen Detailblock einfügen können:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/field_options/"
```

Die Antwort ist wie folgt aufgebaut (gekürzt):

```json
{
  "fields": {
    "finding": [
      {"path": "title", "label": "Title"},
      {"path": "severity", "label": "Severity"},
      {"path": "age_days", "label": "Age (days)"}
    ],
    "asset": [ ... ]
  },
  "ordering_fields": {
    "finding": [ ... ]
  }
}
```

Verwenden Sie für die `fields`-Liste eines Blocks ausschließlich die hier zurückgegebenen `path`-Werte. Manche Pfade sind Langform- oder Markdown-Felder und eher für **Detail**-Blöcke gedacht als für schmale tabellarische Spalten — `field_options` ist die maßgebliche Liste, prüfen Sie also dagegen, anstatt eine vollständige Liste fest zu codieren.

### Filternamen aus dem Schema

Die Filter eines Blocks befinden sich in `filter_entries`, wobei jeder Eintrag ein `{field, value}`-Paar ist. Die gültigen `field`-Namen sind die **GET-Query-Parameternamen** des REST-Endpunkts der zugrunde liegenden Entität — *nicht* die Bezeichnungen, die Sie in der Benutzeroberfläche sehen. Sie finden sie, indem Sie das OpenAPI-Schema lesen:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/oa3/schema/?format=json" \
  > schema.json
```

Lesen Sie dann die GET-Parameter für die Entität, die Sie filtern möchten. Für Befunde schauen Sie unter `paths` → `/api/v2/findings/` → `get` → `parameters`. Die entsprechenden Endpunkte sind `/api/v2/assets/` für **Assets** (früher Products), `/api/v2/organizations/` für **Organizations** (früher Product Types), `/api/v2/engagements/`, `/api/v2/tests/`, `/api/v2/test_types/` und `/api/v2/risk_acceptance/`. Jeder Parametername (`name`) ist ein gültiges Filter-`field`.

> **💡 Tipp:** In DefectDojo Pro hießen **Assets** früher **Products** und **Organizations** früher **Product Types**. Die zugrunde liegenden Filter-Feldpfade bei Befunden verwenden weiterhin die alte `product`-Bezeichnung (zum Beispiel `test__engagement__product`), obwohl die Entitäten jetzt Assets und Organizations heißen.

> **🔑 Wichtig:** Der Server **verwirft stillschweigend** jeden `filter_entry`, dessen `field` kein echter GET-Parameter für dieses Modell ist. Es wird kein Fehler ausgegeben — der Filter existiert im gespeicherten Block schlicht nicht. Rufen Sie den Block nach dem Erstellen immer per GET erneut ab und vergleichen Sie die zurückgegebenen `filter_entries` mit dem, was Sie gesendet haben.

### Häufig verwendete Filterfelder

Die folgenden Tabellen listen verifizierte, besonders nützliche Filter auf. Alle Werte werden als **einzelne String-Werte** gesendet; Booleans sind die wörtlichen Strings `"true"` / `"false"`.

**Filter für Befunde**

| Feld | Beispielwert | Hinweise |
|------|--------------|----------|
| `active` | `"true"` | Boolean-String |
| `verified` | `"true"` | Boolean-String |
| `is_mitigated` | `"false"` | Boolean-String |
| `risk_accepted` | `"false"` | Boolean-String |
| `duplicate` | `"false"` | Boolean-String |
| `false_p` | `"false"` | Boolean-String |
| `out_of_scope` | `"false"` | Boolean-String |
| `severity` | `"Critical"` | Nur ein einzelner Wert — **nicht** kommagetrennt. Verwenden Sie pro Schweregrad einen eigenen Block. |
| `known_exploited` | `"true"` | Boolean-String |
| `ransomware_used` | `"true"` | Boolean-String |
| `outside_of_sla` | `"1"` | **Numerischer** String, kein Boolean-String |
| `priority_min` | `"800"` | Verwenden Sie `_min`/`_max`, nicht `_greater_than` |
| `priority_max` | `"1000"` | Verwenden Sie `_min`/`_max` |
| `tag` | `"DR"` | Ein einzelner Tag |
| `tags` | `"kev,pci"` | Any-of (entspricht jedem beliebigen aufgeführten Tag) |
| `tags__and` | `"kev,pci"` | All-of (muss allen aufgeführten Tags entsprechen) |
| `test__engagement__product` | `"42"` | Asset-ID (Assets hießen früher Products) |
| `test__engagement__product__prod_type` | `"3"` | Organization-ID (früher Product Type) |
| `cve` | `"CVE-2024-12345"` | |
| `cwe` | `"79"` | |
| `date_after` | `"2025-12-31"` | |
| `date_before` | `"2025-12-31"` | |
| `planned_remediation_date_before` | `"2025-12-31"` | |

**Filter für Assets** (Assets hießen früher Products; dies sind die Parameter unter `/api/v2/assets/`)

| Feld | Beispielwert | Hinweise |
|------|--------------|----------|
| `business_criticality` | `"very_high"` | |
| `internet_accessible` | `"true"` | Boolean-String |
| `lifecycle` | `"production"` | |
| `platform` | `"web"` | |
| `tag` | `"pci"` | Ein einzelner Tag |

**Filter für Risikoakzeptanzen**

| Feld | Beispielwert | Hinweise |
|------|--------------|----------|
| `decision` | `"Accept (Transfer)"` | |
| `owner` | `"7"` | Benutzer-ID |
| `expiration_date_before` | `"2025-12-31"` | Für dieses Modell gibt es keinen `tag`-Filter |

Lesen Sie für Blöcke vom Typ **Engagement**, **Test**, **Test Type** und **Organization** die GET-Parameter wie oben beschrieben direkt aus dem Schema. Besonders nützlich sind `engagement__product` und `status` bei Tests sowie `name` bei Test Types — bestätigen Sie den genauen Namen aber immer in `schema.json`, bevor Sie sich darauf verlassen.

> **⚠️** Diese veralteten Namen im UI-Stil werden **stillschweigend verworfen** und dürfen NICHT verwendet werden: `status_any`, `priority_greater_than`, `severity__in`, `mitigated_within_sla` sowie jeder **kommagetrennte `severity`**-Wert (z. B. `"Critical,High"`). Verwenden Sie stattdessen die echten Query-Parameternamen aus dem Schema, und teilen Sie Anforderungen mit mehreren Schweregraden auf separate Blöcke auf.

> **🔑 Wichtig:** Ein `PATCH`, der `filter_entries` enthält, **ersetzt die gesamte Liste** — es gibt kein Zusammenführen (Merge). Senden Sie bei jeder Aktualisierung immer den vollständigen gewünschten Satz an Filtern, sonst gehen die weggelassenen verloren.

## Schritt 2: Theme, Blöcke und Vorlagen erstellen

Erstellen Sie die Bausteine in Abhängigkeitsreihenfolge: zuerst ein **Theme**, dann die **Blöcke**, dann eine **Vorlage**, die auf beide verweist.

### Ein Theme erstellen

Farben sind 7-stellige Hex-Strings. Jedes ausgelassene Feld fällt auf seinen Standardwert zurück (primary `#1e3a5f`, secondary `#4a90a4`, accent `#e67e22`, text `#333333`, background `#ffffff`).

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/" \
  -d '{
    "name": "Quarterly Review Theme",
    "primary_color": "#1e3a5f",
    "secondary_color": "#4a90a4",
    "accent_color": "#e67e22",
    "text_color": "#333333",
    "background_color": "#ffffff",
    "footer_text": "Confidential — Internal Use Only",
    "show_page_numbers": true
  }'
```

Die Antwort enthält die neue Theme-`id`. Kopf- und Fußzeilenbilder sind optional und werden als Multipart-Formularfelder (`header_image` / `footer_image`) hochgeladen; das obige JSON-Beispiel lässt sie aus.

### Blöcke erstellen

Ein Block hat einen `name`, einen `block_type` und ein dazu passendes Konfigurationsobjekt. Die unterstützten `block_type`-Werte sind `stock`, `tabular` und `detail`. (Ein Typ `chart` existiert im Datenmodell, ist aber über die API noch nicht verfügbar.)

**Eine Stock-Titelseite.** Stock-Blöcke enthalten feste Inhalte. `stock_type` ist einer von `cover_page`, `table_of_contents`, `page_break`, `image` oder `text_block`.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Cover Page",
    "block_type": "stock",
    "header": "Cover",
    "stock_configuration": {
      "stock_type": "cover_page",
      "title": "Quarterly Security Report",
      "subtitle": "Q4 — Active Critical Findings"
    }
  }'
```

**Ein tabellarischer Finding-Block mit Filtern.** Tabellarische Blöcke stellen Zeilen eines gewählten Modells dar. `model_choice` ist genau einer von `organization`, `asset`, `engagement`, `test`, `finding`, `test_type` oder `risk_acceptance`. Die `fields` stammen aus `field_options` (bestätigen Sie jeden `path`), und `filter_entries` grenzen die Zeilen ein.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Active Critical Findings",
    "block_type": "tabular",
    "header": "Active Critical Findings",
    "tabular_configuration": {
      "model_choice": "finding",
      "fields": ["severity", "title", "age_days", "sla_days_remaining"],
      "ordering": "-age_days"
    },
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"}
    ]
  }'
```

**Ein Detail-Finding-Block.** Detail-Blöcke stellen pro Datensatz einen ausführlichen Abschnitt dar und können Langform- bzw. Markdown-Felder enthalten, die sich nicht für eine schmale Tabellenspalte eignen. Bestätigen Sie auch hier die `fields` gegen `field_options`.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Critical Finding Detail",
    "block_type": "detail",
    "header": "Critical Findings — Detail",
    "detail_configuration": {
      "model_choice": "finding",
      "fields": ["title", "severity", "description", "mitigation"],
      "ordering": "-severity"
    },
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"}
    ]
  }'
```

Jede Block-Antwort enthält ihre `id`. Beachten Sie, dass `filter_entries` das widerspiegelt, was der Server tatsächlich gespeichert hat — vergleichen Sie dies mit dem, was Sie gesendet haben (siehe [Verifizieren, was Sie erstellt haben](#verify-what-you-built)).

### Eine Vorlage erstellen

Eine Vorlage verbindet ein Theme mit einer geordneten Liste von Blöcken. Das schreibgeschützte Feld ist `template_blocks`; beim Erstellen und Aktualisieren **schreiben** Sie `template_blocks_write`. Jeder Eintrag benötigt ein `order` und eine `block_id`, wobei dieselbe `block_id` mehrfach vorkommen darf.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/" \
  -d '{
    "name": "Quarterly Critical Report",
    "description": "Cover page, critical findings table, then per-finding detail",
    "theme_id": 1,
    "template_blocks_write": [
      {"order": 0, "block_id": 10},
      {"order": 1, "block_id": 11},
      {"order": 2, "block_id": 12}
    ]
  }'
```

Ersetzen Sie `theme_id` und jede `block_id` durch die in den vorherigen Schritten zurückgegebenen IDs. Die Antwort enthält die Vorlagen-`id`.

## Schritt 3: Den Bericht ausführen und das Ergebnis herunterladen

Das Generieren eines Berichts erfolgt asynchron: Sie erstellen einen Lauf, fragen dessen Status ab und laden die Datei herunter, sobald er abgeschlossen ist.

**Einen Lauf starten.** Senden Sie per POST eine `template_id` und ein `file_format` von `pdf` oder `html`:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/" \
  -d '{
    "template_id": 5,
    "file_format": "pdf"
  }'
```

Die Antwort liefert die neue Bericht-`id` mit `status` auf `pending`.

**Status abfragen.** Rufen Sie den Bericht ab, bis sein `status` einen Endzustand erreicht. Der Ablauf ist `pending` → `processing` → `completed`. Lesen Sie bei `failed` die `error_message`, um den Grund zu erfahren.

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/"
```

**Die Datei herunterladen.** Sobald `status` gleich `completed` ist, liefert der Download-Endpunkt die Datei als Anhang. Bis dahin antwortet er mit `404`.

```bash
curl -s -L \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/download/" \
  -o report.pdf
```

## Alles zusammenfügen: ein vollständiges Lifecycle-Skript

Das folgende Skript führt den gesamten Ablauf nur mit der Python-3-Standardbibliothek aus — ohne `requests`, ohne Drittanbieter-Pakete. Es liest das Token aus `DD_IMPORTER_DOJO_API_TOKEN`, erstellt ein Theme, drei Blöcke und eine Vorlage, startet einen Bericht, fragt mit Backoff ab, bis er abgeschlossen ist oder fehlschlägt, lädt das Ergebnis herunter und schreibt die erstellten IDs in `created.json`.

Legen Sie Ihre Instanz-URL fest und führen Sie es aus:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
export DD_BASE_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2"
python3 build_report.py
```

```python
#!/usr/bin/env python3
"""Build and run a DefectDojo Pro report end-to-end using only the stdlib."""

import json
import os
import time
import urllib.error
import urllib.request

# --- Configuration -------------------------------------------------------
BASE_URL = os.environ.get(
    "DD_BASE_URL",
    "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2",
).rstrip("/")
TOKEN = os.environ["DD_IMPORTER_DOJO_API_TOKEN"]  # fail loudly if unset
FILE_FORMAT = "pdf"  # "pdf" or "html"


def api_request(method, path, body=None, accept_json=True):
    """Make an authenticated request. Returns parsed JSON (or raw bytes)."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Token {TOKEN}")
    if accept_json:
        request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        # Surface the server's error body to make debugging easy.
        detail = error.read().decode("utf-8", errors="replace")
        raise SystemExit(f"{method} {path} failed ({error.code}): {detail}")

    if accept_json:
        return json.loads(payload) if payload else {}
    return payload


def main():
    created = {}

    # 1. Create a theme.
    theme = api_request("POST", "/report_themes/", {
        "name": "Quarterly Review Theme",
        "primary_color": "#1e3a5f",
        "secondary_color": "#4a90a4",
        "accent_color": "#e67e22",
        "text_color": "#333333",
        "background_color": "#ffffff",
        "footer_text": "Confidential - Internal Use Only",
        "show_page_numbers": True,
    })
    created["theme_id"] = theme["id"]
    print(f"Created theme id={theme['id']}")

    # 2. Create a stock cover page block.
    cover = api_request("POST", "/report_blocks/", {
        "name": "Cover Page",
        "block_type": "stock",
        "header": "Cover",
        "stock_configuration": {
            "stock_type": "cover_page",
            "title": "Quarterly Security Report",
            "subtitle": "Q4 - Active Critical Findings",
        },
    })
    created["cover_block_id"] = cover["id"]
    print(f"Created stock block id={cover['id']}")

    # 3. Create a tabular finding block scoped to active criticals.
    #    Confirm the chosen fields against /report_blocks/field_options/.
    table = api_request("POST", "/report_blocks/", {
        "name": "Active Critical Findings",
        "block_type": "tabular",
        "header": "Active Critical Findings",
        "tabular_configuration": {
            "model_choice": "finding",
            "fields": ["severity", "title", "age_days", "sla_days_remaining"],
            "ordering": "-age_days",
        },
        "filter_entries": [
            {"field": "active", "value": "true"},
            {"field": "severity", "value": "Critical"},
        ],
    })
    created["table_block_id"] = table["id"]
    print(f"Created tabular block id={table['id']}")

    # 4. Create a detail finding block.
    detail = api_request("POST", "/report_blocks/", {
        "name": "Critical Finding Detail",
        "block_type": "detail",
        "header": "Critical Findings - Detail",
        "detail_configuration": {
            "model_choice": "finding",
            "fields": ["title", "severity", "description", "mitigation"],
            "ordering": "-severity",
        },
        "filter_entries": [
            {"field": "active", "value": "true"},
            {"field": "severity", "value": "Critical"},
        ],
    })
    created["detail_block_id"] = detail["id"]
    print(f"Created detail block id={detail['id']}")

    # 5. Create a template binding the theme to the ordered blocks.
    #    Note: we WRITE template_blocks_write; template_blocks is read-only.
    template = api_request("POST", "/report_templates/", {
        "name": "Quarterly Critical Report",
        "description": "Cover, critical findings table, then per-finding detail",
        "theme_id": created["theme_id"],
        "template_blocks_write": [
            {"order": 0, "block_id": created["cover_block_id"]},
            {"order": 1, "block_id": created["table_block_id"]},
            {"order": 2, "block_id": created["detail_block_id"]},
        ],
    })
    created["template_id"] = template["id"]
    print(f"Created template id={template['id']}")

    # 6. Kick off a report run.
    report = api_request("POST", "/generated_reports/", {
        "template_id": created["template_id"],
        "file_format": FILE_FORMAT,
    })
    report_id = report["id"]
    created["report_id"] = report_id
    print(f"Started report id={report_id} (status={report['status']})")

    # 7. Poll until completed or failed, backing off up to 10 seconds.
    delay = 2
    while True:
        time.sleep(delay)
        report = api_request("GET", f"/generated_reports/{report_id}/")
        status = report["status"]
        print(f"  status={status}")
        if status == "completed":
            break
        if status == "failed":
            raise SystemExit(
                f"Report failed: {report.get('error_message', 'unknown error')}"
            )
        delay = min(delay + 2, 10)  # linear backoff, capped

    # 8. Download the finished file.
    content = api_request(
        "GET",
        f"/generated_reports/{report_id}/download/",
        accept_json=False,
    )
    out_name = f"report.{FILE_FORMAT}"
    with open(out_name, "wb") as handle:
        handle.write(content)
    print(f"Downloaded {out_name} ({len(content)} bytes)")

    # 9. Record the created IDs for later cleanup or reuse.
    with open("created.json", "w") as handle:
        json.dump(created, handle, indent=2)
    print("Wrote created.json")


if __name__ == "__main__":
    main()
```

## Verifizieren, was Sie erstellt haben

Da ungültige Filter stillschweigend verworfen werden, ist die Verifizierung Teil des Workflows — kein nachträglicher Gedanke.

**Bestätigen, dass die Filter eines Blocks erhalten geblieben sind.** Rufen Sie jeden Block per GET erneut ab und vergleichen Sie seine `filter_entries` mit dem, was Sie per POST gesendet haben:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/"
```

Fehlt ein von Ihnen gesendeter Filter in `filter_entries`, war dessen `field`-Name kein gültiger GET-Parameter für dieses Modell — überprüfen Sie den Namen in `schema.json`.

**Reihenfolge und Theme der Vorlage bestätigen.** Rufen Sie die Vorlage per GET ab und prüfen Sie, ob `template_blocks` die Blöcke in der erwarteten `order` auflistet und das verknüpfte Theme übereinstimmt:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/5/"
```

**Verworfene Filter mit PATCH korrigieren.** Um die Filter eines Blocks zu korrigieren, senden Sie per PATCH den **vollständigen** gewünschten Satz — ein PATCH ersetzt `filter_entries` vollständig:

```bash
curl -s -X PATCH \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/" \
  -d '{
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"},
      {"field": "outside_of_sla", "value": "1"}
    ]
  }'
```

## Nächste Schritte

- Erstellen Sie dieselben Themes, Blöcke und Vorlagen interaktiv in der [Report-Builder-Benutzeroberfläche](../report-builder/) und sehen Sie sich eine Vorschau davon an.
- Lassen Sie ein LLM Berichtskonfigurationen für Sie zusammenstellen — mit der [Report-Builder-LLM-Integration](../report-builder-llm/).
