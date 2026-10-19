---
title: DefectDojo API v2
description: Mit der API von DefectDojo können Sie Aufgaben automatisieren, z. B.
  das Hochladen von Scan-Berichten in CI/CD-Pipelines.
draft: false
weight: 2
aliases:
- /en/api/api-v2-docs
---

Die API von DefectDojo wurde mit dem [Django Rest
Framework](http://www.django-rest-framework.org/) erstellt. Die Dokumentation der
einzelnen Endpunkte ist in jeder DefectDojo-Installation unter
[`/api/v2/oa3/swagger-ui`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/) verfügbar und kann über den Link „API v2
Docs" im Benutzer-Dropdown-Menü in der Kopfzeile aufgerufen werden.

![image](images/api_v2_1.png)

Die Dokumentation wird mit [drf-spectacular](https://drf-spectacular.readthedocs.io/) unter [`/api/v2/oa3/swagger-ui/`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/) generiert und ist
interaktiv. Oben in den API-v2-Docs befindet sich ein Link, der eine OpenAPI-v3-Spezifikation generiert.

Um mit der Dokumentation zu interagieren, wird ein gültiger Authorization-Header-Wert
benötigt. Rufen Sie die Ansicht `/api/key-v2` auf, um Ihren
API-Schlüssel (`Token <api_key>`) zu generieren, und kopieren Sie den bereitgestellten Header-Wert.

![image](images/api_v2_2.png)

Jeder Abschnitt ermöglicht es Ihnen, Aufrufe an die API zu senden und die Request-
URL, den Response-Body, den Response-Code und die Response-Headers anzuzeigen.

![image](images/api_v2_3.png)

Wenn Sie in der Web-UI von DefectDojo angemeldet sind, müssen Sie das Authorization-Token nicht angeben.

## Authentifizierung

Die API verwendet eine Header-Authentifizierung mit API-Schlüssel. Das Format des
Headers sollte lauten: :

    Authorization: Token <api.key>

Zum Beispiel: :

    Authorization: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

### Alternative Authentifizierungsmethode

Wenn Sie für Benutzer [eine alternative Authentifizierungsmethode](/admin/sso/) verwenden, sollten Sie DefectDojo-API-Tokens möglicherweise deaktivieren, da diese Ihr Authentifizierungskonzept umgehen könnten. \
Die Verwendung von DefectDojo-API-Tokens kann deaktiviert werden, indem die Umgebungsvariable `DD_API_TOKENS_ENABLED` auf `False` gesetzt wird.
Oder es kann nur der Endpunkt `api/v2/api-token-auth/` deaktiviert werden, indem `DD_API_TOKEN_AUTH_ENDPOINT_ENABLED` auf `False` gesetzt wird.

## Beispielcode

Hier sind einige einfache Python-Beispiele und die damit erzeugten Ergebnisse für
den Endpunkt `/users`: :

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

Dieser Code gibt die Liste aller in DefectDojo definierten Benutzer zurück.
Das JSON-Objekt-Ergebnis sieht folgendermaßen aus: :

{{< highlight json >}}
    [
        {
          "first_name": "Tyagi",
          "id": 22,
          "last_login": "2019-06-18T08:05:51.925743",
          "last_name": "Paz",
          "username": "dev7958"
        },
        {
          "first_name": "saurabh",
          "id": 31,
          "last_login": "2019-06-06T11:44:32.533035",
          "last_name": "",
          "username": "saurabh.paz"
        }
    ]
{{< /highlight >}}

Hier ist ein weiteres Beispiel für den Endpunkt `/users`. Diesmal
filtern wir die Ergebnisse so, dass nur Benutzer angezeigt werden, deren Benutzername
`jay` enthält:

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users/?username__contains=jay'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

Das JSON-Objekt-Ergebnis lautet: :

{{< highlight json >}}
[
    {
        "first_name": "Jay",
        "id": 22,
        "last_login": "2015-10-28T08:05:51.925743",
        "last_name": "Paz",
        "username": "jay7958"
    },
    {
        "first_name": "",
        "id": 31,
        "last_login": "2015-10-13T11:44:32.533035",
        "last_name": "",
        "username": "jay.paz"
    }
]
{{< /highlight >}}

Weitere Beispiele und Tipps finden Sie in der [Dokumentation des Django Rest
Frameworks zur Interaktion mit einer
API](https://www.django-rest-framework.org/).

## Manuelles Aufrufen der API

Tools wie Postman können zum Testen der API verwendet werden.

Beispiel für den Import eines Scan-Ergebnisses:

-   Verb: POST
-   URI: <http://localhost:8080/api/v2/import-scan/>
-   Registerkarte „Headers":

    Fügen Sie den Authentifizierungsheader hinzu
    :   -   Key: Authorization
        -   Value: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

-   Registerkarte „Body"

    -   Wählen Sie \"form-data\" aus, klicken Sie auf \"bulk edit\". Beispiel für einen ZAP-Scan:

<!-- -->

    engagement:3
    verified:true
    active:true
    lead:1
    tags:test
    scan_type:ZAP Scan
    minimum_severity:Info
    close_old_findings:false

-   Registerkarte „Body"

       -   Klicken Sie auf die Bearbeitung \"Key-value\"
       -   Fügen Sie einen Parameter \"file\" vom Typ \"file\" hinzu. Dadurch werden
            Multipart-Formulardaten zum Senden des Dateiinhalts ausgelöst
       -   Suchen Sie die hochzuladende Datei

-   Klicken Sie auf Senden

## Clients / API-Wrapper

| Wrapper                      | Status                   | Hinweise |
| -----------------------------| ------------------------| ------------------------|
| [Spezifischer Python-Wrapper](https://github.com/DefectDojo/defectdojo_api)      | funktionsfähig (2021-01-21)    | API-Wrapper einschließlich Skripten für kontinuierliches CI/CD-Uploading. Hinkt bei den neuesten API-Funktionen etwas hinterher, da eine Überarbeitung des API-Wrappers geplant ist |
| [Openapi-Python-Wrapper](https://github.com/alles-klar/defectdojo-api-v2-client)       | | nur ein Proof of Concept, bei dem wir festgestellt haben, dass die OpenAPI-Spezifikation noch nicht perfekt ist |
| [Java-Bibliothek](https://github.com/secureCodeBox/defectdojo-client-java)                 | funktionsfähig (2021-08-30)    | Erstellt von den freundlichen Leuten von [SecureCodeBox](https://github.com/secureCodeBox/secureCodeBox) |
| [Image mit der Java-Bibliothek](https://github.com/SDA-SE/defectdojo-client) | funktionsfähig (2021-08-30)    | |
| [.Net/C#-Bibliothek](https://www.nuget.org/packages/DefectDojo.Api/)              | funktionsfähig (2021-06-08)    | |
| [dd-import](https://github.com/MaibornWolff/dd-import)                    | funktionsfähig (2021-08-24)    | dd-import ist nicht direkt ein API-Wrapper. Es bietet einige praktische Funktionen, mit denen sich Befunde und Sprachdaten aus CI/CD-Pipelines einfacher importieren lassen. |

Einige der API-Wrapper enthalten recht viel Logik, um das Scannen und Importieren in CI/CD-Umgebungen zu erleichtern. Wir sind dabei, dies zu vereinfachen, indem wir die DefectDojo-API intelligenter machen (damit API-Wrapper/Skripte einfacher gehalten werden können).

## API-Hinweise

### Import / Reimport

**Reimport** ist eigentlich der einfachste Weg, um loszulegen, da dabei bei Bedarf automatisch alle nötigen Entitäten erstellt werden und automatisch erkannt wird, ob es sich um einen erstmaligen Upload oder einen erneuten Upload handelt.

## Import
Der Import über die API erfolgt über den Endpunkt [import-scan](https://demo.defectdojo.org/api/v2/doc/).

Wie in der [Produkthierarchie](/asset_modelling/os_hierarchy/product_hierarchy/) beschrieben, wird ein Test innerhalb eines Engagements erstellt, das wiederum innerhalb eines Produkts liegt, das wiederum innerhalb eines Produkttyps liegt.

Ein Import kann durchgeführt werden, indem die Namen dieser Entitäten in der API-Anfrage angegeben werden:


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
}
```

Wenn `auto_create_context` auf `True` gesetzt ist, werden das Produkt, das Engagement und die Umgebung bei Bedarf erstellt. Stellen Sie sicher, dass Ihr Benutzer über ausreichende [Berechtigungen](/admin/user_management/about_perms_and_roles/) dafür verfügt.

Eine klassische Methode zum Importieren eines Scans besteht darin, stattdessen die ID des Engagements anzugeben:

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "engagement": 123,
}
```

## Reimport
Der Reimport über die API erfolgt über den Endpunkt [reimport-scan](https://demo.defectdojo.org/api/v2/doc/).

Ein Reimport kann durchgeführt werden, indem die Namen dieser Entitäten in der API-Anfrage angegeben werden:


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
    "do_not_reactivate": False,
}
```

Wenn `auto_create_context` auf `True` gesetzt ist, werden der Produkttyp, das Produkt und das Engagement erstellt, sofern sie noch nicht existieren. Stellen Sie sicher, dass Ihr Benutzer über ausreichende [Berechtigungen](/admin/user_management/about_perms_and_roles/) zum Erstellen eines Produkts/Produkttyps verfügt.

Wenn `do_not_reactivate` auf `True` gesetzt ist, ignorieren Import/Reimport hochgeladene aktive Befunde und reaktivieren zuvor geschlossene Befunde nicht, erstellen aber weiterhin neue Befunde, sofern welche vorhanden sind. Sie erhalten am Befund einen Hinweis, der erklärt, dass er aus diesem Grund nicht reaktiviert wurde.

Ein Reimport wählt automatisch den neuesten Test innerhalb des angegebenen Engagements aus, der dem angegebenen `scan_type` und (optional) dem angegebenen `test_title` entspricht.

Wird kein vorhandener Test gefunden, verwendet der Reimport-Endpunkt die Import-Funktion, um den bereitgestellten Bericht in einen neuen Test zu importieren. Das bedeutet, dass ein (CI/CD-)Skript, das die API verwendet, nicht wissen muss, ob bereits ein Test existiert oder ob es sich um einen erstmaligen Upload für dieses Produkt/Engagement handelt.

Eine klassische Methode zum Reimportieren eines Scans besteht darin, stattdessen die ID des Tests anzugeben:

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test": 123,
}
```

## Berichte erstellen

DefectDojo kann über die API einen Befundbericht im Format **JSON**, **HTML**, **CSV** oder **Excel** erstellen.

Ein Bericht wird mit einer `POST`-Anfrage an eine `generate_report/`-Aktion erstellt. Der Endpunkt für Befunde berichtet instanzweit, und die meisten anderen Objekte bieten eine objektspezifische Aktion:

| Endpunkt | Umfang |
|---|---|
| `POST /api/v2/findings/generate_report/` | Jeder Befund, den Sie einsehen dürfen |
| `POST /api/v2/products/{id}/generate_report/` | Ein Produkt |
| `POST /api/v2/engagements/{id}/generate_report/` | Ein Engagement |
| `POST /api/v2/tests/{id}/generate_report/` | Ein Test |
| `POST /api/v2/product_types/{id}/generate_report/` | Ein Produkttyp |
| `POST /api/v2/endpoints/{id}/generate_report/` | Ein Endpunkt |

Die Pro-Objekt-Aliase bieten dieselbe Aktion: `/api/v2/assets/{id}/generate_report/`, `/api/v2/organizations/{id}/generate_report/` und `/api/v2/location/{id}/generate_report/`.

### Anfrageoptionen

Alle Felder sind optional – das Senden eines leeren Bodys (`{}`) liefert einen JSON-Bericht.

| Feld | Typ | Standard | Beschreibung |
|---|---|---|---|
| `report_type` | string | `JSON` | Einer von `JSON`, `HTML`, `CSV`, `Excel`. |
| `include_finding_notes` | boolean | `false` | Notizen zu jedem Befund einschließen. |
| `include_finding_images` | boolean | `false` | An Befunde angehängte Bilder einschließen. |
| `include_executive_summary` | boolean | `false` | Einen Abschnitt mit einer Management-Zusammenfassung einschließen. |
| `include_table_of_contents` | boolean | `false` | Ein Inhaltsverzeichnis einschließen. |

Ein nicht unterstützter `report_type` (zum Beispiel `PDF`) liefert `400 Bad Request` mit einem Fehler im Feld `report_type`.

### Beispiel

Erstellen Sie einen CSV-Bericht aller Befunde, die Sie einsehen können, und speichern Sie ihn in einer Datei:

```bash
curl -X POST \
  -H "Authorization: Token <your-api-token>" \
  -H "Content-Type: application/json" \
  -d '{"report_type": "CSV"}' \
  https://<your-instance>/api/v2/findings/generate_report/ \
  -o findings.csv
```

### Antwortformate

| `report_type` | Content-Type | Antwort |
|---|---|---|
| `JSON` (Standard) | `application/json` | Berichtsinhalt in der Antwort |
| `HTML` | `text/html` | Gerenderte Berichtsseite |
| `CSV` | `text/csv` | Dateianhang |
| `Excel` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | `.xlsx`-Dateianhang |

CSV und Excel werden als Dateianhänge mit einem `Content-Disposition`-Header zurückgegeben und nicht als JSON-Body. Der Dateiname leitet sich von dem Objekt ab, für das der Bericht erstellt wurde – zum Beispiel `product_1_findings.csv` oder `test_42_findings.xlsx`. Der Endpunkt `/findings/generate_report/` ist nicht auf ein einzelnes Objekt beschränkt, daher heißen seine Downloads `findings.csv` und `findings.xlsx`.

### Hinweise und Einschränkungen

* Die `include_*`-Optionen wirken sich nur auf die **JSON**- und **HTML**-Berichte aus. Die **CSV**- und **Excel**-Exporte enthalten immer die Befundzeilen.
* Für die Berichtserstellung ist die Berechtigung **view** für die betroffenen Objekte erforderlich, und ein Bericht enthält nur Befunde, die Sie einsehen dürfen.
* **Standard-Query-Parameter-Filter werden auf diese Aktion nicht angewendet.** Anders als bei `GET /api/v2/findings/` wendet die Aktion `generate_report/` die Finding-Filter nicht an, sodass eine Anfrage wie `POST /api/v2/findings/generate_report/?severity=High` weiterhin über jeden Befund berichtet, den Sie einsehen können. Um einen Bericht einzugrenzen, erstellen Sie ihn stattdessen aus einem bestimmten Produkt, Engagement oder Test.

## Asynchrones Löschverhalten

Löschvorgänge in DefectDojo (sowohl über die API als auch über die UI) werden **asynchron** von Celery-Hintergrund-Workern verarbeitet. Wenn Sie ein Engagement, einen Test oder ein anderes Objekt löschen, liefert die API oder UI sofort eine Erfolgsmeldung, die eigentliche Löschung läuft jedoch im Hintergrund.

Das bedeutet:
- Objekte können nach der Bestätigung der Löschung noch eine Zeit lang in Abfragen erscheinen.
- Kaskadierende Löschungen (z. B. löscht das Löschen eines Engagements auch dessen Tests und Befunde) werden als eine Kette von Hintergrundaufgaben verarbeitet. Untergeordnete Objekte werden in Abhängigkeitsreihenfolge entfernt: zuerst Befunde, dann Tests, dann Engagements.
- Bei großen Engagements mit vielen Befunden kann dieser Vorgang mehrere Minuten dauern.

Es ist nicht nötig, eigene Skripte zu erstellen, um Objekte in Abhängigkeitsreihenfolge zu löschen. Eine einzelne `DELETE`-Anfrage für ein Engagement kaskadiert automatisch auf alle untergeordneten Objekte. Geben Sie den Hintergrundaufgaben einfach genug Zeit, um abgeschlossen zu werden.

## API-Paginierungslimits

DefectDojo Pro erzwingt eine maximale Seitengröße von **250** Ergebnissen pro API-Anfrage. Wird `limit` höher als 250 gesetzt, kann dies aufgrund von Abfrage-Timeouts zu HTTP-502-Fehlern führen.

Open-Source-DefectDojo-Instanzen können bei sehr großen Seitengrößen ebenfalls Timeouts erleben, abhängig von der Datensatzgröße und den Serverressourcen.

Verwenden Sie bei großen Ergebnismengen eine Paginierung mit einer Seitengröße von 50-250 und fügen Sie kurze Verzögerungen zwischen paginierten Anfragen ein, um eine Überlastung des Worker-Pools zu vermeiden.

## Best Practices für Imports im großen Maßstab

Beachten Sie beim Import von Scan-Ergebnissen im großen Maßstab (z. B. SBOM-Pipelines mit Tausenden von Komponenten) Folgendes:

- **Verwenden Sie `background_import=true`** für große Payloads. Synchrone Importe belegen für die Dauer des Imports einen uwsgi-Worker, was die Performance für alle Benutzer beeinträchtigen kann.
- **Streben Sie nach Möglichkeit Payload-Größen unter 1 MB pro Import an.** Teilen Sie große SBOMs in kleinere Dateien pro Produkt oder Komponentengruppe auf.
- **Fügen Sie Verzögerungen zwischen aufeinanderfolgenden API-Aufrufen ein**, um eine Erschöpfung des Worker-Pools zu vermeiden, die zu HTTP-502-Fehlern führt.
- **Verwenden Sie Reimport** (`/api/v2/reimport-scan/`) für wiederkehrende Scans, um vorhandene Befunde zu aktualisieren, statt Duplikate zu erstellen.

## Antworten bei Hintergrundimporten (API: `background_import`)

Ein Hintergrundimport liefert eine Antwort, sobald der hochgeladene Bericht geparst wurde, noch bevor
Befunde geschrieben wurden. Seine Antwort beschreibt daher *geplante* Arbeit, und sie ist
anders aufgebaut als bei einem synchronen Import. Dies gilt für `/api/v2/import-scan/` und
`/api/v2/reimport-scan/`, wenn `background_import` auf `true` gesetzt ist, oder wenn die
Systemeinstellung `api_async_import` dies für jeden Import aktiviert.

Eine Hintergrundantwort enthält:

- `background_import` — `true`. Dies ist das Feld, anhand dessen Sie verzweigen sollten.
- `status` — der Lifecycle-Status des Tests zum Zeitpunkt der Antworterstellung:
  `Processing`, `Post Processing - Deduplication`,
  `Post Processing - False Positive History`, `Processed` oder `Failed`.
- `findings_parsed` — wie viele Befunde aus dem Bericht ausgelesen wurden. Dies ist eine Parse-
  Anzahl, keine Anzahl erstellter Befunde: Die Deduplizierung und die von Ihnen angegebenen Importoptionen
  entscheiden, wie viele Befunde tatsächlich geschrieben werden.
- `test_id` (sowie `engagement_id`, `product_id`, `product_type_id`) — die Kennungen, die
  abgefragt werden können.
- `message` — dieselben Informationen wie `status` und `findings_parsed`, in Textform. Bevorzugen Sie
  die strukturierten Felder.

Sie enthält **nicht** `statistics`, und sie enthält auch nicht `deduplication_complete`.
Diese Schlüssel fehlen, statt null zu sein, weil zu diesem Zeitpunkt noch keine Befunde
erstellt wurden und die Angabe von Nullen den Import falsch beschreiben würde. Ein Client, der
`response["statistics"]` bedingungslos ausliest, schlägt bei einem Hintergrundimport fehl — lesen Sie
zuerst `background_import`, oder verwenden Sie `statistics` nur auf dem synchronen Pfad.

Um einen Hintergrundimport bis zum Abschluss zu verfolgen, fragen Sie den Test ab:

```
POST /api/v2/import-scan/        (background_import=true)  -> test_id, status, findings_parsed
GET  /api/v2/tests/{test_id}/                              -> status, processing
```

Wiederholen Sie den `GET`-Aufruf, bis `status` den Wert `Processed` hat (der Import ist abgeschlossen, und
die Befundzahlen des Tests sind jetzt aussagekräftig) oder `Failed` (der Import wurde nicht abgeschlossen). Während der
Import läuft, ist `processing` `true`, und `status` gibt an, in welcher Phase er sich befindet. Lassen Sie
zwischen den Abfragen einige Sekunden vergehen; bei einem großen Bericht kann die Nachbearbeitung mehrere Minuten dauern.

Ein synchroner Import (`background_import` weggelassen oder auf `false` gesetzt) bleibt unverändert: Er liefert eine Antwort,
sobald die Befunde geschrieben wurden, enthält `statistics` und enthält weder `status`
noch `findings_parsed`.

## Verwendung des Felds für das Scan-Abschlussdatum (API: `scan_date`)

DefectDojo unterstützt eine Vielzahl von Scanner-Berichten, aber nicht alle enthalten die
für einen Benutzer wichtigsten Informationen. Das Feld `scan_date` ist eine flexible intelligente Funktion, die
es Benutzern erlaubt, das Abschlussdatum eines bestimmten Scan-Berichts festzulegen und
es auf alle importierten Befunde übertragen zu lassen. Dieses Feld ist **nicht** verpflichtend, aber der
Standardwert für dieses Feld ist das Datum des Imports (also der Zeitpunkt, zu dem die Anfrage verarbeitet und eine erfolgreiche Antwort zurückgegeben wird).

Im Folgenden finden Sie die Anwendungsfälle für dieses Feld:

1. Der Bericht legt **kein** Datum fest, und `scan_date` wird beim Import **nicht** gesetzt
    - Das Befund-Datum entspricht dem Standardwert von `scan_date`
2. Der Bericht **legt** das Datum fest, und `scan_date` wird beim Import **nicht** gesetzt
    - Das Befund-Datum entspricht dem, was der Bericht festlegt
3. Der Bericht legt **kein** Datum fest, und `scan_date` wird beim Import **gesetzt**
    - Das Befund-Datum entspricht dem, was der Benutzer für `scan_date` festgelegt hat
4. Der Bericht **legt** das Datum fest, und `scan_date` wird beim Import **gesetzt**
    - Das Befund-Datum entspricht dem, was der Benutzer für `scan_date` festgelegt hat
