---
title: Universal Importer & DefectDojo-CLI
description: Dateien über die Kommandozeile in DefectDojo importieren
draft: false
weight: 2
audience: pro
aliases:
- /de/en/connecting_your_tools/external_tools
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Die folgenden externen Tools sind Funktionen, die ausschließlich in DefectDojo Pro verfügbar sind. Diese Binaries funktionieren nur, wenn sie mit einer Instanz verbunden sind, die eine DefectDojo Pro-Lizenz besitzt.</span>

## Über externe Tools

`defectdojo-cli` und `universal-importer` sind Kommandozeilen-Tools, die sowohl den Import als auch den erneuten Import von Befunden und zugehörigen Objekten vereinfachen. Damit eignen sie sich ideal für Benutzer, die diese Interaktionen mit der DefectDojo-API schnell einrichten möchten.

DefectDojo-CLI bietet denselben Funktionsumfang wie Universal Importer, kann Befunde aus DefectDojo darüber hinaus aber auch nach JSON oder CSV exportieren.

## Installation

1. Öffnen Sie „Externe Tools“ über das Menü Ihres Benutzerprofils:

2. Laden Sie das passende Binary für Ihr Betriebssystem von der Plattform herunter.

![image](images/external-tools.png)

3. Entpacken Sie das heruntergeladene Archiv in einem Verzeichnis Ihrer Wahl. Optional können Sie das Verzeichnis mit dem entpackten Binary zum $PATH Ihres Systems hinzufügen, um es wiederholt aufrufen zu können.

**Beachten Sie, dass Macintosh-Benutzer möglicherweise daran gehindert werden, DefectDojo-CLI oder Universal Importer auszuführen, da es sich um Apps eines nicht verifizierten Entwicklers handelt.  Anweisungen dazu, wie Sie diese Sperre von Apple aufheben, finden Sie beim [Apple Support](https://support.apple.com/en-ca/guide/mac-help/mh40616/mac).**  

**Windows-Benutzer: Wenn Sie die Fehlermeldung "Couldn't download - virus detected" erhalten, kann das Deaktivieren von Smartscreen helfen. Andernfalls verwenden Sie einen anderen Browser, um das Tool aus dem Cloud-Portal herunterzuladen.**

## Konfiguration

Universal Importer und DefectDojo-CLI lassen sich über Flags, Umgebungsvariablen oder eine Konfigurationsdatei konfigurieren. Die wichtigste Einstellung ist das API-Token, das als Umgebungsvariable gesetzt werden muss:

1. Fügen Sie Ihren API-Schlüssel zu Ihren Umgebungsvariablen hinzu. 
Ihren API-Schlüssel finden Sie unter: `https://YOUR_INSTANCE.cloud.defectdojo.com/api/key-v2`

oder 

über die DefectDojo-Benutzeroberfläche 
im Benutzer-Dropdown oben rechts:

![image](images/api-token.png)

2. Setzen Sie die Umgebungsvariable für das API-Token.

**Für DefectDojo-CLI:**
	`export DD_CLI_API_TOKEN=YOUR_API_KEY`

**Für Universal Importer:**
	`export DD_IMPORTER_DOJO_API_TOKEN=YOUR_API_KEY`

Hinweis: Verwenden Sie unter Windows `set` anstelle von `export`.

### Windows: PowerShell verwenden

1. Öffnen Sie PowerShell (Windows-Taste, dann nach „PowerShell“ suchen).
2. Setzen Sie die Umgebungsvariablen:
   - **Temporär:**
     ```powershell
     $env:DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     $env:DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Dauerhaft:**
     ```powershell
     [Environment]::SetEnvironmentVariable("DD_IMPORTER_DOJO_API_TOKEN", "[VALUE_FROM_DEFECTDOJO_API]", "Machine")
     ```
3. Starten Sie Ihre PowerShell-Sitzung neu.
4. Überprüfen Sie die Einstellung:
   ```powershell
   echo $env:DD_IMPORTER_DOJO_API_TOKEN
   echo $env:DD_IMPORTER_DEFECTDOJO_URL
   ```

### Windows: Eingabeaufforderung verwenden (Administratorkonten)
1. Öffnen Sie die Eingabeaufforderung (Windows-Taste, dann nach „Command Prompt“ suchen).
2. Setzen Sie die Umgebungsvariablen:
   - **Temporär:**
     ```cmd
     set DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     set DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Dauerhaft:**
     ```cmd
     setx DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     setx DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```

### Windows-Einstellungen verwenden (Konten ohne Administratorrechte)
1. Drücken Sie `Win + I`, um den Dialog der Systemeinstellungen zu öffnen.
2. Geben Sie im Suchfeld „environment“ ein.
3. Wählen Sie „Edit Environment variables for your account“.
4. Klicken Sie unter „User variables for [username]“ auf die Schaltfläche „New…“.
5. Legen Sie die Variable fest:
   - **Variablenname:** `DD_IMPORTER_DOJO_API_TOKEN`
   - **Variablenwert:** `[VALUE_FROM_DEFECTDOJO_API]`
6. Klicken Sie auf „OK“.
7. Wiederholen Sie die Schritte 4 bis 6 für die Variable DD_IMPORTER_DEFECTDOJO_URL
8. Starten Sie alle geöffneten Befehlsfenster neu.
9. Überprüfen Sie die Einstellungen:
   ```cmd
   echo %DD_IMPORTER_DOJO_API_TOKEN%
   echo %DD_IMPORTER_DEFECTDOJO_URL%
   ```

## DefectDojo-CLI

`defectdojo-cli` integriert Scan-Ergebnisse nahtlos in DefectDojo und vereinfacht den Import und den Reimport von Befunden und zugehörigen Objekten. Das Tool ist auf einfache Bedienung ausgelegt und unterstützt verschiedene Endpunkte, sowohl für erste Importe als auch für nachfolgende Reimporte. Damit eignet es sich ideal für Benutzer, die eine robuste und flexible Interaktion mit der DefectDojo-API benötigen. DefectDojo-CLI bietet dieselben Funktionen wie `universal-importer` und ergänzt sie um eine Exportfunktion für Befunde.

### Befehle

- [`import`](./#import)       Importiert Befunde in DefectDojo.
- [`reimport`](./#reimport)     Importiert Befunde erneut in DefectDojo.
- [`export`](./#export)	Exportiert Befunde aus DefectDojo.
- [`interactive`](./#interactive)   Startet einen interaktiven Modus, um den Import- und Reimport-Vorgang zu konfigurieren, Schritt für 

### Globale Optionen

`--help, -h`     
* Hilfe anzeigen

`--version, -v`
* Version ausgeben

#### CLI-Formatierung

`--no-color`
* Deaktiviert die farbige Ausgabe. (Standard: false) `[$DD_CLI_NO_COLOR]`
`--no-emojis, --no-emoji`

* Deaktiviert Emojis in der Ausgabe. (Standard: false) `[$DD_CLI_NO_EMOJIS]`

* `--verbose`
Aktiviert die ausführliche Ausgabe. (Standard: false) `[$DD_CLI_VERBOSE]`

### Import

Verwenden Sie den Befehl import, um neue Befunde in DefectDojo zu importieren.

#### Verwendung

```
defectdojo-cli [global options] import <required flags> [optional flags]
	or: defectdojo-cli [global options] import  --config ./config-file-path
	or: defectdojo-cli import [-h | --help]
	or: defectdojo-cli import example [subcommand options]
	or: defectdojo-cli import example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

`import` kann Befunde auf zwei Arten importieren:

**Nach ID:**
* Erstellen Sie ein Produkt (oder verwenden Sie ein bestehendes Produkt)
* Erstellen Sie ein Engagement innerhalb des Produkts
* Geben Sie die ID des Engagements im Parameter engagement an

In diesem Szenario wird ein neuer Test innerhalb des Engagements erstellt.

**Nach Name:**

* Erstellen Sie ein Produkt (oder verwenden Sie ein bestehendes Produkt)
* Erstellen Sie ein Engagement innerhalb des Produkts
* Geben Sie product-name an
* Geben Sie engagement-name an
* Geben Sie optional product-type-name an

In diesem Szenario ermittelt DefectDojo das Engagement anhand der angegebenen Details.

Wenn Sie Namen verwenden, können Sie Engagements, Produkte und Produkttypen mit `auto-create-context=true` automatisch vom Importer erstellen lassen.
Mit `deduplication-on-engagement` können Sie die Deduplizierung importierter Befunde auf das neu erstellte Engagement beschränken.


**Grundlegende Import-Syntax:**
```
defectdojo-cli import [options]
```

#### **Import-Beispiel:**
```
defectdojo-cli import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### Befehle
`example, x`
* Zeigt ein Beispiel für erforderliche und optionale Flags des Import-Vorgangs

#### Optionen

`--active, -a` 
* Legt fest, ob Befunde beim Import zwingend auf Aktiv oder Inaktiv gesetzt werden.  Der Wert True setzt Befunde auf Aktiv, der Wert False setzt alle Befunde auf Inaktiv.  Wenn kein Wert gesetzt ist, richtet sich der Status Aktiv stattdessen nach der eingehenden Berichtsdatei. (Standard: nicht gesetzt) `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`
* Die ID des API Scan Configuration-Objekts, das beim Import oder Reimport verwendet werden soll. (Standard: 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* Wenn auf true gesetzt, werden die Tags (aus der Option --tag) auf die Endpunkte angewendet (Standard: false) 
`[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* Wenn auf true gesetzt, werden die Tags (aus der Option --tag) auf die Befunde angewendet (Standard: false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* Wenn auf true gesetzt, erstellt der Importer automatisch Engagements, Produkte und Product_Types (Standard: false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Wenn True, werden beim Import alte Befunde, die nicht mehr im Bericht enthalten sind, als Behoben geschlossen. Wenn Service gesetzt ist, werden nur die Befunde für diesen Service geschlossen. [$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Legt fest, ob --close-old-findings für **alle** Befunde desselben Typs im Produkt gilt. Standardmäßig ist dies auf false gesetzt, das heißt, nur alte Befunde desselben Typs im Engagement fallen in den Geltungsbereich (und werden durch Close Old Findings geschlossen). [$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* Wenn auf true gesetzt, beschränkt der Importer die Deduplizierung importierter Befunde auf das neu erstellte Engagement. (Standard: false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* Die ID des Engagements, in das die Befunde importiert werden sollen. (Standard: 0) `[$DD_CLI_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* Der Name des Engagements, in das die Befunde importiert werden sollen. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Legt den niedrigsten Schweregrad fest, der importiert werden soll. Gültige Werte sind: Critical, High, Medium, Low, Info. (Standard: "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* Der Name des Produkts, in das die Befunde importiert werden sollen. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* Der Name des Produkttyps, in den die Befunde importiert werden sollen. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* Der Pfad zu dem zu importierenden Bericht. (erforderlich). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`
* Der Scan-Typ des Tools (erforderlich). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Alle Tags, die auf das Test-Objekt angewendet werden sollen `[$DD_CLI_TAGS]`

`--test-name value, --tn value`
* Der Name des Tests, in den die Befunde importiert werden sollen - standardmäßig der Name des Scan-Typs. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`
* Die Version des Tests. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`
* Legt fest, ob Befunde beim Import auf Verifiziert gesetzt werden. Der Wert True setzt Befunde zwingend auf Verifiziert. Wenn kein Wert gesetzt ist, richtet sich der Status Verifiziert stattdessen nach der eingehenden Berichtsdatei. `[$DD_CLI_VERIFIED]`

**Einstellungen:**

`--config value, -c value`          
* Der Pfad zur TOML-Konfigurationsdatei, mit der Werte für die Optionen gesetzt werden. Wenn eine Option sowohl in der Konfigurationsdatei als auch in der CLI gesetzt ist, wird der in der CLI gesetzte Wert verwendet. `[$DD_CLI_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* Die URL der DefectDojo-Instanz, in die die Befunde importiert werden sollen. (erforderlich). `[$DD_CLI_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          Ignoriert TLS-Validierungsfehler bei der Verbindung zur angegebenen DefectDojo-Instanz. Die meisten Benutzer sollten dieses Flag nicht aktivieren. (Standard: false) `[$DD_CLI_INSECURE_TLS]`

### Reimport

Verwenden Sie den Befehl `reimport`, um einen bestehenden Test auf eine von zwei Arten um Befunde aus einem neuen Bericht zu erweitern:

Nach ID:
- Erstellen Sie ein Produkt (oder verwenden Sie ein bestehendes Produkt)
- Erstellen Sie ein Engagement innerhalb des Produkts
- Importieren Sie einen Scan-Bericht und ermitteln Sie die ID des Tests
- Geben Sie diese im Parameter test-id an

Nach Namen:
- Erstellen Sie ein Produkt (oder verwenden Sie ein bestehendes Produkt)
- Erstellen Sie ein Engagement innerhalb des Produkts
- Importieren Sie einen Bericht, wodurch ein Test erstellt wird
- Geben Sie product-name an
- Geben Sie engagement-name an
- Optional: Geben Sie test-name an

In diesem Szenario ermittelt DefectDojo den Test anhand der angegebenen Details. Wenn kein test-name angegeben wird, wird der neueste Test innerhalb des Engagements auf Basis des scan-type ausgewählt.

Wenn Sie Namen verwenden, können Sie Engagements, Produkte und Produkttypen mit `auto-create-context=true` automatisch vom Importer erstellen lassen.
Mit `deduplication-on-engagement` können Sie die Deduplizierung importierter Befunde auf das neu erstellte Engagement beschränken.

#### Verwendung

```
defectdojo-cli [global options] reimport <required flags> [optional flags]
   or: defectdojo-cli [global options] reimport  --config ./config-file-path
   or: defectdojo-cli reimport [-h | --help]
   or: defectdojo-cli reimport example [subcommand options]
   or: defectdojo-cli reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

#### **Reimport-Beispiel:**

```
defectdojo-cli reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### Befehle

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Optionen

`--active, -a`                                    
* Legt fest, ob Befunde beim Import zwingend auf Aktiv oder Inaktiv gesetzt werden.  Der Wert True setzt Befunde auf Aktiv, der Wert False setzt alle Befunde auf Inaktiv.  Wenn kein Wert gesetzt ist, richtet sich der Status Aktiv stattdessen nach der eingehenden Berichtsdatei. `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`

* Die ID des API Scan Configuration-Objekts, das beim Import oder Reimport verwendet werden soll. (Standard: 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* Wenn auf true gesetzt, werden die Tags (aus der Option --tag) auf die Endpunkte angewendet (Standard: false) `[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* Wenn auf true gesetzt, werden die Tags (aus der Option --tag) auf die Befunde angewendet (Standard: false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* Wenn auf true gesetzt, erstellt der Importer automatisch Engagements, Produkte und Product_Types (Standard: false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Wenn True, werden beim Import alte Befunde, die nicht mehr im Bericht enthalten sind, als Behoben geschlossen. Wenn Service gesetzt ist, werden nur die Befunde für diesen Service geschlossen.[$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Legt fest, ob --close-old-findings für **alle** Befunde desselben Typs im Produkt gilt. Standardmäßig ist dies auf false gesetzt, das heißt, nur alte Befunde desselben Typs im Engagement fallen in den Geltungsbereich (und werden durch Close Old Findings geschlossen). [$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* Wenn auf true gesetzt, beschränkt der Importer die Deduplizierung importierter Befunde auf das neu erstellte Engagement. (Standard: false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* Der Name des Engagements, in das die Befunde importiert werden sollen. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Legt den niedrigsten Schweregrad fest, der importiert werden soll. Gültige Werte sind: Critical, High, Medium, Low, Info. (Standard: "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* Der Name des Produkts, in das die Befunde importiert werden sollen. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* Der Name des Produkttyps, in den die Befunde importiert werden sollen. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* Der Pfad zu dem zu importierenden Bericht. (erforderlich). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`                      
* Der Scan-Typ des Tools (erforderlich). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Alle Tags, die auf das Test-Objekt angewendet werden sollen `[$DD_CLI_TAGS]`

`--test-id value, --ti value`                      
* Die ID des Tests, in den die Befunde erneut importiert werden sollen. (Standard: 0) `[$DD_CLI_TEST_ID]`

`--test-name value, --tn value`                    
* Der Name des Tests, in den die Befunde importiert werden sollen - standardmäßig der Name des Scan-Typs. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`                   
* Die Version des Tests. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`                                   
* Legt fest, ob Befunde beim Import auf Verifiziert gesetzt werden. Der Wert True setzt Befunde zwingend auf Verifiziert.  Wenn kein Wert gesetzt ist, richtet sich der Status Verifiziert stattdessen nach der eingehenden Berichtsdatei. `[$DD_CLI_VERIFIED]`

**Einstellungen:**

`--config value, -c value`
* Der Pfad zur TOML-Konfigurationsdatei, mit der Werte für die Optionen gesetzt werden. Wenn eine Option sowohl in der Konfigurationsdatei als auch in der CLI gesetzt ist, wird der in der CLI gesetzte Wert verwendet. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* Die URL der DefectDojo-Instanz, in die die Befunde importiert werden sollen. (erforderlich). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* Ignoriert TLS-Validierungsfehler bei der Verbindung zur angegebenen DefectDojo-Instanz. Die meisten Benutzer sollten dieses Flag nicht aktivieren. (Standard: false) `[$DD_CLI_INSECURE_TLS]`

### Export

#### Verwendung

```
defectdojo-cli export <required options> [optional options]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --config ./config-file-path
	or: defectdojo-cli [global options] export --config ./config-file-path --json ./output_file_path.json
	or: defectdojo-cli [global options] export --config ./config-file-path --csv ./output_file_path.csv
	or: defectdojo-cli export [-h | --help]
	or: defectdojo-cli export example [subcommand options]
	or: defectdojo-cli export example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

Um Befunde mit DefectDojo-CLI zu exportieren, müssen Sie eine Konfigurationsdatei angeben, die festlegt, welche Befunde Sie exportieren möchten.  Das entspricht der Methode GET Findings über die API.

Hilfe erhalten Sie mit `defectdojo-cli export --help`.

#### **Export-Beispiel**

Dieses Beispiel gibt die URL, das Exportformat und einige Filterparameter an, um eine Liste von Befunden zu erzeugen.

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
--json "./path/to/findings.json" \
--active "true" \
--created "Past 90 days"
```

#### Befehle

`example, x`
* Zeigt ein Beispiel für erforderliche und optionale Flags des Export-Vorgangs

`help, h`
* Zeigt eine Liste der Befehle oder die Hilfe zu einem Befehl

#### Optionen

**Befund-Filter:**

`--active true|false, -a true|false`
* Befunde nach dem Status Aktiv. `[$DD_CLI_FINDINGS_FILTERS_ACTIVE]`

`--created value`
* Befunde nach Erstellungsdatum. Unterstützte Werte: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_CREATED]`

`--cvssv3-score value`
* Befunde nach CVSS-v3-Score. (Standard: ignoriert) `[$DD_CLI_FINDINGS_FILTERS_CVSSV3_SCORE]`

`--cwe value` 
* Befunde nach CWE-ID. (Standard: ignoriert) `[$DD_CLI_FINDINGS_FILTERS_CWE]`

`--date value`
* Befunde nach Datum. Unterstützte Werte: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_DATE]`

`--discovered-after value`
* Befunde, die nach dem angegebenen Datum entdeckt wurden. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_AFTER]`

`--discovered-before value`
* Befunde, die vor dem angegebenen Datum entdeckt wurden. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_BEFORE]`

`--discovered-on value`
* Befunde nach Entdeckungsdatum. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_ON]`

`--duplicate true|false`
* Befunde nach dem Status Duplikat. `[$DD_CLI_FINDINGS_FILTERS_DUPLICATE]`

`--engagement-ids value [ --engagement-ids value ]`
* Befunde nach Engagement-IDs. Dieses Flag kann mehrfach oder als kommagetrennte Liste verwendet werden. `[$DD_CLI_FINDINGS_FILTERS_ENGAGEMENT]`

`--epss-percentile value`
* Befunde nach EPSS-Perzentil. (Standard: ignoriert) `[$DD_CLI_FINDINGS_FILTERS_EPSS_PERCENTILE]`

`--epss-score value`
* Befunde nach EPSS-Score. (Standard: ignoriert) `[$DD_CLI_FINDINGS_FILTERS_EPSS_SCORE]`

`--false-positive true|false`
* Befunde nach dem Status Falsch-positiv. `[$DD_CLI_FINDINGS_FILTERS_FALSE_POSITIVE]`

`--is-mitigated true|false`
* Befunde nach dem Status Behoben. `[$DD_CLI_FINDINGS_FILTERS_IS_MITIGATED]`

`--mitigated value`
* Befunde nach dem Zeitraum, in dem sie als behoben markiert wurden. Unterstützte Werte: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_MITIGATED]`

`--mitigated-after value`
* Befunde, die nach dem angegebenen Datum behoben wurden. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_AFTER]`

`--mitigated-before value`
* Befunde, die vor dem angegebenen Datum behoben wurden. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BEFORE]`

`--mitigated-by-ids value [ --mitigated-by-ids value ]`
* Befunde nach den Benutzer-IDs in mitigated_by. Dieses Flag kann mehrfach oder als kommagetrennte Liste verwendet werden. Kann mit --mitigated-by-names kombiniert werden. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_IDS]`

`--mitigated-by-names value [ --mitigated-by-names value ]`
* Befunde nach den Benutzernamen in mitigated_by. Dieses Flag kann mehrfach oder als kommagetrennte Liste verwendet werden. Kann mit --mitigated-by-ids kombiniert werden. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_NAMES]`

`--mitigated-on value`
* Befunde nach Behebungsdatum. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_ON]`

`--not-tags value [ --not-tags value ]`
* Befunde nach Tags, die nicht vorhanden sein sollen. Dieses Flag kann mehrfach oder als kommagetrennte Liste verwendet werden. `[$DD_CLI_FINDINGS_FILTERS_NOT_TAGS]`

`--out-of-scope true|false`
* Befunde nach dem Status Außerhalb des Geltungsbereichs oder innerhalb des Geltungsbereichs. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SCOPE]`

`--out-of-sla true|false`
* Befunde nach dem Status außerhalb oder innerhalb der SLA. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SLA]`

`--product-name value`
* Befunde nach Produktname. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME]`

`--product-name-contains value`
* Befunde, deren Produktname die angegebene Zeichenfolge enthält. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME_CONTAINS]`

`--product-type-ids value [ --product-type-ids value ]`
* Befunde nach Produkttyp-IDs. Dieses Flag kann mehrfach oder als kommagetrennte Liste verwendet werden. Kann mit --product-type-names kombiniert werden `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_IDS]`

`--product-type-names value [ --product-type-names value ]`
* Befunde nach Produkttypnamen. Dieses Flag kann mehrfach oder als kommagetrennte Liste verwendet werden. Kann mit --product-type-ids kombiniert werden `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_NAMES]`

`--risk-accepted true|false`
* Befunde nach dem Status Risiko akzeptiert. `[$DD_CLI_FINDINGS_FILTERS_RISK_ACCEPTED]`

`--severity value [ --severity value ]`
* Befunde nach Schweregrad. Gültige Werte sind: Critical, High, Medium, Low, Info. Dieses Flag kann mehrfach oder als kommagetrennte Liste verwendet werden. `[$DD_CLI_FINDINGS_FILTERS_SEVERITY]`

`--tags value [ --tags value ]`
* Befunde nach Tags, die vorhanden sein sollen. Dieses Flag kann mehrfach oder als kommagetrennte Liste verwendet werden. `[$DD_CLI_FINDINGS_FILTERS_TAGS]`

`--test-id value`
* Befunde nach Test-ID. (Standard: ignoriert) `[$DD_CLI_FINDINGS_FILTERS_TEST_ID]`

`--title-contains value`
* Befunde, deren Titel die angegebene Zeichenfolge enthält. `[$DD_CLI_FINDINGS_FILTERS_TITLE_CONTAINS]`

`--under-review true|false`
* Befunde nach dem Status In Prüfung. `[$DD_CLI_FINDINGS_FILTERS_UNDER_REVIEW]`

`--verified true|false`
* Befunde nach dem Status Verifiziert. (Standard: ignoriert) `[$DD_CLI_FINDINGS_FILTERS_VERIFIED]`

`--vulnerability-id value [ --vulnerability-id value ]`
* Befunde nach Schwachstellen-ID. Dieses Flag kann mehrfach oder als kommagetrennte Liste verwendet werden. `[$DD_CLI_FINDINGS_FILTERS_VULNERABILITY_ID]`

**Ausgabe der Befunde**

`--csv value`
* Pfad der Datei, in die die CSV-Datei der Befunde geschrieben wird. `[$DD_CLI_FINDINGS_OUTPUT_CSV_PATH_FILE]`

`--json value`  Pfad der Datei, in die die JSON-Datei der Befunde geschrieben wird. `[$DD_CLI_FINDINGS_OUTPUT_JSON_PATH_FILE]`

**Einstellungen**

`--config value, -c value`
Der Pfad zur TOML-Konfigurationsdatei, mit der Werte für die Optionen gesetzt werden. Wenn eine Option sowohl in der Konfigurationsdatei als auch in der CLI gesetzt ist, wird der in der CLI gesetzte Wert verwendet. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`
Die URL der DefectDojo-Instanz, in die die Befunde importiert werden sollen. (erforderlich). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
Ignoriert TLS-Validierungsfehler bei der Verbindung zur angegebenen DefectDojo-Instanz. Die meisten Benutzer sollten dieses Flag nicht aktivieren. (Standard: false) `[$DD_CLI_INSECURE_TLS]`

#### Export-Beispiel:

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
```

### Interactive

Im interaktiven Modus können Sie den Import- und Reimport-Vorgang Schritt für Schritt konfigurieren.

#### Verwendung

```
defectdojo-cli interactive
	or: defectdojo-cli interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: defectdojo-cli interactive [-h | --help]
```

#### Optionen

`--skip-intro `    
* Überspringt den Startbildschirm (Standard: false)

`--no-full-screen`
* Deaktiviert den Vollbildmodus (Standard: false)

`--log-path value`
* Pfad zur Logdatei

`--help, -h`
* Hilfe anzeigen

## Universal Importer

`universal-importer` integriert Scan-Ergebnisse nahtlos in DefectDojo und vereinfacht sowohl den Import als auch den Reimport von Befunden und zugehörigen Objekten. Das Tool ist auf einfache Bedienung ausgelegt und unterstützt verschiedene Endpunkte, sowohl für erste Importe als auch für nachfolgende Reimporte. Damit eignet es sich ideal für Benutzer, die eine robuste und flexible Interaktion mit der DefectDojo-API benötigen.

Universal Importer ähnelt DefectDojo-CLI, verfügt jedoch nicht über die Export-Funktion, und die Umgebungsvariablen sind anders benannt.

### Befehle

- [`import`](./#import-1)       Importiert Befunde in DefectDojo.
- [`reimport`](./#reimport-1)     Importiert Befunde erneut in DefectDojo.
- [`interactive`](./#interactive-1)   Startet einen interaktiven Modus, um den Import- und Reimport-Vorgang zu konfigurieren, Schritt für 

### Globale Optionen

`--help, -h`     
* Hilfe anzeigen

`--version, -v`
* Version ausgeben

#### CLI-Formatierung

`--no-color`
* Deaktiviert die farbige Ausgabe. (Standard: false) `[$DD_IMPORTER_NO_COLOR]`

`--no-emojis, --no-emoji`
* Deaktiviert Emojis in der Ausgabe. (Standard: false) `[$DD_IMPORTER_NO_EMOJIS]`

`--verbose`
* Aktiviert die ausführliche Ausgabe. (Standard: false) `[$DD_IMPORTER_VERBOSE]`

### Import

Verwenden Sie den Befehl import, um neue Befunde in DefectDojo zu importieren.

#### Verwendung

```
universal-importer [global options] import <required flags> [optional flags]
	or: universal-importer [global options] import  --config ./config-file-path
	or: universal-importer import [-h | --help]
	or: universal-importer import example [subcommand options]
	or: universal-importer import example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

`import` kann Befunde auf zwei Arten importieren:

**Nach ID:**
* Erstellen Sie ein Produkt (oder verwenden Sie ein bestehendes Produkt)
* Erstellen Sie ein Engagement innerhalb des Produkts
* Geben Sie die ID des Engagements im Parameter engagement an

In diesem Szenario wird ein neuer Test innerhalb des Engagements erstellt.

**Nach Name:**
* Erstellen Sie ein Produkt (oder verwenden Sie ein bestehendes Produkt)
* Erstellen Sie ein Engagement innerhalb des Produkts
* Geben Sie product-name an
* Geben Sie engagement-name an
* Geben Sie optional product-type-name an

In diesem Szenario ermittelt DefectDojo das Engagement anhand der angegebenen Details.

Wenn Sie Namen verwenden, können Sie Engagements, Produkte und Produkttypen mit `auto-create-context=true` automatisch vom Importer erstellen lassen.
Mit `deduplication-on-engagement` können Sie die Deduplizierung importierter Befunde auf das neu erstellte Engagement beschränken.


**Grundlegende Import-Syntax:**

```
universal-importer import [options]
```

#### **Import-Beispiel:**

```
universal-importer import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### Befehle

`example, x`
* Zeigt ein Beispiel für erforderliche und optionale Flags des Import-Vorgangs

#### Optionen

`--active, -a` 
* Legt fest, ob Befunde beim Import zwingend auf Aktiv oder Inaktiv gesetzt werden.  Der Wert True setzt Befunde auf Aktiv, der Wert False setzt alle Befunde auf Inaktiv.  Wenn kein Wert gesetzt ist, richtet sich der Status Aktiv stattdessen nach der eingehenden Berichtsdatei. `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* Die ID des API Scan Configuration-Objekts, das beim Import oder Reimport verwendet werden soll. (Standard: 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* Wenn auf true gesetzt, werden die Tags (aus der Option --tag) auf die Endpunkte angewendet (Standard: false) 
`[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* Wenn auf true gesetzt, werden die Tags (aus der Option --tag) auf die Befunde angewendet (Standard: false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* Wenn auf true gesetzt, erstellt der Importer automatisch Engagements, Produkte und Product_Types (Standard: false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Wenn True, werden beim Import alte Befunde, die nicht mehr im Bericht enthalten sind, als Behoben geschlossen. Wenn Service gesetzt ist, werden nur die Befunde für diesen Service geschlossen. [$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Legt fest, ob --close-old-findings für **alle** Befunde desselben Typs im Produkt gilt. Standardmäßig ist dies auf false gesetzt, das heißt, nur alte Befunde desselben Typs im Engagement fallen in den Geltungsbereich (und werden durch Close Old Findings geschlossen). [$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* Wenn auf true gesetzt, beschränkt der Importer die Deduplizierung importierter Befunde auf das neu erstellte Engagement. (Standard: false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* Die ID des Engagements, in das die Befunde importiert werden sollen. (Standard: 0) `[$DD_IMPORTER_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* Der Name des Engagements, in das die Befunde importiert werden sollen. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Legt den niedrigsten Schweregrad fest, der importiert werden soll. Gültige Werte sind: Critical, High, Medium, Low, Info. (Standard: "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* Der Name des Produkts, in das die Befunde importiert werden sollen. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* Der Name des Produkttyps, in den die Befunde importiert werden sollen. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* Der Pfad zu dem zu importierenden Bericht. (erforderlich). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`
* Der Scan-Typ des Tools (erforderlich). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Alle Tags, die auf das Test-Objekt angewendet werden sollen `[$DD_IMPORTER_TAGS]`

`--test-name value, --tn value`
* Der Name des Tests, in den die Befunde importiert werden sollen - standardmäßig der Name des Scan-Typs. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`
* Die Version des Tests. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`
* Legt fest, ob Befunde beim Import auf Verifiziert gesetzt werden. Der Wert True setzt Befunde zwingend auf Verifiziert.  Wenn kein Wert gesetzt ist, richtet sich der Status Verifiziert stattdessen nach der eingehenden Berichtsdatei. `[$DD_IMPORTER_VERIFIED]`

**Einstellungen:**

`--config value, -c value`          
* Der Pfad zur TOML-Konfigurationsdatei, mit der Werte für die Optionen gesetzt werden. Wenn eine Option sowohl in der Konfigurationsdatei als auch in der CLI gesetzt ist, wird der in der CLI gesetzte Wert verwendet. `[$DD_IMPORTER_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* Die URL der DefectDojo-Instanz, in die die Befunde importiert werden sollen. (erforderlich). `[$DD_IMPORTER_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          Ignoriert TLS-Validierungsfehler bei der Verbindung zur angegebenen DefectDojo-Instanz. Die meisten Benutzer sollten dieses Flag nicht aktivieren. (Standard: false) `[$DD_IMPORTER_INSECURE_TLS]`

### Reimport

Verwenden Sie den Befehl `reimport`, um einen bestehenden Test auf eine von zwei Arten um Befunde aus einem neuen Bericht zu erweitern:

Nach ID:
- Erstellen Sie ein Produkt (oder verwenden Sie ein bestehendes Produkt)
- Erstellen Sie ein Engagement innerhalb des Produkts
- Importieren Sie einen Scan-Bericht und ermitteln Sie die ID des Tests
- Geben Sie diese im Parameter test-id an

Nach Namen:
- Erstellen Sie ein Produkt (oder verwenden Sie ein bestehendes Produkt)
- Erstellen Sie ein Engagement innerhalb des Produkts
- Importieren Sie einen Bericht, wodurch ein Test erstellt wird
- Geben Sie product-name an
- Geben Sie engagement-name an
- Optional: Geben Sie test-name an

In diesem Szenario ermittelt DefectDojo den Test anhand der angegebenen Details. Wenn kein test-name angegeben wird, wird der neueste Test innerhalb des Engagements auf Basis des scan-type ausgewählt.

Wenn Sie Namen verwenden, können Sie Engagements, Produkte und Produkttypen mit `auto-create-context=true` automatisch vom Importer erstellen lassen.
Mit `deduplication-on-engagement` können Sie die Deduplizierung importierter Befunde auf das neu erstellte Engagement beschränken.

#### Verwendung

```
universal-importer [global options] reimport <required flags> [optional flags]
   or: universal-importer [global options] reimport  --config ./config-file-path
   or: universal-importer reimport [-h | --help]
   or: universal-importer reimport example [subcommand options]
   or: universal-importer reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

#### **Reimport-Beispiel:**

```
universal-importer reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### Befehle

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Optionen

`--active, -a`                                    
* Legt fest, ob Befunde beim Import zwingend auf Aktiv oder Inaktiv gesetzt werden.  Der Wert True setzt Befunde auf Aktiv, der Wert False setzt alle Befunde auf Inaktiv.  Wenn kein Wert gesetzt ist, richtet sich der Status Aktiv stattdessen nach der eingehenden Berichtsdatei. `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* Die ID des API Scan Configuration-Objekts, das beim Import oder Reimport verwendet werden soll. (Standard: 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* Wenn auf true gesetzt, werden die Tags (aus der Option --tag) auf die Endpunkte angewendet (Standard: false) `[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* Wenn auf true gesetzt, werden die Tags (aus der Option --tag) auf die Befunde angewendet (Standard: false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* Wenn auf true gesetzt, erstellt der Importer automatisch Engagements, Produkte und Product_Types (Standard: false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Wenn True, werden beim Import alte Befunde, die nicht mehr im Bericht enthalten sind, als Behoben geschlossen. Wenn Service gesetzt ist, werden nur die Befunde für diesen Service geschlossen. [$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Legt fest, ob --close-old-findings für **alle** Befunde desselben Typs im Produkt gilt. Standardmäßig ist dies auf false gesetzt, das heißt, nur alte Befunde desselben Typs im Engagement fallen in den Geltungsbereich (und werden durch Close Old Findings geschlossen). [$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* Wenn auf true gesetzt, beschränkt der Importer die Deduplizierung importierter Befunde auf das neu erstellte Engagement. (Standard: false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* Der Name des Engagements, in das die Befunde importiert werden sollen. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Legt den niedrigsten Schweregrad fest, der importiert werden soll. Gültige Werte sind: Critical, High, Medium, Low, Info. (Standard: "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* Der Name des Produkts, in das die Befunde importiert werden sollen. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* Der Name des Produkttyps, in den die Befunde importiert werden sollen. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* Der Pfad zu dem zu importierenden Bericht. (erforderlich). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`                      
* Der Scan-Typ des Tools (erforderlich). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Alle Tags, die auf das Test-Objekt angewendet werden sollen `[$DD_IMPORTER_TAGS]`

`--test-id value, --ti value`                      
* Die ID des Tests, in den die Befunde erneut importiert werden sollen. (Standard: 0) `[$DD_IMPORTER_TEST_ID]`

`--test-name value, --tn value`                    
* Der Name des Tests, in den die Befunde importiert werden sollen - standardmäßig der Name des Scan-Typs. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`                   
* Die Version des Tests. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`                                   
* Legt fest, ob Befunde beim Import auf Verifiziert gesetzt werden. Der Wert True setzt Befunde zwingend auf Verifiziert. Wenn kein Wert gesetzt ist, richtet sich der Status Verifiziert stattdessen nach der eingehenden Berichtsdatei. (Standard: nicht gesetzt) `[$DD_IMPORTER_VERIFIED]`

**Einstellungen:**

`--config value, -c value`
* Der Pfad zur TOML-Konfigurationsdatei, mit der Werte für die Optionen gesetzt werden. Wenn eine Option sowohl in der Konfigurationsdatei als auch in der CLI gesetzt ist, wird der in der CLI gesetzte Wert verwendet. `[$DD_IMPORTER_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* Die URL der DefectDojo-Instanz, in die die Befunde importiert werden sollen. (erforderlich). `[$DD_IMPORTER_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* Ignoriert TLS-Validierungsfehler bei der Verbindung zur angegebenen DefectDojo-Instanz. Die meisten Benutzer sollten dieses Flag nicht aktivieren. (Standard: false) `[$DD_IMPORTER_INSECURE_TLS]`

### Interactive
Im interaktiven Modus können Sie den Import- und Reimport-Vorgang Schritt für Schritt konfigurieren.

#### Verwendung

```
universal-importer interactive
	or: universal-importer interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: universal-importer interactive [-h | --help]
```

#### Optionen

`--skip-intro `    
* Überspringt den Startbildschirm (Standard: false)

`--no-full-screen`
* Deaktiviert den Vollbildmodus (Standard: false)
`--log-path value`
* Pfad zur Logdatei
`--help, -h`
* Hilfe anzeigen


## Fehlerbehebung

Wenn bei diesen Tools Probleme auftreten, prüfen Sie Folgendes:
- Stellen Sie sicher, dass Sie das richtige Binary für Ihr Betriebssystem und Ihre CPU-Architektur verwenden.
- Prüfen Sie, ob der API-Schlüssel in Ihren Umgebungsvariablen korrekt gesetzt ist.
- Prüfen Sie, ob die DefectDojo-URL korrekt und erreichbar ist.
- Stellen Sie beim Import sicher, dass die Berichtsdatei vorhanden ist und im unterstützten Format für den angegebenen Scan-Typ vorliegt.  Die von DefectDojo unterstützten Scanner finden Sie in unserer [Liste der unterstützten Tools](/supported_tools). 
