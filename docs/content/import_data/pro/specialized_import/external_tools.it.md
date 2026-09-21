---
title: Universal Importer & DefectDojo-CLI
description: Importa file in DefectDojo dalla riga di comando
draft: false
weight: 2
audience: pro
aliases:
- /it/en/connecting_your_tools/external_tools
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: i seguenti strumenti esterni sono funzionalità esclusive di DefectDojo Pro. Questi binari non funzioneranno a meno che non siano connessi a un'istanza con una licenza DefectDojo Pro.</span>

## Informazioni sugli strumenti esterni

`defectdojo-cli` e `universal-importer` sono strumenti da riga di comando progettati per semplificare i processi di importazione e reimportazione dei Riscontri e degli oggetti associati, rendendoli ideali per gli utenti che desiderano configurare rapidamente queste interazioni con l'API di DefectDojo.

DefectDojo-CLI offre le stesse funzionalità di Universal Importer, ma include anche la possibilità di esportare i Riscontri da DefectDojo in formato JSON o CSV.

## Installazione

1. Individua "Strumenti esterni" nel menu del tuo profilo utente:

2. Scarica il binario appropriato per il tuo sistema operativo dalla piattaforma.

![immagine](images/external-tools.png)

3. Estrai l'archivio scaricato in una directory a tua scelta. Facoltativamente, aggiungi la directory contenente il binario estratto al $PATH del tuo sistema per un accesso ripetuto.

**Nota: agli utenti Macintosh potrebbe essere impedito di eseguire DefectDojo-CLI o Universal Importer poiché si tratta di app di sviluppatori non identificati. Consulta [il supporto Apple](https://support.apple.com/en-ca/guide/mac-help/mh40616/mac) per le istruzioni su come rimuovere il blocco imposto da Apple.**  

**Utenti Windows: se ricevi l'errore "Couldn't download - virus detected", disattivare Smartscreen potrebbe risolvere il problema. In alternativa, utilizza un browser diverso per scaricare lo strumento dal portale Cloud.**

## Configurazione

Universal Importer e DefectDojo-CLI possono essere configurati tramite flag, variabili d'ambiente o un file di configurazione. La configurazione più importante è il token API, che deve essere impostato come variabile d'ambiente:

1. Aggiungi la tua chiave API alle variabili d'ambiente. 
Puoi recuperare la tua chiave API da: `https://YOUR_INSTANCE.cloud.defectdojo.com/api/key-v2`

oppure 

Tramite l'interfaccia utente di DefectDojo 
nel menu a discesa dell'utente in alto a destra:

![immagine](images/api-token.png)

2. Imposta la variabile d'ambiente per il token API.

**Per DefectDojo-CLI:**
	`export DD_CLI_API_TOKEN=YOUR_API_KEY`

**Per Universal Importer:**
	`export DD_IMPORTER_DOJO_API_TOKEN=YOUR_API_KEY`

Nota: su Windows, utilizza `set` al posto di `export`.

### Windows: uso di PowerShell

1. Apri PowerShell (tasto Windows, quindi cerca "PowerShell").
2. Imposta le variabili d'ambiente:
   - **Temporanea:**
     ```powershell
     $env:DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     $env:DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Permanente:**
     ```powershell
     [Environment]::SetEnvironmentVariable("DD_IMPORTER_DOJO_API_TOKEN", "[VALUE_FROM_DEFECTDOJO_API]", "Machine")
     ```
3. Riavvia la sessione di PowerShell.
4. Verifica l'impostazione:
   ```powershell
   echo $env:DD_IMPORTER_DOJO_API_TOKEN
   echo $env:DD_IMPORTER_DEFECTDOJO_URL
   ```

### Windows: uso del prompt dei comandi (account con privilegi amministrativi)
1. Apri il prompt dei comandi (tasto Windows, quindi cerca "Command Prompt").
2. Imposta le variabili d'ambiente:
   - **Temporanea:**
     ```cmd
     set DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     set DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Permanente:**
     ```cmd
     setx DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     setx DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```

### Uso delle impostazioni di Windows (account non amministrativi)
1. Premi `Win + I` per aprire la finestra di dialogo delle impostazioni di sistema.
2. Nella casella di ricerca, digita "environment".
3. Seleziona "Edit Environment variables for your account".
4. In "User variables for [username]", fai clic sul pulsante "New…".
5. Imposta la variabile:
   - **Nome variabile:** `DD_IMPORTER_DOJO_API_TOKEN`
   - **Valore variabile:** `[VALUE_FROM_DEFECTDOJO_API]`
6. Fai clic su "OK".
7. Ripeti i passaggi da 4 a 6 per la variabile DD_IMPORTER_DEFECTDOJO_URL
8. Riavvia eventuali finestre dei comandi aperte.
9. Verifica le impostazioni:
   ```cmd
   echo %DD_IMPORTER_DOJO_API_TOKEN%
   echo %DD_IMPORTER_DEFECTDOJO_URL%
   ```

## DefectDojo-CLI

`defectdojo-cli` integra perfettamente i risultati delle scansioni in DefectDojo, semplificando i processi di importazione e reimportazione dei Riscontri e degli oggetti associati. Progettato per essere facile da usare, lo strumento supporta vari endpoint, adattandosi sia alle importazioni iniziali sia alle reimportazioni successive — ideale per gli utenti che necessitano di un'interazione solida e flessibile con l'API di DefectDojo. DefectDojo-CLI può svolgere le stesse funzioni di `universal-importer` e aggiunge la funzionalità di esportazione dei Riscontri.

### Comandi

- [`import`](./#import)       Importa i riscontri in DefectDojo.
- [`reimport`](./#reimport)     Reimporta i riscontri in DefectDojo.
- [`export`](./#export)	Esporta i riscontri da DefectDojo.
- [`interactive`](./#interactive)   Avvia una modalità interattiva per configurare il processo di importazione e reimportazione, passo dopo 

### Opzioni globali

`--help, -h`     
* mostra la guida

`--version, -v`
* stampa la versione

#### Formattazione CLI

`--no-color`
* Disabilita l'output a colori. (predefinito: false) `[$DD_CLI_NO_COLOR]`
`--no-emojis, --no-emoji`

* Disabilita le emoji nell'output. (predefinito: false) `[$DD_CLI_NO_EMOJIS]`

* `--verbose`
Abilita l'output dettagliato. (predefinito: false) `[$DD_CLI_VERBOSE]`

### Import

Usa il comando import per importare nuovi riscontri in DefectDojo.

#### Utilizzo

```
defectdojo-cli [global options] import <required flags> [optional flags]
	or: defectdojo-cli [global options] import  --config ./config-file-path
	or: defectdojo-cli import [-h | --help]
	or: defectdojo-cli import example [subcommand options]
	or: defectdojo-cli import example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

`import` può importare i Riscontri in due modi:

**Per ID:**
* Crea un Prodotto (o utilizzane uno esistente)
* Crea un Engagement all'interno del prodotto
* Fornisci l'id dell'Engagement nel parametro engagement

In questo scenario, verrà creato un nuovo Test all'interno dell'Engagement.

**Per nome:**

* Crea un Prodotto (o utilizzane uno esistente)
* Crea un Engagement all'interno del prodotto
* Fornisci product-name
* Fornisci engagement-name
* Facoltativamente, fornisci product-type-name

In questo scenario, DefectDojo cercherà l'Engagement in base ai dettagli forniti.

Quando utilizzi i nomi, puoi lasciare che l'importer crei automaticamente Engagement, Prodotti e Product-type utilizzando `auto-create-context=true`.
Puoi usare `deduplication-on-engagement` per limitare la deduplicazione dei Riscontri importati al nuovo Engagement creato.


**Sintassi di base per l'import:**
```
defectdojo-cli import [options]
```

#### **Esempio di import:**
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

#### Comandi
`example, x`
* Mostra un esempio di flag obbligatori e facoltativi per l'operazione di import

#### Opzioni

`--active, -a` 
* Determina se i Riscontri devono essere forzati come Attivo o Inattivo durante l'import.  Un valore True forza i Riscontri su Attivo, mentre un valore False forza tutti i Riscontri su Inattivo.  Se non viene impostato alcun valore, lo stato Attivo dipenderà invece dal file di report in ingresso. (predefinito: non impostato) `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`
* L'ID dell'oggetto API Scan Configuration da utilizzare durante l'import o il reimport. (predefinito: 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* Se impostato su true, i tag (dall'opzione --tag) verranno applicati agli endpoint (predefinito: false) 
`[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* Se impostato su true, i tag (dall'opzione --tag) verranno applicati ai riscontri (predefinito: false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* Se impostato su true, l'importer crea automaticamente Engagement, Prodotti e Product_Type (predefinito: false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Se True, i vecchi Riscontri non più presenti nel report verranno chiusi come Mitigato durante l'import. Se è stato impostato Service, verranno chiusi solo i Riscontri relativi a questo Service. [$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Seleziona se --close-old-findings si applica a **tutti** i Riscontri dello stesso tipo nel Prodotto. Per impostazione predefinita, questo è impostato su false, il che significa che sono in ambito solo i vecchi Riscontri dello stesso tipo nell'Engagement (e verranno chiusi da Close Old Findings). [$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* Se impostato su true, l'importer limita la deduplicazione dei riscontri importati al nuovo Engagement creato. (predefinito: false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* L'ID dell'Engagement in cui importare i riscontri. (predefinito: 0) `[$DD_CLI_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* Il nome dell'Engagement in cui importare i riscontri. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Determina il livello di gravità minimo che deve essere importato. I valori validi sono: Critica, Alta, Media, Bassa, Info. (predefinito: "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* Il nome del Prodotto in cui importare i riscontri. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* Il nome del Product Type in cui importare i riscontri. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* Il percorso del report da importare. (obbligatorio). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`
* Il tipo di scansione dello strumento (obbligatorio). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Eventuali tag da applicare all'oggetto Test `[$DD_CLI_TAGS]`

`--test-name value, --tn value`
* Il nome del Test in cui importare i riscontri - Per impostazione predefinita corrisponde al nome del tipo di scansione. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`
* La versione del test. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`
* Determina se i Riscontri devono essere impostati su Verificato durante l'import. Un valore True forza i Riscontri su Verificato. Se non viene impostato alcun valore, lo stato Verificato dipenderà invece dal file di report in ingresso. `[$DD_CLI_VERIFIED]`

**Impostazioni:**

`--config value, -c value`          
* Il percorso del file di configurazione TOML viene utilizzato per impostare i valori delle opzioni. Se l'opzione è impostata sia nel file di configurazione sia nella CLI, verrà utilizzato il valore impostato dalla CLI. `[$DD_CLI_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* L'URL dell'istanza DefectDojo in cui importare i riscontri. (obbligatorio). `[$DD_CLI_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          ignora gli errori di convalida TLS durante la connessione all'istanza DefectDojo fornita. La maggior parte degli utenti non dovrebbe abilitare questo flag. (predefinito: false) `[$DD_CLI_INSECURE_TLS]`

### Reimport

Usa il comando `reimport` per estendere un Test esistente con i Riscontri di un nuovo report in uno dei due modi seguenti:

Per ID:
- Crea un Prodotto (o utilizzane uno esistente)
- Crea un Engagement all'interno del prodotto
- Importa un report di scansione e trova l'id del Test
- Fornisci questo valore nel parametro test-id

Per nomi:
- Crea un Prodotto (o utilizzane uno esistente)
- Crea un Engagement all'interno del prodotto
- Importa un report che creerà un Test
- Fornisci product-name
- Fornisci engagement-name
- Facoltativo: fornisci test-name

In questo scenario, DefectDojo cercherà il Test in base ai dettagli forniti. Se non viene fornito alcun test-name, verrà scelto l'ultimo test all'interno dell'engagement in base allo scan-type.

Quando utilizzi i nomi, puoi lasciare che l'importer crei automaticamente Engagement, Prodotti e Product-type utilizzando `auto-create-context=true`.
Puoi usare `deduplication-on-engagement` per limitare la deduplicazione dei Riscontri importati al nuovo Engagement creato.

#### Utilizzo

```
defectdojo-cli [global options] reimport <required flags> [optional flags]
   or: defectdojo-cli [global options] reimport  --config ./config-file-path
   or: defectdojo-cli reimport [-h | --help]
   or: defectdojo-cli reimport example [subcommand options]
   or: defectdojo-cli reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

#### **Esempio di reimport:**

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

#### Comandi

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Opzioni

`--active, -a`                                    
* Determina se i Riscontri devono essere forzati come Attivo o Inattivo durante l'import.  Un valore True forza i Riscontri su Attivo, mentre un valore False forza tutti i Riscontri su Inattivo.  Se non viene impostato alcun valore, lo stato Attivo dipenderà invece dal file di report in ingresso. `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`

* L'ID dell'oggetto API Scan Configuration da utilizzare durante l'import o il reimport. (predefinito: 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* Se impostato su true, i tag (dall'opzione --tag) verranno applicati agli endpoint (predefinito: false) `[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* Se impostato su true, i tag (dall'opzione --tag) verranno applicati ai riscontri (predefinito: false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* Se impostato su true, l'importer crea automaticamente Engagement, Prodotti e Product_Type (predefinito: false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Se True, i vecchi Riscontri non più presenti nel report verranno chiusi come Mitigato durante l'import. Se è stato impostato Service, verranno chiusi solo i riscontri relativi a questo Service.[$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Seleziona se --close-old-findings si applica a **tutti** i Riscontri dello stesso tipo nel Prodotto. Per impostazione predefinita, questo è impostato su false, il che significa che sono in ambito solo i vecchi Riscontri dello stesso tipo nell'Engagement (e verranno chiusi da Close Old Findings). [$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* Se impostato su true, l'importer limita la deduplicazione dei riscontri importati al nuovo Engagement creato. (predefinito: false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* Il nome dell'Engagement in cui importare i riscontri. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Determina il livello di gravità minimo che deve essere importato. I valori validi sono: Critica, Alta, Media, Bassa, Info. (predefinito: "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* Il nome del Prodotto in cui importare i riscontri. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* Il nome del Product Type in cui importare i riscontri. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* Il percorso del report da importare. (obbligatorio). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`                      
* Il tipo di scansione dello strumento (obbligatorio). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Eventuali tag da applicare all'oggetto Test `[$DD_CLI_TAGS]`

`--test-id value, --ti value`                      
* L'ID del Test in cui reimportare i riscontri. (predefinito: 0) `[$DD_CLI_TEST_ID]`

`--test-name value, --tn value`                    
* Il nome del Test in cui importare i riscontri - Per impostazione predefinita corrisponde al nome del tipo di scansione. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`                   
* La versione del test. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`                                   
* Determina se i Riscontri devono essere impostati su Verificato durante l'import. Un valore True forza i Riscontri su Verificato.  Se non viene impostato alcun valore, lo stato Verificato dipenderà invece dal file di report in ingresso. `[$DD_CLI_VERIFIED]`

**Impostazioni:**

`--config value, -c value`
* Il percorso del file di configurazione TOML viene utilizzato per impostare i valori delle opzioni. Se l'opzione è impostata sia nel file di configurazione sia nella CLI, verrà utilizzato il valore impostato dalla CLI. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* L'URL dell'istanza DefectDojo in cui importare i riscontri. (obbligatorio). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* ignora gli errori di convalida TLS durante la connessione all'istanza DefectDojo fornita. La maggior parte degli utenti non dovrebbe abilitare questo flag. (predefinito: false) `[$DD_CLI_INSECURE_TLS]`

### Export

#### Utilizzo

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

Per esportare i Riscontri da DefectDojo-CLI, dovrai fornire un file di configurazione contenente i dettagli che spiegano quali Riscontri desideri esportare. Questo è simile al metodo GET Findings tramite l'API.

Per assistenza, usa `defectdojo-cli export --help`.

#### **Esempio di export**

Questo esempio specifica l'URL, il formato di esportazione e alcuni parametri di filtro per creare un elenco di Riscontri.

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
--json "./path/to/findings.json" \
--active "true" \
--created "Past 90 days"
```

#### Comandi

`example, x`
* Mostra un esempio di flag obbligatori e facoltativi per l'operazione di export

`help, h`
* Mostra un elenco di comandi o la guida per un singolo comando

#### Opzioni

**Filtri sui Riscontri:**

`--active true|false, -a true|false`
* Riscontri per stato attivo. `[$DD_CLI_FINDINGS_FILTERS_ACTIVE]`

`--created value`
* Riscontri per data di creazione. Valori supportati: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_CREATED]`

`--cvssv3-score value`
* Riscontri per punteggio CVSS v3. (predefinito: ignorato) `[$DD_CLI_FINDINGS_FILTERS_CVSSV3_SCORE]`

`--cwe value` 
* Riscontri per ID CWE. (predefinito: ignorato) `[$DD_CLI_FINDINGS_FILTERS_CWE]`

`--date value`
* Riscontri per data. Valori supportati: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_DATE]`

`--discovered-after value`
* Riscontri scoperti dopo la data specificata. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_AFTER]`

`--discovered-before value`
* Riscontri scoperti prima della data specificata. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_BEFORE]`

`--discovered-on value`
* Riscontri per data di scoperta. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_ON]`

`--duplicate true|false`
* Riscontri per stato di duplicato. `[$DD_CLI_FINDINGS_FILTERS_DUPLICATE]`

`--engagement-ids value [ --engagement-ids value ]`
* Riscontri per ID engagement. Questo flag può essere usato più volte oppure come elenco separato da virgole. `[$DD_CLI_FINDINGS_FILTERS_ENGAGEMENT]`

`--epss-percentile value`
* Riscontri per percentile EPSS. (predefinito: ignorato) `[$DD_CLI_FINDINGS_FILTERS_EPSS_PERCENTILE]`

`--epss-score value`
* Riscontri per punteggio EPSS. (predefinito: ignorato) `[$DD_CLI_FINDINGS_FILTERS_EPSS_SCORE]`

`--false-positive true|false`
* Riscontri per stato di falso positivo. `[$DD_CLI_FINDINGS_FILTERS_FALSE_POSITIVE]`

`--is-mitigated true|false`
* Riscontri per stato di mitigazione. `[$DD_CLI_FINDINGS_FILTERS_IS_MITIGATED]`

`--mitigated value`
* Riscontri per l'intervallo di date in cui sono stati contrassegnati come mitigati. Valori supportati: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_MITIGATED]`

`--mitigated-after value`
* Riscontri mitigati dopo la data specificata. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_AFTER]`

`--mitigated-before value`
* Riscontri mitigati prima della data specificata. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BEFORE]`

`--mitigated-by-ids value [ --mitigated-by-ids value ]`
* Riscontri per ID utente mitigated_by. Questo flag può essere usato più volte oppure come elenco separato da virgole. Può essere combinato con --mitigated-by-names. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_IDS]`

`--mitigated-by-names value [ --mitigated-by-names value ]`
* Riscontri per nomi utente mitigated_by. Questo flag può essere usato più volte oppure come elenco separato da virgole. Può essere combinato con --mitigated-by-ids. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_NAMES]`

`--mitigated-on value`
* Riscontri per data di mitigazione. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_ON]`

`--not-tags value [ --not-tags value ]`
* Riscontri per tag che non devono essere presenti. Questo flag può essere usato più volte oppure come elenco separato da virgole. `[$DD_CLI_FINDINGS_FILTERS_NOT_TAGS]`

`--out-of-scope true|false`
* Riscontri per stato fuori ambito o in ambito. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SCOPE]`

`--out-of-sla true|false`
* Riscontri per stato fuori o dentro l'SLA. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SLA]`

`--product-name value`
* Riscontri per nome del prodotto. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME]`

`--product-name-contains value`
* Riscontri per nome del prodotto contenente. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME_CONTAINS]`

`--product-type-ids value [ --product-type-ids value ]`
* Riscontri per ID tipo di prodotto. Questo flag può essere usato più volte oppure come elenco separato da virgole. Può essere combinato con --product-type-names `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_IDS]`

`--product-type-names value [ --product-type-names value ]`
* Riscontri per nomi del tipo di prodotto. Questo flag può essere usato più volte oppure come elenco separato da virgole. Può essere combinato con --product-type-ids `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_NAMES]`

`--risk-accepted true|false`
* Riscontri per stato di rischio accettato. `[$DD_CLI_FINDINGS_FILTERS_RISK_ACCEPTED]`

`--severity value [ --severity value ]`
* Riscontri per gravità. I valori validi sono: Critica, Alta, Media, Bassa, Info. Questo flag può essere usato più volte oppure come elenco separato da virgole. `[$DD_CLI_FINDINGS_FILTERS_SEVERITY]`

`--tags value [ --tags value ]`
* Riscontri per tag che devono essere presenti. Questo flag può essere usato più volte oppure come elenco separato da virgole. `[$DD_CLI_FINDINGS_FILTERS_TAGS]`

`--test-id value`
* Riscontri per ID del test. (predefinito: ignorato) `[$DD_CLI_FINDINGS_FILTERS_TEST_ID]`

`--title-contains value`
* Riscontri che contengono la stringa specificata nel titolo. `[$DD_CLI_FINDINGS_FILTERS_TITLE_CONTAINS]`

`--under-review true|false`
* Riscontri per stato in revisione. `[$DD_CLI_FINDINGS_FILTERS_UNDER_REVIEW]`

`--verified true|false`
* Riscontri per stato verificato. (predefinito: ignorato) `[$DD_CLI_FINDINGS_FILTERS_VERIFIED]`

`--vulnerability-id value [ --vulnerability-id value ]`
* Riscontri per ID vulnerabilità. Questo flag può essere usato più volte oppure come elenco separato da virgole. `[$DD_CLI_FINDINGS_FILTERS_VULNERABILITY_ID]`

**Output dei Riscontri**

`--csv value`
* Percorso del file in cui verrà scritto il file CSV dei riscontri. `[$DD_CLI_FINDINGS_OUTPUT_CSV_PATH_FILE]`

`--json value`  Percorso del file in cui verrà scritto il file JSON dei riscontri. `[$DD_CLI_FINDINGS_OUTPUT_JSON_PATH_FILE]`

**Impostazioni**

`--config value, -c value`
Il percorso del file di configurazione TOML viene utilizzato per impostare i valori delle opzioni. Se l'opzione è impostata sia nel file di configurazione sia nella CLI, verrà utilizzato il valore impostato dalla CLI. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`
L'URL dell'istanza DefectDojo in cui importare i riscontri. (obbligatorio). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
ignora gli errori di convalida TLS durante la connessione all'istanza DefectDojo fornita. La maggior parte degli utenti non dovrebbe abilitare questo flag. (predefinito: false) `[$DD_CLI_INSECURE_TLS]`

#### Esempio di export:

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
```

### Interactive

La modalità interattiva ti consente di configurare il processo di importazione e reimportazione, passo dopo passo.

#### Utilizzo

```
defectdojo-cli interactive
	or: defectdojo-cli interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: defectdojo-cli interactive [-h | --help]
```

#### Opzioni

`--skip-intro `    
* Salta la schermata introduttiva (predefinito: false)

`--no-full-screen`
* Disabilita la modalità a schermo intero (predefinito: false)

`--log-path value`
* Percorso del file di log

`--help, -h`
* mostra la guida

## Universal Importer

`universal-importer` integra perfettamente i risultati delle scansioni in DefectDojo, semplificando sia i processi di importazione sia quelli di reimportazione dei riscontri e degli oggetti associati. Progettato per essere facile da usare, lo strumento supporta vari endpoint, adattandosi sia alle importazioni iniziali sia alle reimportazioni successive — ideale per gli utenti che necessitano di un'interazione solida e flessibile con l'API di DefectDojo.

Pur essendo simile a DefectDojo-CLI, Universal Importer non dispone della funzionalità di Export e le variabili d'ambiente sono codificate in modo diverso.

### Comandi

- [`import`](./#import-1)       Importa i riscontri in DefectDojo.
- [`reimport`](./#reimport-1)     Reimporta i riscontri in DefectDojo.
- [`interactive`](./#interactive-1)   Avvia una modalità interattiva per configurare il processo di importazione e reimportazione, passo dopo 

### Opzioni globali

`--help, -h`     
* mostra la guida

`--version, -v`
* stampa la versione

#### Formattazione CLI

`--no-color`
* Disabilita l'output a colori. (predefinito: false) `[$DD_IMPORTER_NO_COLOR]`

`--no-emojis, --no-emoji`
* Disabilita le emoji nell'output. (predefinito: false) `[$DD_IMPORTER_NO_EMOJIS]`

`--verbose`
* Abilita l'output dettagliato. (predefinito: false) `[$DD_IMPORTER_VERBOSE]`

### Import

Usa il comando import per importare nuovi riscontri in DefectDojo.

#### Utilizzo

```
universal-importer [global options] import <required flags> [optional flags]
	or: universal-importer [global options] import  --config ./config-file-path
	or: universal-importer import [-h | --help]
	or: universal-importer import example [subcommand options]
	or: universal-importer import example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

`import` può importare i Riscontri in due modi:

**Per ID:**
* Crea un Prodotto (o utilizzane uno esistente)
* Crea un Engagement all'interno del prodotto
* Fornisci l'id dell'Engagement nel parametro engagement

In questo scenario verrà creato un nuovo Test all'interno dell'Engagement.

**Per nome:**
* Crea un Prodotto (o utilizzane uno esistente)
* Crea un Engagement all'interno del prodotto
* Fornisci product-name
* Fornisci engagement-name
* Facoltativamente, fornisci product-type-name

In questo scenario DefectDojo cercherà l'Engagement in base ai dettagli forniti.

Quando utilizzi i nomi, puoi lasciare che l'importer crei automaticamente Engagement, Prodotti e Product-type utilizzando `auto-create-context=true`.
Puoi usare `deduplication-on-engagement` per limitare la deduplicazione dei Riscontri importati al nuovo Engagement creato.


**Sintassi di base per l'import:**

```
universal-importer import [options]
```

#### **Esempio di import:**

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

#### Comandi

`example, x`
* Mostra un esempio di flag obbligatori e facoltativi per l'operazione di import

#### Opzioni

`--active, -a` 
* Determina se i Riscontri devono essere forzati come Attivo o Inattivo durante l'import.  Un valore True forza i Riscontri su Attivo, mentre un valore False forza tutti i Riscontri su Inattivo.  Se non viene impostato alcun valore, lo stato Attivo dipenderà invece dal file di report in ingresso. `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* L'ID dell'oggetto API Scan Configuration da utilizzare durante l'import o il reimport. (predefinito: 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* Se impostato su true, i tag (dall'opzione --tag) verranno applicati agli endpoint (predefinito: false) 
`[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* Se impostato su true, i tag (dall'opzione --tag) verranno applicati ai riscontri (predefinito: false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* Se impostato su true, l'importer crea automaticamente Engagement, Prodotti e Product_Type (predefinito: false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Se True, i vecchi Riscontri non più presenti nel report verranno chiusi come Mitigato durante l'import. Se è stato impostato Service, verranno chiusi solo i riscontri relativi a questo Service. [$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Seleziona se --close-old-findings si applica a **tutti** i Riscontri dello stesso tipo nel Prodotto. Per impostazione predefinita, questo è impostato su false, il che significa che sono in ambito solo i vecchi Riscontri dello stesso tipo nell'Engagement (e verranno chiusi da Close Old Findings). [$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* Se impostato su true, l'importer limita la deduplicazione dei riscontri importati al nuovo Engagement creato. (predefinito: false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* L'ID dell'Engagement in cui importare i riscontri. (predefinito: 0) `[$DD_IMPORTER_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* Il nome dell'Engagement in cui importare i riscontri. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Determina il livello di gravità minimo che deve essere importato. I valori validi sono: Critica, Alta, Media, Bassa, Info. (predefinito: "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* Il nome del Prodotto in cui importare i riscontri. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* Il nome del Product Type in cui importare i riscontri. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* Il percorso del report da importare. (obbligatorio). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`
* Il tipo di scansione dello strumento (obbligatorio). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Eventuali tag da applicare all'oggetto Test `[$DD_IMPORTER_TAGS]`

`--test-name value, --tn value`
* Il nome del Test in cui importare i riscontri - Per impostazione predefinita corrisponde al nome del tipo di scansione. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`
* La versione del test. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`
* Determina se i Riscontri devono essere impostati su Verificato durante l'import. Un valore True forza i Riscontri su Verificato.  Se non viene impostato alcun valore, lo stato Verificato dipenderà invece dal file di report in ingresso. `[$DD_IMPORTER_VERIFIED]`

**Impostazioni:**

`--config value, -c value`          
* Il percorso del file di configurazione TOML viene utilizzato per impostare i valori delle opzioni. Se l'opzione è impostata sia nel file di configurazione sia nella CLI, verrà utilizzato il valore impostato dalla CLI. `[$DD_IMPORTER_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* L'URL dell'istanza DefectDojo in cui importare i riscontri. (obbligatorio). `[$DD_IMPORTER_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          ignora gli errori di convalida TLS durante la connessione all'istanza DefectDojo fornita. La maggior parte degli utenti non dovrebbe abilitare questo flag. (predefinito: false) `[$DD_IMPORTER_INSECURE_TLS]`

### Reimport

Usa il comando `reimport` per estendere un Test esistente con i Riscontri di un nuovo report in uno dei due modi seguenti:

Per ID:
- Crea un Prodotto (o utilizzane uno esistente)
- Crea un Engagement all'interno del prodotto
- Importa un report di scansione e trova l'id del Test
- Fornisci questo valore nel parametro test-id

Per nomi:
- Crea un Prodotto (o utilizzane uno esistente)
- Crea un Engagement all'interno del prodotto
- Importa un report che creerà un Test
- Fornisci product-name
- Fornisci engagement-name
- Facoltativo: fornisci test-name

In questo scenario DefectDojo cercherà il Test in base ai dettagli forniti. Se non viene fornito alcun test-name, verrà scelto l'ultimo test all'interno dell'engagement in base allo scan-type.

Quando utilizzi i nomi, puoi lasciare che l'importer crei automaticamente Engagement, Prodotti e Product-type utilizzando `auto-create-context=true`.
Puoi usare `deduplication-on-engagement` per limitare la deduplicazione dei Riscontri importati al nuovo Engagement creato.

#### Utilizzo

```
universal-importer [global options] reimport <required flags> [optional flags]
   or: universal-importer [global options] reimport  --config ./config-file-path
   or: universal-importer reimport [-h | --help]
   or: universal-importer reimport example [subcommand options]
   or: universal-importer reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

#### **Esempio di reimport:**

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

#### Comandi

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Opzioni

`--active, -a`                                    
* Determina se i Riscontri devono essere forzati come Attivo o Inattivo durante l'import.  Un valore True forza i Riscontri su Attivo, mentre un valore False forza tutti i Riscontri su Inattivo.  Se non viene impostato alcun valore, lo stato Attivo dipenderà invece dal file di report in ingresso. `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* L'ID dell'oggetto API Scan Configuration da utilizzare durante l'import o il reimport. (predefinito: 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* Se impostato su true, i tag (dall'opzione --tag) verranno applicati agli endpoint (predefinito: false) `[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* Se impostato su true, i tag (dall'opzione --tag) verranno applicati ai riscontri (predefinito: false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* Se impostato su true, l'importer crea automaticamente Engagement, Prodotti e Product_Type (predefinito: false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Se True, i vecchi Riscontri non più presenti nel report verranno chiusi come Mitigato durante l'import. Se è stato impostato Service, verranno chiusi solo i Riscontri relativi a questo Service. [$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Seleziona se --close-old-findings si applica a **tutti** i Riscontri dello stesso tipo nel Prodotto. Per impostazione predefinita, questo è impostato su false, il che significa che sono in ambito solo i vecchi Riscontri dello stesso tipo nell'Engagement (e verranno chiusi da Close Old Findings). [$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* Se impostato su true, l'importer limita la deduplicazione dei riscontri importati al nuovo Engagement creato. (predefinito: false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* Il nome dell'Engagement in cui importare i riscontri. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Determina il livello di gravità minimo che deve essere importato. I valori validi sono: Critica, Alta, Media, Bassa, Info. (predefinito: "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* Il nome del Prodotto in cui importare i riscontri. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* Il nome del Product Type in cui importare i riscontri. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* Il percorso del report da importare. (obbligatorio). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`                      
* Il tipo di scansione dello strumento (obbligatorio). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Eventuali tag da applicare all'oggetto Test `[$DD_IMPORTER_TAGS]`

`--test-id value, --ti value`                      
* L'ID del Test in cui reimportare i riscontri. (predefinito: 0) `[$DD_IMPORTER_TEST_ID]`

`--test-name value, --tn value`                    
* Il nome del Test in cui importare i riscontri - Per impostazione predefinita corrisponde al nome del tipo di scansione. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`                   
* La versione del test. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`                                   
* Determina se i Riscontri devono essere impostati su Verificato durante l'import. Un valore True forza i Riscontri su Verificato. Se non viene impostato alcun valore, lo stato Verificato dipenderà invece dal file di report in ingresso. (predefinito: non impostato) `[$DD_IMPORTER_VERIFIED]`

**Impostazioni:**

`--config value, -c value`
* Il percorso del file di configurazione TOML viene utilizzato per impostare i valori delle opzioni. Se l'opzione è impostata sia nel file di configurazione sia nella CLI, verrà utilizzato il valore impostato dalla CLI. `[$DD_IMPORTER_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* L'URL dell'istanza DefectDojo in cui importare i riscontri. (obbligatorio). `[$DD_IMPORTER_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* ignora gli errori di convalida TLS durante la connessione all'istanza DefectDojo fornita. La maggior parte degli utenti non dovrebbe abilitare questo flag. (predefinito: false) `[$DD_IMPORTER_INSECURE_TLS]`

### Interactive
La modalità interattiva ti consente di configurare il processo di importazione e reimportazione, passo dopo passo.

#### Utilizzo

```
universal-importer interactive
	or: universal-importer interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: universal-importer interactive [-h | --help]
```

#### Opzioni

`--skip-intro `    
* Salta la schermata introduttiva (predefinito: false)

`--no-full-screen`
* Disabilita la modalità a schermo intero (predefinito: false)
`--log-path value`
* Percorso del file di log
`--help, -h`
* mostra la guida


## Risoluzione dei problemi

Se riscontri problemi con questi strumenti, controlla quanto segue:
- Assicurati di utilizzare il binario corretto per il tuo sistema operativo e la tua architettura CPU.
- Verifica che la chiave API sia impostata correttamente nelle variabili d'ambiente.
- Controlla che l'URL di DefectDojo sia corretto e accessibile.
- Durante l'import, conferma che il file di report esista e sia nel formato supportato per il tipo di scansione specificato.  Puoi consultare l'elenco degli scanner supportati da DefectDojo nella nostra [lista degli strumenti supportati](/supported_tools). 
