---
title: Test
description: Informazioni sui Test in DefectDojo Pro
audience: pro
weight: 4
---

Organizzazioni → Asset → Engagement → **TEST** → Riscontri

## Panoramica

Un Test è un contenitore per una o più esecuzioni di scansione, utilizzate per individuare le falle in un Asset. I Test sono il componente finale e più granulare della gerarchia degli oggetti di DefectDojo, e fungono da contenitore per i Riscontri risultanti dall'esecuzione di uno strumento di sicurezza o di una valutazione manuale, aggiungendo anche il contesto in cui tali Riscontri sono stati individuati (ovvero quale strumento li ha segnalati, quando è stato eseguito l'ultima volta, ecc.).

Esempi di Test includono:
- Test di sicurezza delle applicazioni statiche
- Test di sicurezza delle applicazioni dinamiche
- Analisi della composizione del software
- Scansioni di sicurezza dei container
- Scansioni di infrastruttura/rete
- Penetration test manuali
- Scansioni della pipeline CI/CD

### Tipi di Test

Esistono diversi modi per creare Test in DefectDojo, tra cui i **parser specifici per fornitore** (ad es. Burp, OWASP ZAP, Acunetix, Invicti), il **Generic Findings Import**, l'**Universal Parser** e i **Connectors**.

Questi metodi possono creare nuovi Test o reimportare i Riscontri in Test esistenti, a seconda della configurazione e della strategia di deduplicazione.

Sebbene ciascun metodo differisca principalmente nel modo in cui i dati di scansione vengono analizzati e importati, tutti si traducono infine nell'associazione dei Riscontri a un Test.

#### Parser

I **parser** sono componenti che elaborano formati di output di scansione specifici (ad es. XML, JSON, CSV) e li mappano nel modello di Riscontro interno di DefectDojo. Quando i risultati della scansione vengono importati, DefectDojo utilizza il parser selezionato per estrarre i Riscontri e collegarli a un Test appena creato o già esistente.

#### Generic Findings Import

Quando non esiste un parser nativo per un determinato strumento, [**Generic Findings Import**](/supported_tools/parsers/generic_findings_import) consente di importare i riscontri utilizzando uno schema JSON o CSV standardizzato, indipendentemente dalla fonte originale.

DefectDojo analizza i dati forniti, crea un nuovo Test (o li importa in uno esistente) e collega i Riscontri. Viene inoltre creato un Tipo di Test corrispondente in base al campo opzionale `type` del report: quando `type` viene omesso (o è uguale al tipo di scansione) il Tipo di Test è “Generic Findings Import”; quando `type` viene fornito diventa “`{type}` Scan (Generic Findings Import)” (un `type` che termina già con il suffisso “(Generic Findings Import)” viene utilizzato così com'è).

#### Universal Parser

[**Universal Parser**](/supported_tools/parsers/universal_parser) consente agli utenti di definire come i dati di input arbitrari vengono mappati nel modello di Riscontro di DefectDojo. Dopo aver configurato il parser e caricato i dati di scansione, DefectDojo applica le regole di mappatura per estrarre i Riscontri, crea un Test (o ne aggiorna uno esistente) e associa i Riscontri a quel Test.

#### Connectors

I [**Connectors**](/connectors/upstream/about/) possono essere utilizzati per acquisire e organizzare automaticamente i dati sulle vulnerabilità provenienti da strumenti esterni tramite chiamate API. Una volta configurato, un Connector recupera i risultati della scansione, analizza i dati e crea nuovi Test o aggiorna quelli esistenti a seconda della sua configurazione. I Riscontri vengono quindi collegati al Test corrispondente.

#### Confronto dei meccanismi di creazione dei Test

| | **Parser nativi** | **Generic Findings Import** | **Universal Parser (Pro)** | **Connectors** |
|----------|---------------|------------------------|------------------------|------------|
| **Scopo principale** | Importa gli output degli strumenti supportati | Importa dati personalizzati/non supportati tramite uno schema fisso | Importa formati arbitrari tramite mappature configurabili | Sincronizza continuamente i sistemi esterni |
| **Formato di input** | Specifico per strumento (ad es. ZAP XML, SARIF) | Schema JSON/CSV rigoroso | Arbitrario (JSON, XML, ecc.) | Risposte API esterne |
| **Chi gestisce la normalizzazione** | DefectDojo (parser integrato) | Utente (deve conformarsi allo schema) | DefectDojo (tramite configurazione del parser) | Strumento esterno + DefectDojo |
| **Trigger di creazione del Test** | Caricamento manuale o importazione via API | Caricamento manuale o importazione via API | Caricamento manuale o importazione via API | Sincronizzazione automatica (pianificata o basata su eventi) |
| **Tipo di Test** | Predefinito (ad es. "ZAP Scan") | Tipo "Generic" creato automaticamente | Derivato dalla configurazione del parser | Dipende dal connector / parser sottostante |
| **Impegno di configurazione** | Basso | Moderato (richiede trasformazione dei dati) | Alto (configurazione del parser) | Da moderato ad alto (configurazione dell'integrazione) |
| **Flessibilità** | Bassa (solo strumenti supportati) | Media | Alta | Da media ad alta |
| **Livello di automazione** | Da basso a moderato | Da basso a moderato | Da basso a moderato | Alto |
| **Caso d'uso tipico** | Scanner standard (SAST, DAST, SCA) | Script personalizzati, strumenti non supportati | Formati complessi/personalizzati su larga scala | Integrazioni CI/CD, SCM o piattaforma |

Indipendentemente dal metodo di importazione, tutti i dati di scansione in DefectDojo sono infine rappresentati come Riscontri collegati a un Test, che funge da unità di esecuzione e di tracciamento del ciclo di vita.

### Dati del Test

I Test memorizzano una serie di metadati che aiutano a documentare i vari componenti di ogni sforzo di test, come:
- Titolo / nome del Test
- Tipo di Test
- Descrizione / note del Test
- Data di inizio e fine
- L'Ambiente in cui è stato eseguito il Test (ad es. Development, Staging, Pre-Production, Production, ecc.)
- Versione / Branch / Build ID / Commit Hash
- Configurazione della scansione API
- Personale associato al Test
- File aggiuntivi che possono essere utilizzati per controlli successivi o reimportazioni
- L'Engagement, l'Asset e l'Organizzazione principali
- Cronologia di importazione e reimportazione

Ogni Test mantiene una cronologia delle importazioni, che registra tutte le importazioni e reimportazioni di scansione associate al Test. Ogni voce della cronologia include metadati come data della scansione, versione, branch, commit hash e build ID.

Questa cronologia garantisce la tracciabilità tra più esecuzioni di scansione all'interno dello stesso Test.

### Autorizzazioni

È possibile memorizzare più Test all'interno di un singolo Engagement, e gli Engagement sono memorizzati all'interno degli Asset. Di conseguenza, l'accesso a un Asset garantisce automaticamente l'accesso a tutti i Test (ed Engagement) contenuti in quell'Asset. I Test non dispongono di elenchi di controllo degli accessi indipendenti.

## Accedere ai Test

È possibile accedere ai Test da varie sezioni dell'interfaccia utente di DefectDojo.

- La barra laterale

![image](images/tests_ss13.png)

- All'interno di un Engagement

![image](images/tests_ss14.png)

- La barra superiore di un Asset

![image](images/tests_ss15.png)

- La tabella dei metadati all'interno della visualizzazione di un Riscontro

![image](images/tests_ss16.png)

## Utilizzo dei Test

### Creare Test

I Test possono essere creati automaticamente quando i dati di scansione vengono importati direttamente in un Engagement, generando un nuovo Test contenente tali dati. I Test possono anche essere creati in previsione della pianificazione di futuri Engagement, oppure per riscontri di sicurezza inseriti manualmente che richiedono tracciamento e correzione.

#### Flussi di lavoro manuali

Per creare un Test, è necessario prima creare un Engagement che lo contenga, oltre a un Asset che conterrà quell'Engagement. Successivamente, esistono diversi modi per creare un Test:

- Nella barra laterale, sotto Test, all'interno della sottosezione **Manage**
    - Sarà necessario selezionare l'Engagement preesistente a cui attribuire il Test durante la compilazione del modulo Nuovo Test.

![image](images/tests_ss1.png)

- Il menu a discesa delle impostazioni nell'angolo in alto a destra della visualizzazione di un Asset
    - **Import Scan** creerà automaticamente un Test una volta aggiunto un file di scansione al modulo Import Scan. Avrai la possibilità di attribuire il Test a un Engagement preesistente oppure creare e denominare un nuovo Engagement per contenere il nuovo Test.
        - Durante la compilazione del modulo Import Scan, puoi aggiungere metadati come versione, branch tag, commit hash e build ID. Questo si rifletterà nella sezione Import History della visualizzazione del Test.

![image](images/tests_ss2.png)

- Il menu a discesa delle impostazioni in alto a destra della visualizzazione di un Engagement
    - **Import Scan** seguirà lo stesso flusso di lavoro degli Asset, ma posizionerà automaticamente l'oggetto Test all'interno dell'Engagement in cui hai fatto clic su Import Scan.
    - **Add Test** creerà un oggetto Test ma non richiede il caricamento di una scansione nel Test stesso, il che è utile in previsione della pianificazione di Test futuri o per riscontri di sicurezza inseriti manualmente che richiedono tracciamento e correzione.

![image](images/tests_ss3.png)

Se selezioni Add Test e desideri successivamente importare manualmente i risultati di una scansione in un Test, puoi farlo aprendo il Test e facendo clic sul pulsante Reimport Findings nelle impostazioni del Test oppure sul pulsante Reimport Scan nella tabella dei Riscontri.

![image](images/tests_ss21.png)

#### Flussi di lavoro automatizzati

Nei flussi di lavoro automatizzati, i Test possono essere creati a livello di codice come parte del processo di importazione della scansione, consentendo alle pipeline di caricare i risultati senza dover creare manualmente un Test in anticipo.

Quando si utilizza l'API o la CLI per importare i risultati della scansione, è possibile creare automaticamente un nuovo Test fornendo un `engagement` invece di un `test`.

##### API
curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`
In base a quanto sopra, viene creato un nuovo Test nell'Engagement specificato e i risultati della scansione vengono collegati a quel Test.

Se viene invece fornito un ID `test`, i risultati della scansione verranno aggiunti a un Test esistente, il che è comune nei flussi di lavoro di reimportazione.

##### CLI
defectdojo-cli import \
  --engagement-id 45 \
  --scan-type `"ZAP Scan"` \
GOog  --file report.xml
In base a quanto sopra, fornire un `engagement-id` crea un nuovo Test, mentre fornire un `test-id` riutilizza un Test esistente e reimporta i risultati della scansione in quel Test.

Consulta [DefectDojo-CLI](/import_data/pro/specialized_import/external_tools/#defectdojo-cli) per maggiori dettagli sui flag richiesti.

### Modificare i Test

I Test possono essere modificati facendo clic su **Edit Test** all'interno del menu a ingranaggio. Tutti i campi modificabili successivamente sono disponibili anche durante la creazione del Test.

### Eliminare i Test

È possibile eliminare un Test selezionando **Delete Test** dalle impostazioni del Test. Questa azione non può essere annullata.

L'eliminazione di un Test comporterà anche l'eliminazione di tutti i Riscontri contenuti al suo interno.

### Reimportazione dei risultati della scansione (UI)

Per aggiungere nuovi dati a un Test esistente, apri il Test a cui vuoi aggiungere i nuovi dati e fai clic sul pulsante Reimport Findings nelle impostazioni del Test oppure sul pulsante Reimport Scan nella tabella dei Riscontri.

![image](images/tests_ss21.png)

Durante la compilazione del modulo Reimport Scan, avrai la possibilità di aggiornare i metadati per la scansione in fase di reimportazione, tra cui versione, branch tag, commit hash e build ID. Queste modifiche si riflettono nella sezione Import History della visualizzazione del Test, che includerà anche gli stessi metadati delle importazioni di scansione precedenti.

Ad esempio, nello screenshot seguente, il branch tag, il build ID, il commit hash e la versione sono stati tutti aggiornati manualmente tra l'importazione iniziale e la reimportazione successiva.

![image](images/tests_ss23.png)

Per modificare i metadati della scansione reimportata più di recente, fai clic sull'icona a ingranaggio situata nell'angolo in alto a destra di una visualizzazione dell'Engagement e seleziona “Edit Test.” È possibile modificare solo i metadati dell'importazione più recente.

### Reimportazione dei risultati della scansione (API/CLI)

Quando i Test vengono creati o aggiornati tramite una pipeline CI/CD, è possibile includere i metadati dell'esecuzione della pipeline in modo che i Test possano essere correttamente collegati al codice che hanno scansionato. Questo ti consente di:
- Associare i risultati della scansione a un commit o branch specifico.
- Monitorare come i Riscontri evolvono nel corso delle modifiche al codice.
- Migliorare la Deduplicazione comprendendo quando due scansioni si riferiscono alla stessa versione del codice o a versioni diverse.
- Supportare la verificabilità mostrando esattamente quale codice è stato scansionato e quando.

La CLI e l'API di DefectDojo accettano questi valori durante l'importazione o la reimportazione, in modo che possano essere memorizzati come parte dell'importazione della scansione e riflessi nella cronologia delle importazioni del Test. Questi metadati possono essere utilizzati per identificare i commit hash o qualsiasi informazione pertinente sul repository associata a un'esecuzione CI/CD.

#### Campi di metadati supportati

L'API e la CLI supportano un insieme definito di campi di metadati che possono essere inclusi durante la reimportazione. Questi includono:

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- flag `active / verified`

Questi campi rappresentano il meccanismo principale per allegare metadati contestuali durante un'operazione di reimportazione.

Nelle pipeline automatizzate, i metadati più comunemente forniti includono:
- `build_id` (identificatore del job CI)
- `commit_hash` (riferimento al controllo di versione)
- `branch_tag` (contesto di branch o ambiente)
- `tags` (ad es. `nightly`, `staging`, `production`)

Questi campi garantiscono la tracciabilità tra le scansioni senza richiedere interventi manuali.

Sebbene i metadati possano essere aggiornati manualmente tramite il modulo Reimport Scan, la maggior parte degli ambienti automatizzati gestisce questa operazione chiamando direttamente l'endpoint `/api/v2/reimport-scan/` oppure utilizzando la CLI di DefectDojo (`defectdojo-cli reimport`) come parte del processo di build. Questo approccio consente alla pipeline di allegare automaticamente i metadati al momento della reimportazione.

##### Reimportazione API con metadati
curl -X POST `"https://<your-instance>/api/v2/reimport-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"test=123"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"` \
  -F `"tags=nightly,api-scan"` \
  -F `"version=1.4.2"` \
  -F `"build_id=jenkins-842"` \
  -F `"branch_tag=main"` \
  -F `"commit_hash=a1b2c3d4"`
##### Reimportazione CLI con metadati
defectdojo-cli import \
  --test-id 123 \
  --scan-type "ZAP Scan" \
  --file report.xml \
  --tag nightly \
  --tag api \
  --build-id jenkins-842 \
  --branch main \
  --commit a1b2c3d4
La CLI si associa direttamente allo stesso endpoint API e supporta lo stesso insieme di campi di metadati.

Ci sono alcune limitazioni di cui tenere conto quando si lavora con i metadati durante la reimportazione:
- L'API/CLI supporta solo parametri predefiniti. Non è possibile aggiungere metadati chiave-valore personalizzati durante la reimportazione
- Metadati aggiuntivi possono essere estratti direttamente dal file di scansione, a seconda del tipo di scansione e del parser.
- I metadati forniti durante la reimportazione non si comportano come un aggiornamento diretto dell'oggetto Test, a differenza delle modifiche manuali effettuate nell'interfaccia utente.

##### Metadati, reimportazione e scansioni pianificate

Le scansioni possono anche essere pianificate per essere eseguite a intervalli regolari, ad esempio tramite cron job. Le scansioni pianificate non sono legate all'attività del repository, il che rende irrilevanti metadati come i commit hash o i nomi dei branch, a meno che non vengano iniettati esplicitamente dallo script stesso. Ciò nonostante, l'uso della reimportazione può essere comunque utile se si preferisce mantenere un registro continuo della propria postura di sicurezza all'interno di un singolo Test.

## Reimportazione e Deduplicazione

La reimportazione delle scansioni all'interno dei Test è fondamentale per una deduplicazione efficace. Quando i risultati della scansione vengono reimportati nello stesso Test:

- I Riscontri esistenti possono essere aggiornati
- I Riscontri duplicati possono essere soppressi
- Nuovi Riscontri possono essere creati se non viene trovata alcuna corrispondenza

Questo comportamento dipende dalle regole di deduplicazione configurate e dal tipo di scansione.

La creazione di un nuovo Test anziché la reimportazione in uno esistente può comportare la creazione di Riscontri duplicati anziché il loro aggiornamento.

### Reimportazione vs. Importazione

La reimportazione viene generalmente utilizzata quando:

- Si eseguono scansioni ricorrenti sullo stesso target
- Si monitora come i Riscontri evolvono nel tempo
- Si mantiene una visione continua della postura di sicurezza dell'applicazione

Al contrario, l'importazione (creazione di un nuovo Test) è più adatta per esecuzioni di scansione una tantum o indipendenti.
