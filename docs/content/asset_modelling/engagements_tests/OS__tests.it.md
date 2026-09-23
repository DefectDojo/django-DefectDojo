---
title: Test
description: Comprendere i Test in DefectDojo OS
audience: opensource
weight: 4
---

Organizzazioni → Asset → Engagement → **TEST** → Riscontri

## Panoramica

Un Test è un contenitore per una o più esecuzioni di scansione, utilizzate per individuare le vulnerabilità in un Prodotto. I Test sono la componente finale e più granulare della gerarchia dei prodotti di DefectDojo, fungendo da contenitore per i Riscontri che derivano dall'esecuzione di uno strumento di sicurezza o di una valutazione manuale, aggiungendo al contempo il contesto in cui tali Riscontri sono stati individuati (ossia quale strumento li ha segnalati, quando tale strumento è stato eseguito l'ultima volta, ecc.).

Esempi di Test includono:
- Static Application Security Testing
- Dynamic Application Security Testing
- Software Composition Analysis
- Scansioni di sicurezza dei container
- Scansioni di infrastruttura / rete
- Penetration test manuali
- Scansioni di pipeline CI/CD

### Tipi di Test

Esistono due modi principali per creare Test in DefectDojo:
1. **Parser specifici per fornitore** (ad es. Burp, OWASP ZAP, Acunetix, Invicti)
2. **Generic Findings Import**

Ciascun metodo può creare nuovi Test o reimportare i Riscontri in Test esistenti, a seconda della configurazione e della strategia di deduplicazione.

Sebbene ciascun metodo differisca principalmente nel modo in cui i dati di scansione vengono analizzati e importati, alla fine tutti comportano l'associazione dei Riscontri a un Test.

#### Parser

I **Parser** sono componenti che elaborano formati di output di scansione specifici (ad es. XML, JSON, CSV) e li mappano nel modello interno dei Riscontri di DefectDojo. Quando i risultati di una scansione vengono importati, DefectDojo utilizza il parser selezionato per estrarre i Riscontri e collegarli a un Test appena creato o esistente.

#### Generic Findings Import

Quando non esiste un parser nativo per un determinato strumento, **Generic Findings Import** consente di importare i riscontri utilizzando uno schema JSON o CSV standardizzato, indipendentemente dalla fonte originale.

DefectDojo analizza i dati forniti, crea un nuovo Test (oppure importa in uno esistente) e collega i Riscontri. Viene inoltre creato un Test Type corrispondente in base al campo opzionale `type` del report: quando `type` viene omesso (o è uguale al tipo di scansione), il Test Type è “Generic Findings Import”; quando `type` viene fornito, diventa “{type} Scan (Generic Findings Import)” (un `type` che termina già con il suffisso “(Generic Findings Import)” viene utilizzato così com'è).

|  | **Parser nativi** | **Generic Findings Import** |
|----------|---------------|------------------------|
| **Scopo principale** | Importa gli output di strumenti supportati | Importa dati non supportati/personalizzati tramite uno schema fisso |
| **Formato di input** | Specifico per lo strumento (ad es. ZAP XML, SARIF) | Schema JSON/CSV rigoroso |
| **Chi gestisce la normalizzazione** | DefectDojo (parser integrato) | Utente (deve rispettare lo schema) |
| **Trigger di creazione del Test** | Caricamento manuale o import via API | Caricamento manuale o import via API |
| **Test Type** | Predefinito (ad es. “ZAP Scan”) | Tipo “Generic” creato automaticamente |
| **Impegno di configurazione** | Basso | Moderato (richiede trasformazione dei dati) |
| **Flessibilità** | Bassa (solo strumenti supportati) | Media |
| **Livello di automazione** | Basso–Moderato | Basso–Moderato |
| **Caso d'uso tipico** | Scanner standard (SAST, DAST, SCA) | Script personalizzati, strumenti non supportati |

Indipendentemente dal metodo di importazione, tutti i dati di scansione in DefectDojo vengono infine rappresentati come Riscontri collegati a un Test, che funge da unità di esecuzione e tracciamento del ciclo di vita.

### Dati del Test

I Test memorizzano una serie di metadati utili a documentare i vari aspetti di ciascuno sforzo di test, come:
- Titolo / nome del Test
- Tipo di Test
- Descrizione / note del Test
- Data di inizio e fine
- L'Ambiente in cui il Test è stato eseguito (ad es. Development, Staging, Pre-Production, Production, ecc.)
- Versione / Branch / Build ID / Commit Hash
- Configurazione della scansione API
- File aggiuntivi utilizzabili per audit o reimportazioni successive
- L'Engagement, l'Asset e l'Organizzazione principali
- Cronologia di importazione e reimportazione

Ogni Test mantiene una cronologia di importazione, che registra tutte le importazioni e reimportazioni di scansioni associate al Test. Questo include metadati come data della scansione, versione, branch, commit hash e build ID.

Questa cronologia garantisce la tracciabilità tra più esecuzioni di scansione all'interno dello stesso Test.

### Permessi

Più Test possono essere memorizzati all'interno di un singolo Engagement, e gli Engagement sono memorizzati all'interno dei Prodotti. Di conseguenza, l'accesso a un Prodotto concede automaticamente l'accesso a tutti i Test (ed Engagement) al suo interno. I Test non dispongono di elenchi di controllo degli accessi indipendenti.

### Accesso ai Test

Sebbene i Test esistano come oggetto indipendente in DefectDojo OS, non dispongono di una sezione specifica dedicata all'interno dell'interfaccia utente. Pertanto, ogni Test è accessibile principalmente tramite il Prodotto e/o l'Engagement che lo contiene.

### Vista Test

La vista Test ospita diverse tabelle, tra cui l'Engagement principale, la cronologia di importazione e reimportazione, un elenco dei Riscontri contenuti nel Test, nonché eventuali Gruppi di Riscontri.

Sono presenti anche tabelle per Potential Findings, File e Note, tutte aggiungibili manualmente.

#### Impostazioni del Test

Le seguenti impostazioni sono disponibili in ciascuna vista Test:
- **Edit Test**
    - Consente di modificare i dati del Test, come titolo, pianificazione, ambiente e altri dettagli.
- **Copy Test**
    - Duplica un Test, insieme a tutti i metadati e i Riscontri associati, e ne consente l'attribuzione a un Engagement diverso.
- **Re-Upload Scan**
    - Avvia il processo di reimportazione. Maggiori informazioni sulla reimportazione sono riportate più avanti in questo articolo.
- **Add Notes**
    - Consente all'utente di aggiungere una Nota. In fondo alla pagina è presente anche una tabella delle Note.
        - Una Nota può essere impostata come Private, nel qual caso non viene inviata a Jira, ai Report e alle esportazioni dei Riscontri.
- **Report**
    - Avvia il processo di generazione di un Report, in cui è possibile applicare numerosi filtri per creare un report contenente solo i Riscontri filtrati.
- **Add To Calendar**
    - Scarica un file .ics del Test selezionato, che può essere aggiunto alla vostra applicazione di calendario di terze parti.
- **View History**
    - Apre una cronologia delle modifiche apportate al Test a fini di tracciamento, reporting e audit.

## Lavorare con i Test

### Creare Test

I Test possono essere creati automaticamente quando i dati di scansione vengono importati direttamente in un Engagement, generando un nuovo Test contenente i dati della scansione. I Test possono anche essere creati in previsione della pianificazione di futuri Engagement, oppure per riscontri di sicurezza inseriti manualmente che richiedono tracciamento e remediation.

#### Flussi di lavoro manuali

Esistono diversi modi per creare un Test nella versione OS:

- Selezionate un Prodotto e fate clic su “Import Scan Results” nel menu Findings nella barra di navigazione
    - Questo creerà un Engagement ad hoc per contenere il Test

![image](images/tests_ss5.png)

- Selezionate un Engagement all'interno di un Prodotto, fate clic sul menu a discesa nella sottosezione Tests, quindi fate clic su “Add Tests” oppure su “Import Scan Results”
    - Questo creerà il Test risultante direttamente all'interno dell'Engagement scelto

![image](images/tests_ss6.png)

- Durante la creazione di un Engagement

![image](images/tests_ss7.png)

Utilizzando il terzo metodo sopra descritto, durante la creazione di un Engagement potete:

- Importare immediatamente i risultati di una scansione
- Creare un Test vuoto (nel quale importerete in seguito una scansione)
- Non fare nessuna delle due cose e limitarvi a creare l'Engagement facendo clic su “Done”

Avrete la possibilità di aggiungere metadati sia durante l'importazione di una scansione sia durante la creazione di un Test vuoto. Eventuali metadati verranno riportati nella sezione Import History della vista Test.

#### Flussi di lavoro automatizzati

Nei flussi di lavoro automatizzati, i Test possono essere creati a livello programmatico come parte del processo di importazione della scansione, consentendo alle pipeline di caricare i risultati senza che sia necessario creare un Test manualmente in anticipo.

Quando si utilizza l'API per importare i risultati di una scansione, è possibile creare automaticamente un nuovo Test fornendo un engagement anziché un test.

##### API

curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`

In base a quanto sopra, viene creato un nuovo Test all'interno dell'Engagement specificato e i risultati della scansione vengono collegati a quel Test.

Se viene invece fornito un ID `test`, i risultati della scansione verranno aggiunti a un Test esistente, come avviene comunemente nei flussi di reimportazione.

### Modificare i Test

I Test possono essere modificati facendo clic su **Edit Test** dal menu kebab ⋮ nella tabella Tests all'interno della vista dell'Engagement principale, oppure dal menu delle impostazioni nella vista del Test. Tutti i campi modificabili di seguito sono disponibili anche durante la creazione del Test.

![image](images/tests_ss24.png)

![image](images/tests_ss12.png)

#### Aggiungere manualmente Riscontri a un Test

Un Riscontro può essere aggiunto manualmente a un Test facendo clic su **Add Finding to Test** dal menu kebab ⋮ accanto al Test nella vista dell'Engagement principale, oppure dalle impostazioni della tabella Findings nella vista del Test.

![image](images/tests_ss29.png)

![image](images/tests_ss30.png)

### Eliminare i Test

È possibile eliminare un Test selezionando **Delete Test** dal menu kebab ⋮ accanto al Test nella vista dell'Engagement principale, oppure dal menu delle impostazioni nella vista del Test. Questa azione non può essere annullata.

L'eliminazione di un Test comporta anche l'eliminazione di tutti i Riscontri contenuti in quel Test.

![image](images/tests_ss25.png)

![image](images/tests_ss26.png)

## Reimportazione

La reimportazione delle scansioni all'interno dei Test è fondamentale per una deduplicazione efficace. Quando i risultati di una scansione vengono reimportati nello stesso Test:

- I Riscontri esistenti possono essere aggiornati
- I Riscontri duplicati possono essere soppressi
- Possono essere creati nuovi Riscontri se non viene trovata alcuna corrispondenza

Questo comportamento dipende dalle regole di deduplicazione configurate e dal tipo di scansione.

Creare un nuovo Test invece di reimportare in uno esistente può comportare la creazione di Riscontri duplicati anziché il loro aggiornamento.

#### Reimportazione vs. Importazione

La reimportazione viene tipicamente utilizzata quando:

- Si eseguono scansioni ricorrenti sullo stesso obiettivo
- Si monitora l'evoluzione dei Riscontri nel tempo
- Si mantiene una visione continua della postura di sicurezza applicativa

Al contrario, l'importazione (creazione di un nuovo Test) è più adatta per esecuzioni di scansione singole o indipendenti.

### Reimportazione dei risultati di scansione (interfaccia utente)

Per aggiungere nuovi dati a un Test esistente, potete fare clic su **Re-Upload Scan Results** dal menu kebab ⋮ accanto al Test nella vista dell'Engagement principale, oppure su **Re-Upload Scan** nel menu delle impostazioni della vista del Test.

![image](images/tests_ss27.png)

![image](images/tests_ss10.png)

Durante la compilazione del modulo Reimport Scan, avrete la possibilità di aggiornare i metadati della scansione in fase di reimportazione, tra cui versione, branch tag, commit hash e build ID.

Queste modifiche vengono riportate nella sezione Import History della vista Test, che includerà anche gli stessi metadati delle scansioni importate in precedenza.

Ad esempio, nella schermata seguente, branch tag, build ID, commit hash e versione sono stati tutti aggiornati manualmente tra l'importazione iniziale e la successiva reimportazione.

![image](images/tests_ss28.png)

Per modificare i metadati della scansione reimportata più di recente, seguite le istruzioni riportate nella sezione precedente Modificare i Test e aggiornate i metadati come desiderato. È possibile modificare solo i metadati dell'importazione più recente.

### Reimportazione dei risultati di scansione (API)

Quando i Test vengono creati o aggiornati tramite una pipeline CI/CD, è possibile includere metadati provenienti dall'esecuzione della pipeline, in modo che i Test possano essere collegati correttamente al codice che hanno scansionato. Questo consente di:
- Associare i risultati della scansione a un commit o branch specifico.
- Monitorare l'evoluzione dei Riscontri attraverso le modifiche al codice.
- Migliorare la Deduplicazione comprendendo quando due scansioni si applicano alla stessa versione del codice o a versioni diverse.
- Supportare la tracciabilità (auditability) mostrando esattamente quale codice è stato scansionato e quando.

L'API di DefectDojo accetta questi valori durante l'importazione o la reimportazione, in modo che possano essere memorizzati come parte dell'importazione della scansione e riportati nella cronologia di importazione del Test. Questi metadati possono essere utilizzati per identificare commit hash o qualsiasi altra informazione rilevante del repository associata a un'esecuzione CI/CD.

#### Campi di metadati supportati

L'API supporta un insieme definito di campi di metadati che possono essere inclusi durante la reimportazione. Tra questi:

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- flag `active / verified`

Questi campi rappresentano il meccanismo principale per collegare metadati contestuali durante un'operazione di reimportazione.

Nelle pipeline automatizzate, i metadati forniti più comunemente includono:
- build_id (identificatore del job CI)
- commit_hash (riferimento al controllo del codice sorgente)
- branch_tag (contesto di branch o ambiente)
- tags (ad es. nightly, staging, production)

Questi campi garantiscono la tracciabilità tra le scansioni senza richiedere alcun intervento manuale.

Sebbene i metadati possano essere aggiornati manualmente tramite il modulo Reimport Scan, la maggior parte degli ambienti automatizzati gestisce questa operazione chiamando direttamente l'endpoint `/api/v2/reimport-scan/`. Questo approccio consente alla pipeline di collegare automaticamente i metadati al momento della reimportazione.

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

##### Metadati, reimportazione e scansioni pianificate

Le scansioni possono anche essere pianificate per essere eseguite a intervalli regolari, ad esempio tramite job cron. Le scansioni pianificate non sono legate all'attività del repository, il che rende irrilevanti metadati come commit hash o nomi di branch, a meno che non vengano iniettati esplicitamente dallo script stesso. Ciononostante, l'uso della reimportazione può comunque essere utile se preferite mantenere un registro continuo della vostra postura di sicurezza all'interno di un singolo Test. 
