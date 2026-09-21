---
title: 🌐 Universal Parser
description: ''
draft: 'false'
weight: 1
audience: pro
aliases:
- /it/en/connecting_your_tools/universal_parser
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: l'Universal Parser è disponibile solo in DefectDojo Pro.</span>

L'Universal Parser è attivo per ogni istanza di DefectDojo Pro; non è necessario abilitare nulla. Per maggiori informazioni, consultate la nostra [presentazione di annuncio](https://community.defectdojo.com/universalparser).

## Informazioni sull'Universal Parser
DefectDojo dispone di un'ampia libreria di parser, aggiornata regolarmente, per aiutare i team di sicurezza ad acquisire dati.  Tuttavia, a volte gli utenti dispongono di uno strumento non supportato dai parser, oppure desiderano importare i dati nel modello di DefectDojo in modo diverso rispetto a come fa il parser.

L'Universal Parser di DefectDojo è pensato per offrire agli utenti con tipi di report non supportati un modo per procedere, importando e mappando **qualsiasi file JSON, CSV o XML**.

**L'Universal Parser è:**

* Un modo rapido per supportare formati di file per i quali non disponiamo di parser Community, come i report prodotti da strumenti interni
* Uno strumento che vi aiuta ad acquisire dati, anche se un parser Community non è aggiornato o non struttura i riscontri come desiderate
* Un'alternativa alla scrittura di script personalizzati per trasformare i report degli strumenti nel formato CSV/JSON previsto dal tipo di scansione "Generic Findings Import"
* Progettato per essere facile da usare per chiunque, senza necessità di programmazione e con una configurazione minima

**L'Universal Parser non è:**

* Un sostituto completo dei parser open source, dei Connector o dei report "Generic Findings Import" curati manualmente
* In grado di gestire una logica ramificata e sofisticata per strutturare i riscontri

La configurazione dell'Universal Parser è disponibile solo nella UI Pro, anche se è comunque possibile importare scansioni utilizzando un Universal Parser tramite la vecchia UI o l'API.

## Fase 1: Creazione di un nuovo Universal Parser

Potete creare un nuovo Universal Parser facendo clic sul pulsante "New Universal Parser" nella barra di navigazione, nella sezione "Import", oppure dal link presente nella pagina "Add Findings".

![image](images/universal_parser.png)

La prima schermata vi chiederà un file di scansione e un nome per il parser.

![image](images/universal_parser_2.png)

Il file dovrebbe:

* Avere un'estensione riconosciuta (vedere di seguito le estensioni di file supportate)
* Contenere un numero sufficiente di oggetti simili a riscontri da essere rappresentativo di report reali, ovvero uno che includa valori in tutti i campi opzionali
* Non superare circa 1-2MB - oltre questo punto, in genere si otterrà solo un'analisi del file più lenta, senza alcun vantaggio

Il nome del parser verrà utilizzato durante la creazione del Test_Type per questo nuovo parser. Troverete il vostro Universal Parser appena creato nel menu a discesa dei tipi di scansione nella pagina "Add Findings", con un nome del tipo "Universal Parser - MyCustomParser". I nomi dei parser devono essere univoci per evitare confusione al momento di selezionare un tipo di scansione per le importazioni.

## Fase 2: Mappatura dei campi del Riscontro

![image](images/universal_parser_3.png)

Dopo aver caricato un file di scansione di esempio, selezionato un nome per il parser e fatto clic su "Next", la pagina successiva vi permetterà di configurare il modo in cui questo Universal Parser popolerà i campi dei riscontri quando questa configurazione viene utilizzata per eseguire le importazioni. Sulla destra troverete una selezione di campi riscontro di DefectDojo (campi di output). I menu a discesa a sinistra di ciascun campo di output vi permettono di selezionare quale/i elemento/i (campi di input) della struttura del vostro file di scansione debba/debbano essere utilizzato/i per popolarli.

Esempio:

Se avete caricato un file di scansione in formato JSON simile a questo:

```
{
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345",
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "LOW",
            "CVE": "CVE-2025-54321",
            ...
        },
        ...

    ]
}
```

Vedrete una rappresentazione gerarchica dei campi univoci rilevati in base alla struttura del file di input, con icone che indicano il tipo di ciascun campo (se è possibile determinarlo). Potrete quindi selezionare il campo di input "title" nel menu a discesa che popola il campo di output "Title", il campo di input "description" può essere abbinato al campo di output "Description", e così via. 

I nomi dei campi di input non devono necessariamente corrispondere ai nomi dei campi di output, e il vostro file di scansione potrebbe non avere un equivalente per tutti i campi di output di DefectDojo.

### Campi del riscontro mappabili

La tabella seguente elenca ogni campo riscontro di DefectDojo (campo di output) a cui è possibile mappare un campo di input. Il vostro file di scansione non avrà necessariamente un equivalente per tutti — mappate solo ciò che è presente.

* **Obbligatorio** — questo campo di output deve avere almeno un campo di input mappato prima di poter salvare il parser.
* **Accetta più input** — questo campo di output può essere popolato da più di un campo di input. Quando ne mappate diversi, ogni valore viene presentato sotto un'intestazione con il nome del rispettivo campo di input (vedere [Campi a selezione multipla](#multi-select-fields)).

| Campo di output | Obbligatorio | Accetta più input | Descrizione |
|---|:---:|:---:|---|
| Title | ✅ | | Una breve descrizione del difetto. |
| Severity | ✅ | | Il livello di gravità di questo difetto (Critica, Alta, Media, Bassa, Info). Il valore predefinito è "Info" se sconosciuto. |
| Description | ✅ | ✅ | Informazioni più dettagliate e descrittive sul difetto. |
| Date | | | La data in cui il difetto è stato scoperto. |
| CWE | | | Il numero CWE associato a questo difetto. |
| CVSS v3 Vector | | | Il vettore Common Vulnerability Scoring System versione 3 (CVSSv3) associato a questo difetto. |
| CVSS v4 Vector | | | Il vettore Common Vulnerability Scoring System versione 4 (CVSSv4) associato a questo difetto. |
| Mitigation | | ✅ | Testo che descrive come correggere al meglio il difetto. |
| Impact | | ✅ | Testo che descrive l'impatto che questo difetto ha su sistemi, prodotti, azienda, ecc. |
| References | | ✅ | La documentazione esterna disponibile per questo difetto. |
| Severity Justification | | ✅ | Testo che descrive il motivo per cui è stata associata una determinata gravità a questo difetto. |
| Steps to Reproduce | | ✅ | Testo che descrive i passaggi da seguire per riprodurre il difetto / bug. |
| Component Name | | | Nome del componente interessato (nome della libreria, parte di un sistema, ...). |
| Component Version | | | Versione del componente interessato. |
| File Path | | | File identificati che contengono il difetto. |
| Line Number | | | Numero di riga sorgente del vettore di attacco. |
| Active | | | Indica se questo difetto è attivo o meno. Il valore predefinito è true. |
| Verified | | | Indica se questo difetto è stato verificato manualmente dal tester. Il valore predefinito è false. |
| False Positive | | | Indica se questo difetto è stato considerato un falso positivo dal tester. Il valore predefinito è false. |
| Duplicate | | | Indica se questo difetto è un duplicato di altri difetti segnalati. Il valore predefinito è false. |
| EPSS Score | | | Punteggio EPSS per la CVE — quanto è probabile che la vulnerabilità venga sfruttata nei prossimi 30 giorni. Il valore deve essere compreso tra 0,0 e 1,0. |
| EPSS Percentile | | | Percentile EPSS per la CVE — quante CVE hanno un punteggio pari o inferiore a questa. Il valore deve essere compreso tra 0,0 e 1,0. |
| Unique ID From Tool | | | ID tecnico della vulnerabilità proveniente dallo strumento di origine. Consente il tracciamento di vulnerabilità univoche. |
| Vuln ID from Tool | | | ID tecnico non univoco proveniente dallo strumento di origine, associato al tipo di vulnerabilità. |
| Tags | | | Tag testuali che aiutano a descrivere questo riscontro. |
| Endpoints | | | Gli host/URL all'interno del prodotto che sono soggetti a questo difetto. |
| Vulnerability IDs | | | Uno o più identificatori di advisory di vulnerabilità associati a questo riscontro (più comunemente, CVE). |

> **Nota:** Nell'esempio precedente, un campo di input `CVE` verrebbe mappato al campo di output **Vulnerability IDs** — DefectDojo non dispone di un campo riscontro chiamato letteralmente "CVE".

### Campi obbligatori
I seguenti campi di output richiedono una mappatura con un campo di input:

* Title
* Severity
* Description

### Informazioni sulle gravità
Un Universal Parser accetterà qualsiasi variazione di maiuscole/minuscole delle gravità di DefectDojo - "CRITICAL", "Critical", "cRiTiCaL", ecc. - e la applicherà ai vostri riscontri. Qualsiasi valore che non corrisponda a una gravità di DefectDojo verrà sostituito con "Info". Questo rispecchia il modo in cui funzionano oggi i parser e i Connector: i valori sconosciuti vengono generalmente mappati su "Info".

### Campi a selezione multipla
Alcuni campi di output accetteranno più campi di input. Se decidete di selezionare più di un campo di input, forniremo il valore di quel campo sotto un'intestazione con il nome di quel campo di input.

Esempio

`description`

Questo è stato estratto da un campo chiamato "description" nel file di input

`detailed_description`

Questo è stato estratto da un campo chiamato "detailed_description" nel file di input

## Fase 3: Anteprima dei Riscontri

Una volta selezionate le mappature dai campi di input ai campi di output, potete fare clic sul pulsante "Next" per vedere un'anteprima di come appariranno i Riscontri del vostro file di input una volta importati in DefectDojo con la configurazione scelta. Alcuni campi avranno un pulsante di "espansione" accanto per permettervi di vedere il MarkDown completo e renderizzato di come apparirà quel campo. Verranno visualizzate in anteprima solo le prime 25 Riscontri del vostro file di input, ma potrete anche vedere quanti riscontri sono stati rilevati nell'intero file di scansione.

Se le anteprime non corrispondono a quanto vi aspettavate, potete premere il pulsante "Back" per modificare le mappature. Una volta soddisfatti della configurazione, fate clic sul pulsante "Submit" per creare il vostro nuovo Universal Parser. Questo non eseguirà automaticamente un'importazione.

Una volta creato il vostro Universal Parser, sarete reindirizzati alla pagina "Add Findings" dove potrete caricare e importare un file di scansione che corrisponda alla struttura del file di esempio fornito nella Fase 1.

## Note aggiuntive sulla configurazione dell'Universal Parser

### Scegliere i campi di input corretti

Ogni fornitore può produrre formati di report di scansione molto diversi tra loro, alcuni dei quali si adatteranno al modello di riscontro di DefectDojo meglio di altri. Consentiamo una notevole flessibilità in ciò che accettiamo, ma dobbiamo imporre una certa struttura per garantire che i riscontri non vengano alterati nella traduzione dall'input all'output. Sebbene possiamo gestire campi di input opzionali, non accettiamo campi "globali", ovvero campi che compaiono un numero di volte diverso rispetto al numero di oggetti riscontro.

#### Esempio

```
{
    "scan_type": "MyToolScan", // <- There is only one instance of this field, which doesn't match the number of findings
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345", // <- This optional field only appears in Finding 1 - that's okay!
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "CRITICAL",
            ...  // <- While there is no "CVE" field here, we can still query for it and simply default to a null value
        },
        ... 5 more findings ...
    ],
    "global_details": [
        {
            "nested_detail": "Global detail 1"
        },
        {
            "nested_detail": "Global detail 2" // <- The number of "global_details" objects (2) does not match the number of individual finding objects (7)
        }

    ]
}
```

## Dopo aver salvato un Universal Parser

Potete modificare il Test_Type associato al vostro Universal Parser per cambiare:
* Se è "attivo" o meno. In caso contrario, non comparirà come opzione nel menu a discesa "Scan Type" della pagina "Add Findings"
* Se i suoi riscontri devono essere contrassegnati come "static" o "dynamic"
* Potete modificare i codici hash di deduplicazione same-tool e cross-tool, così come i codici hash di reimportazione, per il vostro Universal Parser in "Enterprise Settings". Per impostazione predefinita, vengono popolati solo i codici hash di deduplicazione same-tool e di reimportazione, con i valori obbligatori Title, Severity e Description.

## Ciclo di vita: creazione, disattivazione, riattivazione

Il ciclo di vita di un Universal Parser è **di sola creazione**, senza possibilità di modifica o eliminazione dall'interfaccia. Una volta creato un parser, la configurazione di mappatura dei campi non può essere modificata, e il parser stesso non può essere rimosso dalla UI — questo è voluto, perché le configurazioni dell'Universal Parser sono legate a record Test_Type che potrebbero essere referenziati da Riscontri, Test e cronologia di importazione esistenti.

Quello che **potete** fare dalla UI:

* **Disattivare** un parser per nasconderlo dal menu a discesa "Scan Type" in fase di importazione. Aprite **Import → Universal Parser** nella barra laterale per vedere tutti i vostri Universal Parser, e disattivate il toggle "Active". (In alternativa, potete modificare il Test_Type sottostante e deselezionare "active".) I parser disattivati non compaiono più come opzione di Scan Type nella pagina **Add Findings**, ma i Test esistenti importati con questo parser non ne risentono e continuano a funzionare.
* **Riattivare** un parser dalla stessa schermata riattivando il toggle "Active".
* **Modificare i campi del Test_Type** descritti nella sezione precedente (attivo/inattivo, static/dynamic, codici hash di deduplicazione).

### Flusso di lavoro consigliato quando cambia il formato di report di uno scanner

Poiché la configurazione di mappatura dei campi viene bloccata una volta creato un parser, il flusso di lavoro standard per gestire un cambiamento di formato nello scanner sottostante consiste nel **passare a un nuovo parser** anziché cercare di modificare quello vecchio:

1. **Create un nuovo Universal Parser** utilizzando un campione del nuovo formato di report (vedere Fase 1). Assegnategli un nome distinto — ad esempio aggiungendo `v2` o una data al nome originale.
2. **Passate le nuove importazioni** nella vostra pipeline CI/CD o nel flusso di lavoro della UI al tipo di scansione del nuovo parser.
3. **Disattivate il vecchio parser** una volta confermato che quello nuovo produce i riscontri attesi. I Test già importati con il vecchio parser rimangono in DefectDojo e possono ancora essere sottoposti a triage; solo le nuove importazioni vengono indirizzate al nuovo parser.

Se avete bisogno di rimuovere in modo permanente la configurazione di un parser (ad esempio perché contiene nomi di campo sensibili), contattate [DefectDojo Support](mailto:support@defectdojo.com).

## Una nota sulla mappatura delle gravità

L'Universal Parser **non** dispone di un campo di mappatura delle gravità configurabile. La gravità viene mappata automaticamente secondo queste regole:

* Qualsiasi variazione di maiuscole/minuscole di una gravità di DefectDojo viene accettata — `CRITICAL`, `Critical`, `cRiTiCaL`, `critical` vengono tutti mappati su **Critica**. Lo stesso vale per `High`, `Medium`, `Low` e `Info`.
* Qualsiasi valore che **non** corrisponde a una delle cinque gravità di DefectDojo viene mappato su **Info**.

Questo comportamento è identico per tutti i parser di DefectDojo (parser integrati, Connector e Universal Parser).

Se uno scanner che state cercando di acquisire utilizza etichette di gravità che non corrispondono a quelle di DefectDojo (ad es. "warning", "note", o punteggi CVSS numerici), l'Universal Parser mapperà tutti quei valori non corrispondenti su Info. Se avete bisogno di una mappatura diversa, la soluzione migliore oggi è **trasformare i valori di gravità a monte** — ad esempio, nella vostra pipeline CI prima del caricamento — in modo che i valori ricevuti da DefectDojo siano già uno dei cinque nomi di gravità di DefectDojo.
