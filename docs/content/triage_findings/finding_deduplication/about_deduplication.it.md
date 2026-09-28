---
title: Informazioni sulla deduplicazione
description: Concetti fondamentali e principi chiave della deduplicazione
weight: 1
aliases:
- /it/en/working_with_findings/finding_deduplication/about_deduplication
- /it/en/working_with_findings/finding_deduplication/delete_deduplicates
- /it/en/working_with_findings/findings_workflows/manage_duplicate_findings
---

DefectDojo è progettato per importare in blocco report provenienti dai tool, creando uno o più Riscontri in base al contenuto del report. Quando si utilizza DefectDojo, è molto probabile importare regolarmente report dallo stesso tool, il che rende molto probabile la comparsa di Riscontri duplicati.

È qui che entra in gioco la Deduplicazione, una funzionalità intelligente che può essere configurata per gestire automaticamente i Riscontri duplicati.

## Come DefectDojo gestisce i duplicati

1. Innanzitutto, si importa **Test 1\.** Il report contiene una vulnerabilità che viene registrata come Riscontro A.
2. **In seguito, si importa il Test 2, che contiene la stessa vulnerabilità. Questa verrà registrata come Riscontro B, e il Riscontro B sarà contrassegnato come duplicato del Riscontro A.**
3. Più avanti, si importa **Test 3**, che contiene anch'esso quella vulnerabilità. Questa verrà registrata come Riscontro C, che sarà contrassegnato come duplicato del Riscontro A.

Creando e contrassegnando i Duplicati in questo modo, DefectDojo garantisce che tutto il lavoro relativo alla vulnerabilità "originale" sia centralizzato nella pagina del Riscontro originale, senza creare contesti separati né dare al team l'impressione che esistano più vulnerabilità distinte da affrontare.

### Quale Riscontro diventa l'originale

La Deduplicazione considera sempre come originale canonico il Riscontro creato per **primo** in una catena di duplicati, quindi un Riscontro proveniente da un'importazione precedente non viene mai declassato a duplicato di uno più recente: un originale già stabilito non cambia mai.

All'interno di un *singolo* report, l'ordine in cui lo scanner elenca i propri riscontri non determina il vincitore. I riscontri di una singola importazione vengono creati in un ordine stabile, derivato dal contenuto, quindi un report che contiene più riscontri in collisione sulla stessa chiave di deduplicazione produce **sempre lo stesso originale a ogni importazione**. Ripetere la scansione e reimportare gli stessi risultati non cambierà il Riscontro su cui il team sta lavorando.

Per impostazione predefinita, questi Test devono essere annidati sotto lo stesso Prodotto perché la Deduplicazione venga applicata. Se lo si desidera, è possibile limitare ulteriormente l'ambito della Deduplicazione a un singolo Engagement.

![Deduplication on product and engagement level](images/deduplication.png)

Per impostazione predefinita, i Riscontri duplicati vengono impostati su Inattivo. Questo non significa che il Riscontro duplicato in sé sia inattivo: piuttosto, serve a garantire che il team abbia un solo Riscontro attivo su cui lavorare e da correggere, con l'implicazione che, una volta Mitigato il Riscontro originale, anche i Duplicati verranno Mitigati.

## Deduplicazione in fase di reimportazione

La Deduplicazione e la Reimportazione sono processi simili, ma utilizzano algoritmi diversi per identificare le corrispondenze tra Riscontri.

* Quando si Reimporta in un Test, il processo di Reimportazione analizza i Riscontri in arrivo, **confronta i codici hash e quindi scarta eventuali corrispondenze**. Queste corrispondenze non verranno mai create come Riscontri o come Riscontri duplicati.

Tuttavia, eventuali Riscontri rimasti dopo la Deduplicazione in Reimportazione restano comunque soggetti alla Deduplicazione con lo stesso tool. Quindi, se si utilizza un ambito più ristretto per la Deduplicazione con lo stesso tool, si possono comunque ottenere Duplicati all'interno di una pipeline di Reimportazione.

### Esempio

Ecco un tool con un algoritmo di Deduplicazione in Reimportazione diverso dall'algoritmo di Deduplicazione con lo stesso tool.

| Algoritmo di deduplicazione | Campi del codice hash |
| ----- | ---- |
| Reimportazione | Title, CWE, Severity, Description, Line Number |
| Stesso tool | Title, CWE, Severity, Description |

Supponiamo di avere un Riscontro in DefectDojo con un determinato numero di riga. Si ripete la scansione dell'ambiente e il numero di riga di quella vulnerabilità cambia. Si reimporta nello stesso Test. Ecco cosa accade durante la reimportazione e la deduplicazione:

* Durante la Reimportazione, il Riscontro non verrà associato a nessun Riscontro già esistente, perché il numero di riga è diverso. Verrà quindi creato un nuovo Riscontro nel Test.
* Al termine della Reimportazione, verrà eseguito l'algoritmo di Deduplicazione con lo stesso tool. Questa Deduplicazione, in questa configurazione, non considera il numero di riga, quindi il nuovo Riscontro verrà etichettato come duplicato.

La Reimportazione può scartare completamente i Riscontri prima che vengano registrati, quindi le impostazioni di Deduplicazione in Reimportazione vanno modificate con cautela.

## Quando sono appropriati i duplicati?

I Duplicati sono utili quando si ha a che fare con contesti di test condivisi ma distinti. Ad esempio, se il Prodotto riceve i risultati dei Test per due repository diverse che devono essere confrontate, è utile sapere quali vulnerabilità sono condivise tra quelle repository.

Tuttavia, se DefectDojo crea un numero eccessivo di duplicati, questo può anche essere un segnale che occorre modificare le pipeline o i processi di importazione.

## Cosa indicano i miei duplicati?

* **La stessa vulnerabilità, ma rilevata in un contesto diverso:** questo è il modo appropriato di utilizzare i Riscontri duplicati. Se sono presenti molti componenti interessati dalla stessa vulnerabilità, probabilmente si vuole sapere quali componenti sono coinvolti per comprendere la portata del problema.
​
* **La stessa vulnerabilità, rilevata nello stesso contesto**: in questo caso esistono opzioni migliori. Se il Riscontro duplicato non fornisce alcun nuovo contesto sulla vulnerabilità, o se capita spesso di ignorare o eliminare i Riscontri duplicati, questo è un segnale che il processo può essere migliorato. Ad esempio, la Reimportazione consente di gestire in modo efficace i report in arrivo da una pipeline CI/CD. Anziché creare un oggetto Riscontro completamente nuovo per ogni duplicato, la Reimportazione registrerà il duplicato in arrivo senza creare affatto il Riscontro duplicato.

## Panoramica

DefectDojo Open Source supporta quattro algoritmi di deduplicazione selezionabili per ogni parser (tipo di test):

- **Unique ID From Tool**: utilizza l'identificatore univoco fornito dallo scanner.
- **Hash Code**: utilizza un insieme configurato di campi per calcolare un hash.
- **Unique ID From Tool or Hash Code**: preferisce l'ID univoco del tool; se non viene trovato un ID univoco corrispondente, ricorre all'hash.
- **Legacy**: algoritmo storico con più condizioni; disponibile solo nella versione Open Source.

**DefectDojo Pro ne aggiunge altri.** Due algoritmi aggiuntivi effettuano il confronto su **tutti i Prodotti** dell'istanza anziché all'interno di un singolo Prodotto o Engagement: **Global Component** (per nome e versione del componente) e **Global Vulnerability ID** (per CVE, GHSA, …). Entrambi sono disattivati per impostazione predefinita e vengono abilitati dal Supporto DefectDojo. Pro consente inoltre all'algoritmo Hash Code di trattare gli ID di vulnerabilità e i CWE di un Riscontro come **insiemi**, effettuando la corrispondenza sull'insieme esatto, su qualsiasi valore condiviso (`_partial`), oppure quando uno è un sottoinsieme dell'altro (`_subset`). Per l'elenco completo, i campi con corrispondenza a insieme e le regole che li governano, vedere [Deduplication Tuning (Pro)](/triage_findings/finding_deduplication/pro__deduplication_tuning/).

### Un'alternativa alla Deduplicazione: la Cronologia dei falsi positivi

Le istanze che scelgono deliberatamente di **non** deduplicare possono invece utilizzare [False Positive History](/triage_findings/finding_deduplication/false_positive_history/), che contrassegna automaticamente un Riscontro in arrivo come falso positivo quando un Riscontro corrispondente nello stesso Prodotto era già stato classificato in tal modo. È **mutuamente esclusiva con la Deduplicazione** — DefectDojo non consente di abilitare entrambe — ed è tuttora contrassegnata come sperimentale.

## Come vengono valutati gli endpoint per ciascun algoritmo

Gli Endpoint possono influenzare la deduplicazione in modi diversi a seconda dell'algoritmo e della configurazione.

### Unique ID From Tool

- La Deduplicazione utilizza `unique_id_from_tool` (o `vuln_id_from_tool`).
- **Gli Endpoint vengono ignorati** ai fini della corrispondenza dei duplicati.
- L'hash di un riscontro può comunque essere calcolato per altre funzionalità, ma non influisce sulla deduplicazione secondo questo algoritmo.

### Hash Code

- La Deduplicazione utilizza un hash calcolato a partire dai campi specificati da `HASHCODE_FIELDS_PER_SCANNER` per il parser in questione.
- L'hash include anche i campi di `HASH_CODE_FIELDS_ALWAYS` (vedere la sezione sul campo Service più sotto).
- Gli Endpoint possono influenzare la deduplicazione in due modi:
  - Se i campi hash dello scanner includono `endpoints`, questi fanno parte dell'hash e devono corrispondere di conseguenza.
- Se i campi hash dello scanner non includono `endpoints`, è possibile abilitare una corrispondenza opzionale basata sugli endpoint tramite `DEDUPE_ALGO_ENDPOINT_FIELDS` (impostazione OS). Se configurato:
    - Impostarlo su un elenco vuoto `[]` per ignorare completamente gli endpoint.
    - Impostarlo su un elenco di attributi dell'endpoint (ad es. `["host", "port"]`). Se almeno una coppia di endpoint tra i due riscontri corrisponde su tutti gli attributi elencati, la deduplicazione può avvenire.

### Unique ID From Tool or Hash Code
Un riscontro è duplicato di un altro se condividono lo stesso unique_id_from_tool oppure lo stesso hash_code.

Anche gli endpoint devono corrispondere perché i riscontri siano considerati duplicati; vedere sopra l'algoritmo Hash Code.

### Legacy (solo Open Source)

- La Deduplicazione considera più attributi, inclusi gli endpoint.
- Il comportamento differisce tra riscontri statici e dinamici:
  - **Riscontri statici**: il nuovo riscontro deve contenere tutti gli endpoint dell'originale. Endpoint aggiuntivi sul nuovo riscontro sono ammessi.
  - **Riscontri dinamici**: gli endpoint devono corrispondere in modo rigoroso (in genere per host e porta); endpoint diversi impediscono la deduplicazione.
- Se non sono presenti endpoint e sia `file_path` sia `line` sono vuoti, la deduplicazione in genere non avviene.

## Elaborazione in background

- La deduplicazione viene attivata durante l'importazione/reimportazione e durante alcuni aggiornamenti eseguiti in background tramite Celery.

### Modalità di esecuzione della deduplicazione in importazione/reimportazione

Per l'importazione e la reimportazione è possibile controllare come viene distribuita l'elaborazione successiva della deduplicazione e se la risposta dell'API la attende. Impostarla per singolo utente nella pagina del profilo (**Deduplication execution mode**), oppure sovrascriverla per singola richiesta con il campo `deduplication_execution_mode` sugli endpoint di importazione/reimportazione (il valore della richiesta ha la precedenza su quello del profilo).

- `async` (predefinito): la deduplicazione e il resto dell'elaborazione successiva vengono eseguiti in background e la risposta viene restituita immediatamente. Comportamento storico; la risposta viene generata prima che i riscontri vengano deduplicati.
- `async_wait`: l'elaborazione successiva viene comunque distribuita in background, ma la richiesta attende il completamento della deduplicazione prima di rispondere. La notifica `scan_added` e le statistiche nella risposta riflettono quindi lo stato deduplicato (i riscontri risultati duplicati non vengono più conteggiati o elencati come nuovi). Il push su JIRA, il grading del prodotto e le altre attività non legate alla deduplicazione restano asincroni e non vengono attesi. L'attesa è limitata da `DD_DEDUPLICATION_ASYNC_WAIT_TIMEOUT` (predefinito `60` secondi); se nessun worker prende in carico l'attività in tempo, la richiesta risponde comunque anziché rimanere in attesa indefinitamente.
- `sync`: la deduplicazione in importazione viene eseguita in linea nella richiesta web.

La risposta di importazione/reimportazione include un booleano `deduplication_complete` che indica se la deduplicazione era terminata al momento della generazione della risposta (`true` per `sync` e per un `async_wait` completato, `false` per `async`).

Questo è indipendente dal flag di profilo globale `block_execution`, che forza in primo piano **tutte** le attività asincrone di un utente (notifiche, push su JIRA, grading del prodotto, deduplicazione, ...). Quando non è impostata alcuna modalità di esecuzione, `block_execution=True` ricade su `sync`.

## Il campo Service e il suo impatto

- Per impostazione predefinita, `HASH_CODE_FIELDS_ALWAYS = ["service"]`, il che significa che il `service` associato a un riscontro viene aggiunto all'hash per tutti gli scanner.
- Implicazioni pratiche:
  - Due riscontri altrimenti identici ma con valori di `service` diversi produrranno hash diversi e non verranno deduplicati nei percorsi basati su hash.
  - Durante l'importazione/reimportazione, il campo `Service` inserito nell'interfaccia utente può sovrascrivere il service fornito dal parser. Modificarlo può cambiare l'hash e quindi influire sui risultati della deduplicazione.
  - Se si desidera che il service non abbia alcun impatto sulla deduplicazione, configurare `HASH_CODE_FIELDS_ALWAYS` di conseguenza (vedere la pagina di tuning OS). Rimuovere `service` dall'elenco sempre incluso ne impedirà l'effetto sugli hash.

## Eliminazione dei Riscontri duplicati

Se sono presenti troppi Riscontri duplicati che si desidera eliminare, è possibile impostare **Delete Deduplicate Findings** come opzione nelle **Impostazioni di sistema**.

**Delete Deduplicate Findings**, combinato con il campo **Maximum Duplicates**, consente a DefectDojo di limitare il numero di Riscontri duplicati archiviati. Quando questo campo è abilitato, DefectDojo manterrà solo un determinato numero di Riscontri duplicati.

### Quali duplicati verranno eliminati?

Il Riscontro originale non viene mai eliminato automaticamente da DefectDojo, ma una volta superata la soglia di Maximum Duplicates, DefectDojo eliminerà automaticamente il Riscontro duplicato più vecchio.

Ad esempio, supponiamo che il campo Maximum Duplicates sia impostato su '1'.

1. Per prima cosa, si importa **Test 1\.** Il report contiene una vulnerabilità che viene registrata come Riscontro A.
2. **In seguito, si importa il Test 2, che contiene la stessa vulnerabilità. Questa verrà registrata come Riscontro B, e il Riscontro B sarà contrassegnato come duplicato del Riscontro A.**
3. Più avanti, si importa **Test 3**, che contiene anch'esso quella vulnerabilità. Questa verrà registrata come Riscontro C, che sarà contrassegnato come duplicato del Riscontro A. A questo punto, il Riscontro B verrà eliminato da DefectDojo poiché è stata superata la soglia massima di duplicati.

### Applicazione di questa impostazione

Applicare **Delete Deduplicate Findings** avvierà immediatamente un processo di eliminazione. Questa impostazione può essere applicata nella pagina **Impostazioni di sistema**. Per maggiori informazioni, vedere Enabling Deduplication.

## Risoluzione dei problemi di Deduplicazione

A volte la Deduplicazione non funziona come previsto. Ecco alcuni esempi di casi in cui la Deduplicazione potrebbe non funzionare correttamente, insieme alle possibili soluzioni.

| Cosa si osserva | Causa più probabile | Cosa regolare |
| --- | --- | --- |
| La Reimportazione chiude un vecchio Riscontro e ne crea uno nuovo quando è cambiato solo il numero di riga | La corrispondenza in Reimportazione utilizza campi instabili (ad esempio il numero di riga) | <strong>Reimport Deduplication</strong> (preferire ID stabili o campi hash stabili) |
| Vengono creati più Riscontri nello stesso Test che si ritiene dovrebbero essere duplicati | La corrispondenza di deduplicazione non è configurata per quel tool o ambito | <strong>Same Tool Deduplication</strong> (e considerare il comportamento di "Delete Deduplicate Findings") |
| Vengono creati duplicati tra tool diversi | La corrispondenza tra tool diversi è disabilitata o troppo restrittiva | <strong>Cross Tool Deduplication (solo Pro)</strong> (corrispondenza basata su hash) |
| La stessa dipendenza SCA importata in più Prodotti crea Riscontri separati anziché duplicati | La Deduplicazione è per impostazione predefinita limitata al singolo Prodotto | <strong>Global Component Deduplication (solo Pro)</strong> ([abilitarla per i propri tool SCA](/triage_findings/finding_deduplication/pro__global_component_deduplication/)), oppure, nel modello dati Locations, <strong>Global Locations Deduplication (solo Pro)</strong> ([corrispondenza sulla location condivisa](/triage_findings/finding_deduplication/pro__global_locations_deduplication/)) |
| Lo stesso URL / Riscontro web importato in più Prodotti crea Riscontri separati anziché duplicati | La Deduplicazione è per impostazione predefinita limitata al singolo Prodotto, e Global Component effettua la corrispondenza solo sui componenti | <strong>Global Locations Deduplication (solo Pro)</strong> ([corrispondenza tra Riscontri DAST/URL tra i vari Prodotti](/triage_findings/finding_deduplication/pro__global_locations_deduplication/)) |
| Vengono creati duplicati in eccesso dello stesso Riscontro, tra i vari Test | La Asset Hierarchy non è configurata correttamente | [Considerare la Reimportazione per i test continuativi](/triage_findings/finding_deduplication/avoid_excess_duplicates/) |

Quando la deduplicazione automatica non individua Riscontri che si ritiene debbano essere collegati, è possibile collegarli manualmente dalla pagina Visualizza Riscontro. Vedere Similar Findings per sapere come individuare Riscontri correlati e contrassegnarli manualmente come duplicati ([Open Source](/triage_findings/finding_deduplication/os__similar_findings/) | [Pro](/triage_findings/finding_deduplication/pro__similar_findings/)).
