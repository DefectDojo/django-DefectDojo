---
title: Riscontri
description: Informazioni sui Riscontri in DefectDojo OS
audience: opensource
weight: 5
---

Organizzazioni	→ Asset → Engagement → Test → **RISCONTRI**

## Panoramica

I **Riscontri** rappresentano il livello più basso della Gerarchia dei Prodotti, dove le singole vulnerabilità vengono tracciate e gestite, e costituiscono il modo principale in cui DefectDojo standardizza e guida il processo di reportistica e remediation dei tuoi strumenti di sicurezza. Indipendentemente dal fatto che una vulnerabilità sia stata segnalata da SonarQube, Acunetix o da uno strumento personalizzato del tuo team, i Riscontri ti offrono la possibilità di gestire ogni vulnerabilità allo stesso modo.

Esempi di Riscontri includono: 
- Cookie non contrassegnato come HttpOnly
- Versione obsoleta (PHP)
- Valutazione del codice out-of-band (PHP)
- Versione obsoleta (MySQL)
- Rilevato codice sorgente di backup
- Blind Cross-Site Scripting

Oltre ad archiviare i dati sulla vulnerabilità e fornire un framework di remediation, DefectDojo migliora i tuoi Riscontri anche nei seguenti modi:
- Aggiunta automatica dei punteggi EPSS correlati a un Riscontro per descriverne la sfruttabilità
- Traduzione automatica della metrica di gravità di uno strumento di sicurezza in un punteggio di Gravità per ogni Riscontro, che assegna al Riscontro un SLA in base alla configurazione SLA del tuo Asset. Per maggiori informazioni sulla configurazione SLA, clicca [qui](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content).

Nel complesso, i Riscontri sono progettati per funzionare insieme alla Gerarchia dei Prodotti al fine di standardizzare i tuoi sforzi e applicare un metodo coerente a ogni Asset.

## Accesso ai Riscontri

I Riscontri sono accessibili tramite la barra laterale. Il sottomenu fornisce l'accesso ai Riscontri aperti e chiusi, a Tutti i Riscontri (indipendentemente dallo stato aperto o chiuso), ai [Riscontri a rischio accettato](/triage_findings/findings_workflows/os__risk_acceptance/), oltre ai Modelli di Riscontro. I singoli Riscontri sono accessibili anche dall'interno del Test che li contiene. 

![image](images/osfindings_ss1.png)

### Permessi

Ogni Riscontro appartiene a un Test, il che consente a DefectDojo di conservare l'informazione su quale scansione o valutazione ha originariamente identificato la vulnerabilità.

Poiché i Riscontri appartengono ai Test, l'accesso ai Riscontri è determinato dall'accesso di un Utente all'Asset che contiene il Test. I Test non dispongono di liste di controllo degli accessi indipendenti.

## Vista dei Riscontri
Le viste dei Riscontri contengono diverse tabelle utili per interpretare a colpo d'occhio lo stato di un Riscontro. Tra queste:
- **Panoramica**
    - **ID**: Il numero ID univoco di quel Riscontro. 
    - **Gravità**: La valutazione di gravità di quel Riscontro, applicata automaticamente. 
        - Come menzionato in precedenza, DefectDojo traduce automaticamente la metrica di gravità di uno strumento di sicurezza in un punteggio di Gravità per ogni Riscontro, che assegna al Riscontro un SLA in base alla configurazione SLA del tuo Asset.
    - **SLA**: La data di scadenza prevista entro cui il Riscontro dovrebbe essere risolto. 
    - **Stato**: Lo stato del Riscontro (ad es. Attivo, Verificato, Falso positivo, Duplicato, Fuori ambito e In revisione difetto).
    - **Tipo di Riscontro**: Se il Riscontro è Statico (SAST) o Dinamico (DAST).
    - **Data di rilevamento**: La data in cui il Riscontro è stato rilevato. 
    - **CWE**: La classificazione CWE del Riscontro. 
    - **ID vulnerabilità**: ID delle vulnerabilità presenti negli avvisi di sicurezza associati al Riscontro (ad es. CVE o altre fonti).  
    - **Rilevato da**: Lo strumento che ha rilevato il Riscontro. 
- **Riscontri simili**: Altri Riscontri all'interno dello stesso Asset che non sono duplicati esatti ma presentano valori simili per ID vulnerabilità, CWE, file_path, numero di riga, ecc.
- **Cronologia importazioni**: Elenco delle importazioni/reimportazioni che hanno creato/chiuso/riattivato questo Riscontro in qualsiasi Test. 
- **Endpoint/sistemi vulnerabili**: Endpoint/sistemi che il Riscontro rivela essere vulnerabili. 
- **Descrizione**: La descrizione del Riscontro (aggiunta automaticamente a seconda del tipo di Riscontro, oppure creata manualmente). 
- **Mitigazione**: Passaggi consigliati per la mitigazione.
- **Impatto**: Impatto potenziale nel lasciare il Riscontro irrisolto. 
- **Passaggi per la riproduzione**: Passaggi per riprodurre il Riscontro. 
- **Motivazione della gravità**: Descrizione scritta del motivo per cui è stata associata al Riscontro una determinata valutazione di Gravità. 
- **Riferimenti**: URL per fare riferimento incrociato alla descrizione specifica del Riscontro fornita dallo strumento di scansione di terze parti. Ad esempio, i Riferimenti potrebbero essere link a una voce pertinente in un catalogo di Riscontri, oppure un singolo URL di un avviso. 
- **Note**: Note lasciate dagli Utenti relative al Riscontro. Contrassegnare una nota come Privata comporterà la sua esclusione da qualsiasi report generato che includa il Riscontro selezionato. 

## Dati dei Riscontri

I Riscontri richiedono i seguenti metadati:
**Titolo**
**Data**
**Gravità**
**Descrizione**

Oltre ai metadati corrispondenti alle tabelle nella vista di un Riscontro, i campi di metadati opzionali includono: 
- **Gruppo**: I Gruppi di Riscontri che includono il Riscontro selezionato. 
- **Vettore e punteggio CVSS3/CVSS4**: Il vettore e il punteggio CVSS3 e CVSS4 del Riscontro selezionato. 
- **Coppie di richiesta e risposta**: Una copia del messaggio inviato dal client e della risposta del server alla richiesta.
- **Endpoint da aggiungere**: Endpoint vulnerabili che potrebbero essere interessati dal Riscontro selezionato e che non sono riportati nell'elenco precedente di sistemi/endpoint. 
- **Punteggio e percentile EPSS**: Punteggio e percentile EPSS per la CVE. 
- **Data di aggiunta al KEV**: La data in cui il Riscontro è stato aggiunto al catalogo KEV. 
- **Disponibilità e versione della correzione**: Definisce se è disponibile una correzione per la vulnerabilità e la versione del componente interessato in cui la correzione è stata implementata. 
- **Utente che ha richiesto la revisione del difetto**: Registra chi ha richiesto una revisione del difetto per la vulnerabilità in questione. 
- **Numero di riga**: Numero di riga del codice sorgente del vettore di attacco. 
- **Percorso del file**: File identificati che contengono il difetto. 
- **Nome e versione del componente**: Nome e versione del componente interessato. 
- **ID univoco dello strumento**: ID tecnico della vulnerabilità proveniente dallo strumento di origine. 
- **ID vulnerabilità dello strumento**: ID tecnico non univoco proveniente dallo strumento di origine. 
- **Oggetto sorgente SAST, numero di riga e percorso del file**: Oggetto sorgente, numero di riga e percorso del file del vettore di attacco. 
- **Oggetto sink SAST**: Oggetto sink del vettore di attacco. 
- **Numero di occorrenze**: Numero di occorrenze nello strumento di origine quando più vulnerabilità sono state rilevate e aggregate dallo scanner. 
- **Data di pubblicazione**: Data in cui il Riscontro è stato pubblicato. 
- **Servizio**: I Servizi connessi (componenti funzionali autonomi all'interno di un Asset) interessati dal Riscontro selezionato. Quando è popolato, questo campo viene incluso nella corrispondenza di deduplicazione (ovvero, i Riscontri con campi Servizio identici verranno deduplicati). 
- **Data e versione di remediation pianificata**: La data entro cui è prevista la remediation del Riscontro e la versione del componente interessato in cui verrà implementata la correzione.
- **Impegno per la correzione**: Il livello di impegno richiesto per correggere il Riscontro (ad es. Bassa, Media o Alta). 
- **Tag**: Eventuali tag aggiunti al Riscontro. 

I metadati esatti disponibili dipendono dal parser/scanner che ha rilevato il Riscontro. Alcuni forniscono solo informazioni di base come titolo e gravità, mentre altri includono vettori CVSS, componenti vulnerabili, endpoint, coppie di richiesta/risposta e altri metadati specifici dello scanner.
 
Questi metadati migliorano il filtraggio, la reportistica e la definizione delle priorità in tutto il tuo programma di sicurezza, consentendo il tracciamento a lungo termine e l'analisi delle tendenze. Ulteriori dettagli e descrizioni dei metadati sono disponibili [qui](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page). 

### Deduplicazione

DefectDojo include funzionalità di deduplicazione che aiutano a identificare e gestire i Riscontri che rappresentano la stessa vulnerabilità sottostante. Man mano che i risultati delle scansioni vengono importati da uno o più strumenti, DefectDojo utilizza una logica di corrispondenza configurabile per identificare i Riscontri che rappresentano la stessa vulnerabilità.

La deduplicazione impedisce che la stessa vulnerabilità compaia più volte quando viene rilevata ripetutamente dallo stesso scanner o da scanner diversi, consentendo alla cronologia di remediation di rimanere associata a un singolo Riscontro.

Ulteriori informazioni sulla deduplicazione sono disponibili [qui](/triage_findings/finding_deduplication/about_deduplication/).

### Reimportazione

La funzione di Reimportazione di DefectDojo consente di aggiornare i Riscontri man mano che vengono importati nuovi risultati di scansione. Quando una scansione viene reimportata, DefectDojo confronta i risultati in arrivo con i Riscontri esistenti e aggiorna i record corrispondenti invece di crearne di completamente nuovi. Questo preserva un contesto prezioso, come le variazioni di stato, la cronologia di remediation, i commenti e le informazioni sulla proprietà, fornendo una registrazione continua del ciclo di vita di un Riscontro attraverso più cicli di test.

Ulteriori informazioni sulla funzione di Reimportazione sono disponibili [qui](/import_data/import_intro/reimport/#main-content).

### Accettazioni del rischio 

Le Accettazioni del rischio sono uno stato speciale che può essere applicato ai Riscontri per documentare formalmente e rendere operativa la decisione di riconoscerli senza porvi rimedio immediatamente. 

Ulteriori informazioni sulle Accettazioni del rischio sono disponibili [qui](/triage_findings/findings_workflows/os__risk_acceptance/).

### Stati 

Ogni Riscontro creato in DefectDojo ha uno Stato che comunica informazioni rilevanti e aiuta il tuo team a monitorare i progressi nella risoluzione dei problemi.

Ulteriori informazioni sugli Stati sono disponibili [qui](/triage_findings/findings_workflows/finding_status_definitions/).

## Utilizzo dei Riscontri 

### Creazione di Riscontri 

Sebbene la maggior parte dei Riscontri venga generata automaticamente tramite importazioni di scansioni e integrazioni, DefectDojo supporta anche la creazione manuale dei Riscontri. I Riscontri manuali sono utili per tracciare vulnerabilità e problematiche di sicurezza identificate tramite penetration test, revisioni architetturali, valutazioni di conformità, programmi di bug bounty, incarichi di consulenza o altre attività che non producono un output da scanner. 

Per creare manualmente un Riscontro:
1. Vai al Test in cui desideri aggiungere manualmente il Riscontro, fai clic sul segno + e poi su **New Finding**.

![image](images/osfindings_ss2.png)

2. Si aprirà il modulo New Finding, che potrai compilare con qualsiasi informazione pertinente relativa al tuo Riscontro.

3. Seleziona **Aggiungi un altro Riscontro** per aggiungere manualmente un altro Riscontro, oppure **Terminato** per concludere il processo di creazione manuale del Riscontro.

Il Riscontro comparirà ora nell'elenco dei Riscontri contenuti nel Test originale. 

È importante notare che l'aggiunta manuale di un Riscontro dalla barra superiore creerà automaticamente un Engagement e un Test ad hoc per contenere il nuovo Riscontro, anziché aggiungerlo al Test attualmente visualizzato (vedi l'immagine sottostante). Questo perché la barra superiore fa riferimento all'Asset nel suo complesso. Se desideri aggiungere manualmente un Riscontro a un Test specifico e preesistente, è preferibile farlo dall'interno del Test stesso, come descritto nei passaggi 1-3 sopra. 

![image](images/osfindings_ss3.png)

### Modifica dei Riscontri

#### Menu kebab ⋮

Il menu kebab ⋮ accanto ai Riscontri contiene le seguenti funzioni: 
- **Visualizza**: Apri e visualizza il Riscontro. 
- **Modifica**: Modifica il Riscontro. 
- **Copia**: Crea una copia del Riscontro. La copia può essere salvata in uno qualsiasi dei Test contenuti nell'Engagement corrispondente. 
- **Richiedi Peer Review**: Avvia il processo di Peer Review e modifica lo stato del Riscontro in “In revisione”. Ulteriori informazioni sulle Peer Review sono disponibili [qui](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Touch Finding**: Registrerà l'interattività con il Riscontro nella sua cronologia. 
- **Rendi il Riscontro un Modello**: Creerà automaticamente un Modello di Riscontro basato sul Riscontro selezionato. 
- **Applica Modello al Riscontro**: Consentirà di applicare un Modello di Riscontro preesistente a un Riscontro. 
- **Chiudi Riscontro**: Avvierà il processo di chiusura del Riscontro. 
- **Aggiungi Accettazione del rischio**: Avvierà il processo di Accettazione del rischio. Ulteriori informazioni sono disponibili [qui](/triage_findings/findings_workflows/os__risk_acceptance/#main-content).
- **Visualizza cronologia**: Mostra la cronologia del Riscontro selezionato. 
- **Elimina**: Elimina il Riscontro selezionato. 

#### Allegare file ai Riscontri 
Puoi allegare file a qualsiasi Riscontro per fornire un contesto visivo — ad esempio, uno screenshot di una vulnerabilità in azione o un'immagine di proof-of-concept.

I tipi di file supportati includono: 

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Per allegare un file a un Riscontro:
1. Apri il Riscontro a cui vuoi allegare un file.
2. Apri il menu delle azioni (il pulsante ☰ in alto a destra del Riscontro) e fai clic su Gestisci file.

![image](images/OS_manage_files_menu.png)

3. Nella pagina Aggiungi file, inserisci un Titolo per il file e scegli il file dal tuo computer. Puoi aggiungere fino a tre file alla volta; salva e torna indietro per aggiungerne altri se necessario.

![image](images/OS_manage_files_form.png)

4. Fai clic su **Salva**.

Il file viene quindi elencato nel pannello **File** del Riscontro. I file immagine vengono visualizzati come miniature:

![image](images/OS_finding_files_panel.png)

#### Modifica in blocco dei Riscontri 

I Riscontri possono essere modificati in blocco da un elenco di Riscontri, come la tabella di Tutti i Riscontri accessibile dalla barra laterale, oppure dalla tabella dei Riscontri all'interno di uno specifico Test.

Ulteriori informazioni su come modificare in blocco i Riscontri sono disponibili [qui](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings). 

### Chiusura dei Riscontri 

Una volta completato il lavoro su un Riscontro, puoi chiuderlo manualmente facendo clic su **Chiudi Riscontro** nel menu kebab ⋮ o nel menu delle azioni ☰ del Riscontro. In alternativa, se una scansione viene reimportata in DefectDojo senza contenere un Riscontro registrato in precedenza, quest'ultimo verrà chiuso automaticamente.

Se non desideri che alcun Riscontro venga chiuso, puoi disabilitare questo comportamento durante la Reimportazione:

- Deseleziona la casella Close Old Findings se utilizzi l'interfaccia utente
- Imposta close_old_findings su False se utilizzi l'API ​

### Eliminazione dei Riscontri 

L'eliminazione di un Riscontro può essere effettuata dal menu kebab ⋮ o dal menu delle azioni ☰ del Riscontro. Questa azione non può essere annullata. 

A fini di audit, si consiglia di chiudere i Riscontri risolti anziché eliminarli. 

## Gruppi di Riscontri 

I **Gruppi di Riscontri** ti consentono di trattare più Riscontri correlati come un'unica unità logica ai fini del triage, della reportistica e del coordinamento della remediation.

Ad esempio, una scansione potrebbe generare 10 Riscontri di SQL injection su endpoint diversi. Invece di gestirli singolarmente, puoi raggrupparli in un unico Gruppo di Riscontri che rappresenta il problema più ampio di SQL injection.

Un Gruppo di Riscontri non sostituisce i singoli Riscontri. Ogni Riscontro continua a esistere con la propria gravità, stato, metadati, commenti e cronologia di remediation. Un Gruppo di Riscontri fornisce semplicemente un ulteriore livello organizzativo al di sopra dei Riscontri che contiene.

### Accesso ai Gruppi di Riscontri 

I Gruppi di Riscontri sono accessibili tramite la barra laterale. Il sottomenu fornisce l'accesso ai Gruppi di Riscontri aperti e chiusi, nonché a Tutti i Gruppi di Riscontri (indipendentemente dallo stato aperto).

![image](images/osfindings_ss1.png)

### Creazione di Gruppi di Riscontri 


I Gruppi di Riscontri possono essere creati manualmente o automaticamente. 

È importante notare che i Gruppi di Riscontri possono essere creati solo a partire dai Riscontri contenuti in un singolo Test. I Riscontri provenienti da Test, Engagement o Prodotti diversi non possono essere aggiunti allo stesso Gruppo di Riscontri.

#### Gruppi di Riscontri manuali 

Per eseguire manualmente le azioni sui Gruppi di Riscontri:
1. Vai a un elenco di Riscontri all'interno di un Test. 
2. Seleziona il/i Riscontro/i che desideri aggiungere a un Gruppo di Riscontri facendo clic sulla casella corrispondente. 
3. Fai clic sulla casella **Gruppo**. 
4. Fai clic sull'azione corrispondente che desideri completare.
    - **Crea**: Crea un Gruppo di Riscontri che include i Riscontri selezionati.
    - **Aggiungi a**: Aggiunge i Riscontri selezionati a un Gruppo di Riscontri preesistente.
    - **Rimuovi da qualsiasi gruppo**: Rimuove i Riscontri selezionati da qualsiasi Gruppo di Riscontri di cui facevano precedentemente parte. 
    - **Raggruppa per**: Raggruppa i Riscontri selezionati in base all'opzione scelta (ad es. Nome componente, Percorso file, Titolo del Riscontro, ecc.) 
5. Fai clic su **Invia**.

![image](images/osfindings_ss4.png)

Nota che l'unica azione possibile quando si selezionano Riscontri dall'elenco Tutti i Riscontri è rimuoverli da qualsiasi Gruppo di Riscontri. Questo perché, come menzionato, i Gruppi di Riscontri possono essere creati solo a partire dai Riscontri contenuti in un singolo Test.

#### Gruppi di Riscontri automatici 

Durante l'importazione di una scansione, la funzione “Raggruppa per” può creare automaticamente Gruppi di Riscontri in base a un metodo di raggruppamento scelto. Questo è utile quando uno scanner produce molti Riscontri correlati che dovrebbero essere gestiti insieme.

La casella adiacente **Crea Gruppi di Riscontri per tutti i Riscontri** svolge due funzioni: 
- **Selezionata**: Crea un Gruppo di Riscontri per ogni Riscontro importato, anche se tale Riscontro è l'unico membro del gruppo.
- **Deselezionata**: Crea Gruppi di Riscontri solo quando sono effettivamente presenti più Riscontri da raggruppare.

![image](images/osfindings_ss5.png)

Se durante l'importazione non viene selezionata alcuna opzione dal menu a discesa Raggruppa per, non verrà eseguito alcun raggruppamento. 

Se il criterio di raggruppamento (ad es. nome del componente, ID vulnerabilità, ecc.) non è popolato nel Riscontro, per quest'ultimo non verrà creato alcun gruppo né verrà aggiunto a un Gruppo di Riscontri preesistente. 

Se viene importata una scansione che rivela 10 Riscontri non raggruppati, e la stessa scansione viene successivamente reimportata con i Riscontri raggruppati, i primi 10 Riscontri non verranno aggiunti a quel Gruppo di Riscontri (ovvero, il Gruppo di Riscontri includerà solo i 10 Riscontri della reimportazione, non i 10 Riscontri dell'importazione iniziale e successiva). 

## Modelli di Riscontro 

I **Modelli di Riscontro** consentono agli Utenti di creare modelli riutilizzabili per le vulnerabilità e i problemi di sicurezza segnalati più comunemente. Un modello può includere informazioni standardizzate come titolo, descrizione, impatto, passaggi per la riproduzione, mitigazione, riferimenti e altri metadati del Riscontro.

I Modelli di Riscontro sono particolarmente utili nelle situazioni in cui gli Utenti devono creare ripetutamente Riscontri manuali e vogliono evitare di reinserire ogni volta le stesse informazioni di supporto.

### Accesso ai Modelli di Riscontro 

I Modelli di Riscontro si trovano nel sottomenu Riscontri della barra laterale. 

![image](images/osfindings_ss6.png) 

### Creazione di Modelli di Riscontro 

I Modelli di Riscontro possono essere creati facendo clic sul pulsante + in alto a destra nella vista dei Modelli di Riscontro. 

La pagina successiva fornisce una panoramica dei metadati che verranno applicati a un Riscontro quando viene utilizzato un Modello di Riscontro.

Puoi anche utilizzare un Riscontro preesistente come base per un nuovo Modello di Riscontro facendo clic su **Rendi il Riscontro un Modello** nel menu kebab ⋮ del Riscontro. 

### Applicazione dei Modelli di Riscontro 

I Modelli di Riscontro possono essere applicati ai Riscontri facendo clic sul pulsante **Applica Modello al Riscontro** nel menu kebab ⋮ del Riscontro selezionato.

![image](images/osfindings_ss7.png)

La pagina successiva ti permetterà di selezionare il modello da applicare al Riscontro in questione, e quindi se mantenere, sostituire o combinare i metadati del Riscontro con quelli del modello. 

### Reportistica 

Il generatore di report di DefectDojo ti consente di assemblare un report personalizzato a partire da un insieme di widget di contenuto, eseguirlo ed esportare il risultato (ad esempio, stampandolo in PDF). I report personalizzati possono riassumere i Riscontri o gli Endpoint che desideri condividere con un pubblico esterno e possono includere branding e testo standard.

Ulteriori informazioni sul Generatore di Report di DefectDojo sono disponibili [qui](/metrics_reports/reports/using-the-report-builder/).

#### Esportazione dei Riscontri 

Le pagine che mostrano un elenco di Riscontri o un elenco di Engagement dispongono di un'opzione di esportazione in CSV ed Excel nel menu a discesa in alto a destra.

Da qualsiasi pagina con un elenco di Riscontri, apri il menu a discesa nell'angolo in alto a destra per esportare i Riscontri visibili come file CSV o Excel. Anche l'elenco degli Engagement può essere esportato come CSV o Excel utilizzando lo stesso menu a discesa nella pagina dell'elenco Engagement.
