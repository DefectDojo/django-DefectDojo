---
title: Riscontri
description: Comprendere i Riscontri in DefectDojo Pro
audience: pro
weight: 5
---

Organizzazioni	→ Asset → Engagement → Test → **RISCONTRI**

## Panoramica
I **Riscontri** rappresentano il livello più basso della Gerarchia dei Prodotti, in cui le singole vulnerabilità vengono tracciate e gestite, e costituiscono il modo principale con cui DefectDojo standardizza e guida il processo di segnalazione e correzione dei tuoi strumenti di sicurezza. Indipendentemente dal fatto che una vulnerabilità sia stata segnalata da SonarQube, Acunetix o dallo strumento personalizzato del tuo team, i Riscontri ti permettono di gestire ogni vulnerabilità nello stesso modo.

Esempi di Riscontri includono: 
- **Cookie non contrassegnato come HttpOnly**
- **Versione obsoleta (PHP)**
- **Valutazione del codice Out-of-Band (PHP)**
- **Versione obsoleta (MySQL)**
- **Codice sorgente di backup rilevato**
- **Cross-Site Scripting cieco**

Oltre a memorizzare i dati sulle vulnerabilità e fornire un framework di correzione, DefectDojo migliora i tuoi Riscontri anche nei seguenti modi:
- Aggiungendo automaticamente i punteggi EPSS correlati a un Riscontro per descriverne la sfruttabilità
- Traducendo automaticamente la metrica di gravità di uno strumento di sicurezza in un punteggio di Gravità per ogni Riscontro, il che conferisce al Riscontro uno SLA in base alla configurazione SLA del tuo Asset. Per maggiori informazioni sulla configurazione degli SLA, clicca [qui](/asset_modelling/pro_hierarchy/priority_sla/#working-with-slas).

Nel complesso, i Riscontri sono progettati per funzionare insieme alla Gerarchia dei Prodotti al fine di standardizzare i tuoi sforzi e applicare un metodo coerente a ciascun Asset.

## Accesso ai Riscontri 
I Riscontri sono accessibili tramite la barra laterale. Il sottomenu offre l'accesso ai Riscontri Attivi e Mitigati, a Tutti i Riscontri (indipendentemente dallo stato Aperto o Chiuso), ai Gruppi di Riscontri, ai Modelli di Riscontro e al flusso di lavoro per un Nuovo Riscontro. I singoli Riscontri sono accessibili anche dal Test che li contiene. 

[Riscontri con Rischio accettato] (/triage_findings/findings_workflows/os__risk_acceptance/) sono accessibili dalla sezione **Accettazioni del rischio** della barra laterale. 

![image](images/profindings_ss1.png)

### Autorizzazioni 
Ogni Riscontro appartiene a un Test, il che consente a DefectDojo di conservare l'informazione su quale scansione o valutazione ha originariamente identificato la vulnerabilità.

Poiché i Riscontri appartengono ai Test, l'accesso ai Riscontri è determinato dall'accesso di un Utente all'Asset che contiene il Test. I Test non dispongono di liste di controllo degli accessi indipendenti.

## Vista dei Riscontri
Le viste dei Riscontri contengono una serie di tabelle che aiutano a interpretare a colpo d'occhio lo stato di un Riscontro. 

### Panoramica del Riscontro
- **Descrizione**: la descrizione del Riscontro (aggiunta automaticamente in base al tipo di Riscontro, oppure creata manualmente). 
- **Mitigazione**: i passaggi suggeriti per la mitigazione.
- **Policy di mitigazione generale**: la policy di mitigazione standardizzata per il Riscontro selezionato. 
Le policy di mitigazione possono essere trovate e modificate nella barra laterale in **Configurazione** → **Policy di mitigazione**.
- **Impatto**: il potenziale impatto derivante dal non risolvere il Riscontro.
- **Riferimenti**: URL per incrociare la descrizione specifica del Riscontro fornita dallo strumento di scansione di terze parti. Ad esempio, i Riferimenti potrebbero essere collegamenti a una voce pertinente in un catalogo di Riscontri, oppure un singolo URL di un advisory. 
- **File**: eventuali file aggiunti per contestualizzare il Riscontro. 
- **Note**: le note lasciate dagli Utenti relative al Riscontro. Contrassegnare una nota come Privata significa che non verrà inclusa in nessun report generato che includa il Riscontro selezionato. 

### Metadati 
- **ID**: l'ID univoco del Riscontro in DefectDojo. 
- **Organizzazione, Asset, Engagement e Test**: gli oggetti superiori del Riscontro selezionato.
- **Stato**: lo stato del Riscontro (ad esempio, Attivo, Verificato, Falso positivo, Duplicato, Fuori ambito e In revisione del difetto).
- **Gravità**: la valutazione di gravità di quel Riscontro, applicata automaticamente. 
    - Come accennato in precedenza, DefectDojo traduce automaticamente la metrica di gravità di uno strumento di sicurezza in un punteggio di Gravità per ogni Riscontro, il che conferisce al Riscontro uno SLA in base alla configurazione SLA del tuo Asset.
- **Rischio**: un sistema di classificazione a 4 livelli che tiene conto della sfruttabilità di un Riscontro e viene applicato automaticamente. 
    - I dettagli su come vengono calcolati priorità, rischio e SLA sono disponibili [qui](/asset_modelling/pro_hierarchy/priority_sla/#main-content). Ulteriori dettagli sulle definizioni di stato del Riscontro e di livello di rischio sono disponibili [qui](/triage_findings/findings_workflows/finding_status_definitions/).
- **Priorità**: una classificazione numerica calcolata, applicata a tutti i Riscontri, che consente di comprendere rapidamente le vulnerabilità nel loro contesto. 
- **Età**: da quanto tempo esiste il Riscontro selezionato. 
- **SLA**: la data entro cui il Riscontro dovrebbe essere risolto.
- **Tipo**: indica se il Riscontro è stato rilevato da uno strumento di sicurezza applicativa statico o dinamico (Statico, Dinamico o Statico/Dinamico). 
- **Posizione e riga**: il file e il numero di riga in cui è stato trovato il Riscontro selezionato. 
- **Nome e versione del componente**: il nome e la versione del componente in cui è stato trovato il Riscontro selezionato. 
- **Data di scoperta**: la data in cui è stato scoperto il Riscontro. 
- **Data e versione di correzione pianificata**: la data in cui è pianificata la correzione del Riscontro e la versione del componente interessato in cui verrà implementata la correzione.
- **Servizio**: i Servizi connessi (parti di funzionalità autonome all'interno di un Asset) interessati dal Riscontro selezionato. Quando è compilato, questo campo viene incluso nella corrispondenza per la deduplicazione (ossia, i Riscontri con campi Servizio identici verranno deduplicati). 
- **Segnalatore**: l'Utente che ha rilevato il Riscontro. 
- **CWE**: la classificazione della debolezza CWE del Riscontro. Un Riscontro può avere **più CWE** — un CWE primario, più eventuali CWE aggiuntivi forniti dallo strumento di segnalazione. Il CWE primario è quello utilizzato per la deduplicazione legacy e per il calcolo dell'hash code; l'intero insieme di CWE può inoltre essere utilizzato per la corrispondenza tramite i campi Hash Code basati su insiemi di Pro (vedi [Ottimizzazione della deduplicazione](/triage_findings/finding_deduplication/pro__deduplication_tuning/#set-based-hash-code-fields-vulnerability-ids-and-cwes)).
    - Un CWE descrive una *classe* di debolezza (ad esempio, “SQL Injection”), non un'istanza specifica di vulnerabilità — a questo servono gli ID di vulnerabilità.
- **ID di vulnerabilità**: identificatori di vulnerabilità pubblicamente riconosciuti associati al Riscontro, come CVE, GHSA o altri riferimenti standardizzati di advisory. In DefectDojo Pro, vengono utilizzati anche per eseguire ricerche EPSS e KEV.
    - Gli ID di vulnerabilità vengono memorizzati come record di prima classe, quindi lo stesso CVE viene tracciato una sola volta e condiviso da ogni Riscontro che vi fa riferimento. Puoi consultarli — insieme ai relativi valori EPSS e KEV — nell'**Esploratore delle vulnerabilità**. Vedi [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/#viewing-kevepss-in-the-vulnerability-explorer).
- **ID univoco dallo strumento**: un identificatore stabile assegnato dallo strumento di origine a una specifica istanza di Riscontro. Gli ID univoci sono pensati per rimanere coerenti tra scansioni ripetute, consentendo allo strumento di riconoscere lo stesso Riscontro nel tempo. 
    - A differenza degli ID di vulnerabilità, questo valore è proprietario dello strumento di segnalazione e non è un riferimento pubblico di vulnerabilità.
        - Esempio: `finding-12345`
- **ID di vulnerabilità dallo strumento**: un identificatore proprietario di vulnerabilità o regola, assegnato dallo strumento di origine per descrivere il tipo di vulnerabilità rilevata. 
    - A differenza dell'ID univoco dallo strumento, questo identificatore non è univoco per un singolo Riscontro e può comparire in molti Riscontri che corrispondono alla stessa regola di rilevamento. 
    - A differenza degli ID di vulnerabilità, questi identificatori sono specifici dello strumento di segnalazione e non sono standardizzati pubblicamente.
        - Esempio: `semgrep.rule.lang.security.sql-injection`
- **Punteggio EPSS / Percentile**: il punteggio EPSS e il percentile per il CVE.
- **Sfruttamento noto**: indica se esiste conferma che la vulnerabilità sia stata sfruttata. 
- **Ransomware utilizzato**: indica se un ransomware è stato coinvolto nello sfruttamento della vulnerabilità. 
- **Data KEV**: la data in cui il Riscontro è stato aggiunto al catalogo KEV.
- **Rilevato da**: il tipo di strumento che ha identificato la vulnerabilità.
- **Vettore e punteggio CVSSv3 e CVSSv4**: il vettore e il punteggio CVSS3 e CVSS4 del Riscontro selezionato.
- **Ticket integratore**: i numeri di ticket del sistema di tracciamento problemi di terze parti associati al Riscontro. 

### Endpoint vulnerabili 
Questa sezione include una tabella degli Endpoint interessati dal Riscontro selezionato, insieme a eventuali metadati pertinenti.

### Dettagli aggiuntivi 
- **Coppie richiesta/risposta**: una copia del messaggio inviato dal client e della risposta del server alla richiesta.
- **Passaggi per la riproduzione**: i passaggi per riprodurre il Riscontro.
- **Motivazione della gravità**: descrizione scritta del motivo per cui è stata associata al Riscontro una determinata valutazione di Gravità. 

## Dati dei Riscontri 
I Riscontri richiedono i seguenti metadati:
- **Nome**
- **Data**
- **Gravità**
- **Descrizione**

Oltre ai metadati corrispondenti alle tabelle nella vista di un Riscontro, i campi di metadati opzionali includono: 
- **Tag**: eventuali tag aggiunti al Riscontro.
- **Proprietari**: il gruppo di utenti responsabile del Riscontro selezionato.
- **Invia a Jira**: invia il Riscontro a Jira a scopo di ticketing. 
- **Invia a Integratore**: invia il Riscontro a qualsiasi sistema di tracciamento problemi di terze parti integrato.
- **Impostazioni di rischio e priorità**: offre la possibilità di sovrascrivere il calcolo automatico di DefectDojo del rischio e della priorità del Riscontro. 
- **Endpoint da aggiungere**: endpoint vulnerabili che potrebbero essere interessati dal Riscontro selezionato e che non sono riportati nell'elenco precedente di sistemi/endpoint.
- **Revisione del difetto richiesta da**: registra chi ha richiesto una revisione del difetto per il problema in questione.
- **Oggetto sorgente SAST, numero di riga e percorso del file**: l'oggetto sorgente, il numero di riga e il percorso del file del vettore di attacco.
- **Oggetto sink SAST**: l'oggetto sink del vettore di attacco.
- **Numero di occorrenze**: il numero di occorrenze nello strumento di origine quando più vulnerabilità sono state trovate e aggregate dallo scanner. 
- **Data di pubblicazione**: la data in cui la vulnerabilità è stata pubblicata. 
- **Stima dello sforzo**: il livello di impegno necessario per correggere il Riscontro (ad esempio, Bassa, Media o Alta).

I metadati esatti disponibili dipendono dal parser/scanner che ha rilevato il Riscontro. Alcuni forniscono solo informazioni di base come titolo e gravità, mentre altri includono vettori CVSS, componenti vulnerabili, endpoint, coppie richiesta/risposta e altri metadati specifici dello scanner.
 
Questi metadati migliorano il filtraggio, la reportistica e la definizione delle priorità nell'intero programma di sicurezza, consentendo un tracciamento a lungo termine e l'analisi delle tendenze. Ulteriori dettagli e descrizioni dei metadati sono disponibili [qui](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page). 

### Deduplicazione 
DefectDojo include funzionalità di deduplicazione che aiutano a identificare e gestire i Riscontri che rappresentano la stessa vulnerabilità sottostante. Quando i risultati delle scansioni vengono importati da uno o più strumenti, DefectDojo utilizza una logica di corrispondenza configurabile per identificare i Riscontri che rappresentano la stessa vulnerabilità.

La deduplicazione evita che la stessa vulnerabilità appaia più volte quando viene rilevata ripetutamente dallo stesso scanner o da scanner diversi, permettendo alla cronologia di correzione di rimanere collegata a un unico Riscontro.

Ulteriori informazioni sulla deduplicazione sono disponibili [qui](/triage_findings/finding_deduplication/about_deduplication/).

### Reimportazione
La funzione di Reimportazione di DefectDojo consente di aggiornare i Riscontri man mano che vengono importati nuovi risultati di scansione. Quando una scansione viene reimportata, DefectDojo confronta i risultati in arrivo con i Riscontri esistenti e aggiorna i record corrispondenti invece di crearne di completamente nuovi. Questo preserva informazioni contestuali preziose come i cambiamenti di stato, la cronologia di correzione, i commenti e le informazioni di appartenenza, fornendo un registro continuo del ciclo di vita di un Riscontro attraverso più cicli di test.

Ulteriori informazioni sulla funzione di Reimportazione sono disponibili [qui](/import_data/import_intro/reimport/).

### Accettazioni del rischio 
Le Accettazioni del rischio sono uno stato speciale che può essere applicato ai Riscontri per documentare formalmente e rendere operativa la decisione di riconoscerli senza correggerli immediatamente. 

Ulteriori informazioni sulle Accettazioni del rischio sono disponibili [qui](/triage_findings/findings_workflows/pro__risk_acceptance/).

### Stati 
Ogni Riscontro creato in DefectDojo ha uno Stato che comunica informazioni rilevanti e aiuta il tuo team a tenere traccia dei progressi nella risoluzione dei problemi.

Ulteriori informazioni sugli Stati sono disponibili [qui](/triage_findings/findings_workflows/finding_status_definitions/).

## Lavorare con i Riscontri 

### Creazione dei Riscontri 
Sebbene la maggior parte dei Riscontri venga generata automaticamente tramite importazioni di scansioni e integrazioni, DefectDojo supporta anche la creazione manuale dei Riscontri. I Riscontri manuali sono utili per tracciare vulnerabilità e problemi di sicurezza identificati tramite penetration test, revisioni dell'architettura, valutazioni di conformità, programmi di bug bounty, incarichi di consulenza o altre attività che non producono un output da scanner. 

I Riscontri possono essere aggiunti manualmente cliccando su **Nuovo Riscontro** all'interno della sezione **Riscontri** della barra laterale, oppure selezionando **Aggiungi Riscontro** nel menu a ingranaggio del Test a cui si desidera aggiungere il Riscontro. 

### Modifica dei Riscontri 
Il menu kebab ⋮ accanto ai Riscontri contiene le seguenti funzioni: 
- **Modifica Riscontro**: modifica il Riscontro.
- **Copia Riscontro**: crea una copia del Riscontro in un altro Test. La copia può essere salvata in qualsiasi Test all'interno dello stesso Engagement per cui si dispone dell'autorizzazione di modifica. La copia è utile quando la stessa vulnerabilità deve essere tracciata separatamente in più di un contesto di Test.
- **Chiudi Riscontro**: avvia il processo di chiusura del Riscontro.
- **Richiedi revisione**: avvia il processo di Revisione tra pari e modifica lo stato del Riscontro in “In revisione”. Ulteriori informazioni sulle Revisioni tra pari sono disponibili [qui](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Aggiungi Accettazione del rischio**: avvia il processo di Accettazione del rischio. Ulteriori informazioni sono disponibili [qui](/triage_findings/findings_workflows/pro__risk_acceptance/).
- **Aggiungi file**: avvia il processo per aggiungere un file al Riscontro (vedi la sezione seguente).
- **Aggiungi nota**: avvia il processo per aggiungere una nota al Riscontro. 
- **Aggiungi campo personalizzato**: apre una finestra pop-up che consente di aggiungere e definire un campo personalizzato da applicare al Riscontro. 
- **Invia a Jira**: invia il Riscontro a Jira a scopo di ticketing. 
- **Invia a Integratore**: invia il Riscontro a qualsiasi sistema di tracciamento problemi di terze parti integrato.
- **Elimina Riscontro**: elimina il Riscontro selezionato. 
- **Cronologia Riscontro**: mostra la cronologia del Riscontro selezionato.

#### Allegare file ai Riscontri 
Puoi allegare file a qualsiasi Riscontro per fornire un contesto aggiuntivo — ad esempio, uno screenshot di una vulnerabilità in azione o un'immagine di proof-of-concept.

I tipi di file supportati includono: 

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Per allegare un file a un Riscontro, clicca su **Aggiungi file** dal menu kebab ⋮ oppure dal menu a ingranaggio del Riscontro selezionato. Inserisci un Titolo per il file, scegli il file dal tuo computer e clicca su **Invia**.

Il file comparirà quindi nella sezione File della tabella **Panoramica del Test** all'interno della vista del Riscontro.

#### Modifica in blocco dei Riscontri 
I Riscontri possono essere modificati in blocco da un elenco di Riscontri, come la tabella di Tutti i Riscontri accessibile dalla barra laterale, oppure dalla tabella dei Riscontri all'interno di un Test specifico.

Ulteriori informazioni su come modificare in blocco i Riscontri sono disponibili [qui](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings). 

### Chiusura dei Riscontri 
Una volta completato il lavoro su un Riscontro, puoi chiuderlo manualmente cliccando su **Chiudi Riscontro** nel menu kebab ⋮ o nel menu a ingranaggio del Riscontro. In alternativa, se una scansione viene reimportata in DefectDojo e non contiene un Riscontro registrato in precedenza, tale Riscontro verrà chiuso automaticamente.

Se non desideri che nessun Riscontro venga chiuso, puoi disabilitare questo comportamento nel modulo di Reimportazione della scansione:

- Deseleziona la casella Chiudi Riscontri obsoleti se utilizzi l'interfaccia utente
- Imposta close_old_findings su False se utilizzi l'API ​

### Eliminazione dei Riscontri 
L'eliminazione di un Riscontro può essere effettuata dal menu kebab ⋮ o dal menu a ingranaggio del Riscontro. Questa azione non può essere annullata. 

Per finalità di audit, si consiglia di chiudere i Riscontri corretti anziché eliminarli. 

## Gruppi di Riscontri 
I **Gruppi di Riscontri** ti permettono di trattare più Riscontri correlati come un'unica unità logica ai fini del triage, della reportistica e del coordinamento della correzione.

Ad esempio, una scansione potrebbe produrre 10 Riscontri di SQL injection su endpoint diversi. Invece di gestirli singolarmente, puoi raggrupparli in un unico Gruppo di Riscontri che rappresenta il problema più ampio di SQL injection.

Un Gruppo di Riscontri non sostituisce i singoli Riscontri. Ogni Riscontro continua a esistere con la propria gravità, stato, metadati, commenti e cronologia di correzione. Un Gruppo di Riscontri fornisce semplicemente un ulteriore livello organizzativo al di sopra dei Riscontri che contiene.

### Accesso ai Gruppi di Riscontri 
I Gruppi di Riscontri sono accessibili tramite la barra laterale. Il sottomenu offre l'accesso ai Gruppi di Riscontri Aperti e Chiusi, oltre che a Tutti i Gruppi di Riscontri (indipendentemente dallo stato Aperto).

![image](images/profindings_ss1.png)

### Creazione dei Gruppi di Riscontri 
I Gruppi di Riscontri possono essere creati manualmente o automaticamente. 

È importante notare che i Gruppi di Riscontri possono essere creati solo a partire dai Riscontri contenuti in un singolo Test. I Riscontri provenienti da Test, Engagement o Prodotti diversi non possono essere aggiunti allo stesso Gruppo di Riscontri.

#### Gruppi di Riscontri manuali 
Per eseguire manualmente le azioni sui Gruppi di Riscontri:
1. Vai a un elenco di Riscontri all'interno di un Test. 
2. Seleziona il/i Riscontro/i che desideri aggiungere a un Gruppo di Riscontri cliccando sulla casella di controllo corrispondente. 
3. Clicca sul pulsante **Gruppo di Riscontri** che appare nella parte superiore dell'elenco dei Riscontri. 
4. Clicca sull'azione corrispondente che desideri eseguire.
    - **Aggiungi a nuovo Gruppo di Riscontri**: crea un nuovo Gruppo di Riscontri che include i Riscontri selezionati.
    - **Aggiungi a Gruppo di Riscontri esistente**: aggiunge i Riscontri selezionati a un Gruppo di Riscontri preesistente.
    - **Rimuovi da Gruppo di Riscontri**: rimuove i Riscontri selezionati da qualsiasi Gruppo di Riscontri di cui facevano precedentemente parte.
5. Clicca su **Invia**.

Nota che il raggruppamento sarà disabilitato a meno che ogni riscontro selezionato non sia modificabile, non raggruppato e nello stesso Test. 

Inoltre, nota che l'unica azione possibile quando si selezionano Riscontri dall'elenco Tutti i Riscontri è rimuoverli da qualsiasi Gruppo di Riscontri. Questo perché, come accennato, i Gruppi di Riscontri possono essere creati solo a partire dai Riscontri contenuti in un singolo Test.

#### Gruppi di Riscontri automatici 
Durante l'importazione di una scansione, la funzione **Raggruppa per** all'interno del menu a scomparsa **Campi opzionali** può creare automaticamente Gruppi di Riscontri in base a un metodo di raggruppamento scelto. Questo è utile quando uno scanner produce molti Riscontri correlati che dovrebbero essere gestiti insieme.

La casella di controllo adiacente **Crea Gruppi di Riscontri per tutti i Riscontri** svolge due funzioni: 
- **Selezionata**: crea un Gruppo di Riscontri per ogni Riscontro importato, anche se quel Riscontro è l'unico membro del gruppo.
- **Deselezionata**: crea Gruppi di Riscontri solo quando ci sono effettivamente più Riscontri da raggruppare insieme.

![image](images/profindings_ss2.png)

Se durante l'importazione non viene selezionata alcuna opzione dal menu a discesa Raggruppa per (ad esempio, **Titolo del Riscontro** nello screenshot sopra, ecc.), non avverrà alcun raggruppamento. 

Se i criteri di raggruppamento (ad esempio, nome del componente, ID di vulnerabilità, titolo del Riscontro, ecc.) non sono compilati nel Riscontro, per esso non verrà creato alcun gruppo né verrà aggiunto a un Gruppo di Riscontri preesistente. 

Se viene importata una scansione che rivela 10 Riscontri non raggruppati e la stessa scansione viene successivamente reimportata con i Riscontri raggruppati, i primi 10 Riscontri non verranno aggiunti a quel Gruppo di Riscontri (ossia, il Gruppo di Riscontri includerà solo i 10 Riscontri della reimportazione, non i 10 Riscontri dell'importazione iniziale). 

## Modelli di Riscontro 
I **Modelli di Riscontro** consentono agli Utenti di creare modelli riutilizzabili per vulnerabilità e problemi di sicurezza segnalati di frequente. Un modello può includere informazioni standardizzate come titolo, descrizione, impatto, passaggi per la riproduzione, mitigazione, riferimenti e altri metadati del Riscontro.

I Modelli di Riscontro sono particolarmente utili nelle situazioni in cui gli Utenti devono creare ripetutamente Riscontri manuali e vogliono evitare di reinserire ogni volta le stesse informazioni di supporto.

### Accesso ai Modelli di Riscontro 
I Modelli di Riscontro si trovano nel sottomenu Riscontri della barra laterale. 

![image](images/profindings_ss1.png)

### Creazione dei Modelli di Riscontro
I Modelli di Riscontro possono essere creati cliccando sul pulsante **Nuovo Modello di Riscontro** in alto a sinistra nella vista Modelli di Riscontro. 

La pagina successiva fornisce una panoramica dei metadati che verranno applicati a un Riscontro quando si utilizza un Modello di Riscontro.

### Applicazione dei Modelli di Riscontro
I Modelli di Riscontro differiscono tra DefectDojo OS e DefectDojo Pro. In Pro, i Modelli di Riscontro non possono essere applicati a Riscontri preesistenti, né possono essere creati sulla base di Riscontri preesistenti. 

Tuttavia, puoi aggiungere manualmente un Riscontro a un Test basato su un Modello di Riscontro utilizzando il menu kebab ⋮ accanto al Test nella vista dell'Engagement principale, oppure utilizzando il menu a ingranaggio nella vista del Test. 

![image](images/profindings_ss3.png)

![image](images/profindings_ss4.png)

## Reportistica 
Il generatore di report di DefectDojo ti consente di assemblare un report personalizzato a partire da un insieme di widget di contenuto, eseguirlo ed esportare il risultato (ad esempio, stampandolo in PDF). I report personalizzati possono riassumere i Riscontri o gli Endpoint che desideri condividere con un pubblico esterno e possono includere branding e testo standard.

Ulteriori informazioni sul Generatore di report di DefectDojo sono disponibili [qui](/metrics_reports/reports/report-builder/).

### Esportazione dei Riscontri 
Le pagine che mostrano un elenco di Riscontri o un elenco di Engagement dispongono di un'opzione di esportazione CSV ed Excel in alto a sinistra. Per i Riscontri, è disponibile anche l'opzione per eseguire un'Esportazione rapida, che aprirà una nuova scheda con tabelle di metadati relativi a ciascun Riscontro. 
