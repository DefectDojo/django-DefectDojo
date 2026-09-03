---
title: Definizioni degli stati dei Riscontri
description: 'Una guida rapida agli stati dei Riscontri: Aperto, Verificato, Accettato..'
weight: 2
aliases:
- /it/en/working_with_findings/findings_workflows/finding_status_definitions
---

Ogni Riscontro creato in DefectDojo ha uno Stato che comunica informazioni rilevanti. Gli stati aiutano il tuo team a tenere traccia dei progressi nella risoluzione dei problemi.

Ogni stato di un Riscontro ha un significato specifico al contesto, che dovrà essere definito dal tuo team. Queste sono le nostre raccomandazioni, ma l'utilizzo da parte del tuo team potrebbe variare.

Nota che Aperto/Chiuso non sono tipi di Stato **espliciti** per i Riscontri.  Alcuni aspetti della Classic UI (la tabella "All Open Findings", ad esempio) possono fare riferimento a Riscontri Aperti o Chiusi: questo è pensato come categoria generica per

* Riscontri Attivi e/o Verificati, nel caso dei "Riscontri Aperti"
* Riscontri Inattivi e/o con Rischio accettato, In revisione, Fuori ambito, Falso positivo, nel caso dei "Riscontri Chiusi"

## **Stati dei Riscontri Aperti**

Una volta che un Riscontro è **Attivo**, verrà etichettato come Riscontro **Aperto**, indipendentemente dal fatto che sia stato **Verificato** oppure no.

I Riscontri Aperti sono visibili dalla vista **Findings \> Open Findings** di DefectDojo.

### **Riscontri Attivi**

'Questo Riscontro è stato individuato da uno strumento di scansione.'

Per impostazione predefinita, qualsiasi nuovo Riscontro creato in DefectDojo verrà etichettato come **Attivo**. In questo caso, Attivo significa 'questo è un nuovo Riscontro che DefectDojo non ha registrato in un'importazione precedente'. Se un Riscontro è stato Mitigato in passato, ma ricompare in una scansione futura, lo stato di quel Riscontro tornerà ad aprirsi per riflettere il fatto che la vulnerabilità è ricomparsa.

### **Riscontri Verificati**

'Il nostro team ha confermato l'esistenza di questo Riscontro.'

Il fatto che uno strumento registri un problema non significa necessariamente che il Riscontro richieda l'attenzione del team di ingegneria. Per questo motivo, i nuovi Riscontri vengono etichettati anche come **Non verificati** per impostazione predefinita.

Se sei in grado di confermare che il Riscontro esiste effettivamente, puoi contrassegnarlo come **Verificato**.

Alcune funzioni di DefectDojo richiedono che i Riscontri siano Attivi e Verificati.  Se non hai bisogno di verificare manualmente ogni Riscontro, puoi disattivare il requisito di Verifica per una o tutte queste funzioni dalla pagina **Impostazioni di sistema** (**Classic UI: Configurazione > Impostazioni di sistema**, **Pro UI: Impostazioni > Sistema > Impostazioni di sistema**).

![image](images/verified_status_toggle.png)

Questi Stati Verificati sono richiesti per

* Inviare le issue Jira
* Applicare la Grading ai Prodotti
* Calcolare le Metriche

## **Stati dei Riscontri Chiusi**

'La vulnerabilità registrata qui non è più attiva'.

Una volta completato il lavoro su un Riscontro, puoi chiuderlo manualmente tramite l'opzione **Chiudi Riscontri**. In alternativa, se una scansione viene reimportata in DefectDojo senza contenere un Riscontro precedentemente registrato, quest'ultimo si chiuderà automaticamente.

## **Inattivo**

'Questo Riscontro è stato individuato in precedenza, ma è stato mitigato oppure non richiede attenzione immediata.'

Se un Riscontro è contrassegnato come Inattivo, significa che il problema attualmente non ha impatto sull'ambiente software e non richiede interventi. Questo stato non significa necessariamente che il problema sia stato risolto, poiché anche le Accettazioni del rischio attive etichettano i Riscontri come Inattivi.

### **In revisione**

'Ho inviato questo Riscontro a uno o più membri del team affinché lo esaminino.'

Quando un Riscontro è In revisione, deve essere esaminato da un membro del team. Puoi mettere un Riscontro in revisione selezionando **Richiedi Peer Review** dal menu a discesa del Riscontro.

![image](images/Finding_Status_Definitions.png)

### **Rischio accettato**

'Il nostro team ha valutato il rischio associato a questo Riscontro, e abbiamo concordato che possiamo posticipare in sicurezza la sua risoluzione.'

I Riscontri non possono sempre essere rimediati o affrontati per vari motivi. Puoi aggiungere un'Accettazione del rischio a un Riscontro tramite l'opzione **Aggiungi Accettazione del rischio**. Le Accettazioni del rischio ti consentono di caricare file e inserire note a supporto di una decisione di accettazione del rischio.

Le Accettazioni del rischio hanno date di scadenza, al raggiungimento delle quali puoi rivalutare l'impatto del Riscontro e decidere come procedere.

Per maggiori informazioni sulle Accettazioni del rischio, consulta la nostra [Guida](/triage_findings/findings_workflows/os__risk_acceptance/).

### **Fuori ambito**

'Questo Riscontro è stato individuato dal nostro strumento di scansione, ma rilevare questo tipo di vulnerabilità non era l'obiettivo diretto del nostro test.'

Quando contrassegni un Riscontro come Fuori ambito, stai indicando che non è direttamente rilevante per l'Engagement o il Test in cui è contenuto.

Se hai un'attività di test e rimedio relativa a un aspetto specifico del tuo software, puoi utilizzare questo Stato per indicare che questo Riscontro non fa parte di tale attività.

### **Falso positivo**

'Questo Riscontro è stato individuato dal nostro strumento di scansione, ma dopo averlo esaminato abbiamo scoperto che la vulnerabilità segnalata non esiste.'

Dopo aver esaminato un Riscontro, potresti scoprire che la vulnerabilità segnalata in realtà non esiste. Lo stato Falso positivo verrà mantenuto in caso di reimportazione e impedirà l'apertura o la chiusura dei Riscontri corrispondenti, contribuendo a ridurre il rumore.

Se uno strumento di scansione diverso individua un Riscontro simile, questo non verrà registrato come Falso positivo. DefectDojo può confrontare i Riscontri solo all'interno dello stesso strumento per determinare se un Riscontro è già stato registrato.

## Gravità vs Rischio
La Gravità riflette l'impatto tecnico di un problema se sfruttato. Il Rischio riflette l'urgenza aziendale e la risposta richiesta, tenendo conto di fattori come l'esposizione, la sfruttabilità, i controlli compensativi e l'impatto operativo.


## Definizioni dei livelli di rischio
### Urgente
Un riscontro che rappresenta un rischio aziendale immediato e inaccettabile.

Alta probabilità di sfruttamento, oppure sfruttamento attivo osservato
Esposizione diretta di sistemi critici, dati sensibili o ambienti dei clienti
Controlli compensativi limitati o assenti
Il mancato intervento potrebbe causare gravi interruzioni aziendali, impatti normativi o danni alla reputazione

Azione prevista: risposta immediata SLA tipico: rimedio d'emergenza


### Richiede intervento
Un riscontro che presenta un rischio chiaro e concreto che richiede un rimedio o una mitigazione tempestivi.

Esiste un percorso di attacco realistico
L'asset interessato è esposto, critico per il business o rivolto ai clienti
I controlli compensativi sono deboli, assenti o non verificati
Lo sfruttamento comporterebbe un impatto misurabile a livello aziendale, di sicurezza o di conformità

Azione prevista: rimedio o mitigazione attivi richiesti SLA tipico: finestra di rimedio a breve termine


### Rischio medio
Un riscontro che presenta un livello moderato di rischio aziendale e che dovrebbe essere risolto entro tempi pianificati.

Un impatto significativo potrebbe verificarsi in caso di sfruttamento
Esiste una certa esposizione, ma lo sfruttamento richiede condizioni o privilegi specifici
Potrebbe influire indirettamente sui sistemi di produzione o sui dati dei clienti
Spesso corrisponde a problemi di gravità media o alta senza sfruttabilità immediata

Azione prevista: rimedio prioritario SLA tipico: finestra di rimedio pianificata


### Rischio basso
Un riscontro che presenta un impatto aziendale minimo e non richiede un intervento immediato.

Nessuno sfruttamento noto in circolazione
Esposizione limitata o assente (ad esempio sistemi interni, non di produzione, controlli compensativi solidi)
Il rimedio può essere affrontato nell'ambito dei normali cicli di sviluppo o manutenzione
Spesso si tratta di riscontri informativi o di bassa gravità, ma possono includere anche problemi di gravità più alta ben mitigati

Azione prevista: monitorare e affrontare in modo opportunistico SLA tipico: best effort / backlog
