---
title: Glossario
weight: 1
---

Di seguito è riportato un semplice glossario per aiutare a comprendere le varie funzionalità di DefectDojo, con l'indicazione se ciascuna funzionalità definita è presente/applicabile nella versione Pro di DefectDojo, nella versione OS, oppure in entrambe. 

## Gerarchia dei Prodotti (Entrambe) 
Il modello strutturale utilizzato per organizzare i dati di sicurezza all'interno di DefectDojo, costituito da Organizations → Assets → Engagements → Tests → Findings.
## Organization (Entrambe)
Un oggetto gerarchico di primo livello che funge da oggetto padre degli Asset in DefectDojo Pro. Fornisce un contesto condiviso per la governance, il controllo degli accessi e il reporting su tutti gli Asset figli.
## Asset (Entrambe)
Un oggetto di prima classe che rappresenta un'entità di sistema distribuibile o logica (ad esempio, applicazione, host, ambiente) all'interno delle Organization. Gli Asset supportano relazioni padre-figlio e metadati aziendali più ricchi nella versione Pro, ma non supportano relazioni padre-figlio nella versione OS.
### Gerarchia degli Asset (Pro)
Un modello di relazione padre-figlio tra Asset che consente l'ereditarietà del contesto e l'aggregazione dei Riscontri.
## Engagement (Entrambe)
Un'attività di sicurezza delimitata che rappresenta una finestra di test, una pipeline o un contesto di valutazione.
## Test (Entrambe) 
Una singola esecuzione di uno scanner o di una valutazione manuale all'interno di un Engagement. I Test memorizzano i metadati di esecuzione e fungono da punto di ingestione per i Riscontri.
## Service (Entrambe)
Un sotto-oggetto opzionale utilizzato per attribuire i Riscontri a un componente o un'interfaccia specifica all'interno di un Asset. I Service sono particolarmente utili in OS DefectDojo, poiché la loro funzionalità viene replicata e potenziata dalla Gerarchia degli Asset nella versione Pro.
## Components (Entrambe)
Una libreria di terze parti, un modulo software o una dipendenza esterna tracciata in DefectDojo Pro. I Component importati derivano dai dati di scansione e sono associati ai Riscontri. Nell'interfaccia Pro, la Component Table aggrega i conteggi dei Riscontri Attivo, Duplicato e Totale per Component e rimane popolata anche quando tutti i Riscontri associati sono Mitigato.
## Finding (Entrambe)
L'oggetto vulnerabilità più granulare nella Gerarchia dei Prodotti di DefectDojo, che rappresenta un problema di sicurezza specifico.
### Stato del Riscontro (Entrambe)
Lo stato attuale del ciclo di vita di un Riscontro (ad esempio, Attivo, Verificato, Inattivo/Mitigato, Under Review, Rischio accettato, Falso positivo, Fuori ambito). Lo Stato del Riscontro determina l'inclusione nelle metriche e nelle dashboard.
### Priorità/Rischio del Riscontro (Pro) 
Un valore calcolato o derivato che rappresenta l'urgenza di remediation combinando la gravità con fattori contestuali come la criticità dell'asset o la sfruttabilità. La Priorità è distinta dalla gravità grezza ed è utilizzata per il processo decisionale basato sul rischio.
### Gruppi di Riscontri (Entrambe)
Un meccanismo per raggruppare Riscontri correlati tra Organization, Asset o strumenti. I Gruppi di Riscontri consentono un'analisi consolidata e un reporting di livello superiore.
## Endpoint (Entrambe)
Una posizione raggiungibile in rete (URL, IP, porta) associata a un Riscontro. Gli Endpoint forniscono il contesto tecnico dello sfruttamento.
## Import (Entrambe)
Il processo di ingestione dei risultati di scansione o dei riscontri manuali in DefectDojo, tipicamente tramite il caricamento di un file o l'invio di dati tramite l'API. Durante l'import, DefectDojo analizza, normalizza, deduplica e associa i riscontri all'Asset, all'Engagement, al Test e agli oggetti correlati appropriati.
## Reimport (Entrambe)
L'azione di ingestione di nuovi risultati di scansione in un Test esistente. Il Reimport aggiorna gli stati dei Riscontri in base alla loro presenza o assenza nei nuovi dati.
## Deduplication (Entrambe)
Il processo di correlazione dei Riscontri in ingresso con quelli esistenti utilizzando hash e logica di corrispondenza, consentendo il tracciamento storico tra le esecuzioni di scansione.
## Falso positivo (Entrambe)
Uno stato del Riscontro che indica che il problema non è valido o non è sfruttabile. I Falsi positivi vengono conservati ai fini di audit ma esclusi dai calcoli del rischio.
## Accettazione del rischio (Entrambe)
Uno stato del flusso di lavoro che indica un Riscontro riconosciuto ma non risolto. I rischi accettati rimangono visibili ma sono esclusi dall'applicazione degli SLA.
## Metadata (Entrambe)
Dati chiave allegati a Test o Riscontri, come il nome del branch o l'ID della build, comunemente forniti tramite pipeline CI/CD.
## Integrazione CI/CD (Entrambe)
Ingestione automatizzata dei risultati di scansione durante i flussi di lavoro di build o deployment. Le integrazioni si basano tipicamente sull'API e sul framework di importazione.
## API (Entrambe)
Un'interfaccia RESTful utilizzata per gestire programmaticamente gli oggetti di DefectDojo. L'API è il meccanismo principale per l'automazione e l'integrazione delle pipeline.
## Webhook (Pro)
Un callback HTTP in uscita attivato da eventi specifici (ad esempio, la creazione di un Riscontro). I Webhook consentono l'integrazione in tempo reale con sistemi esterni.
## Configurazione SLA (Pro)
Definizioni di policy che assegnano scadenze di remediation in base alla gravità o agli attributi di rischio. Gli SLA consentono l'applicazione e la misurazione delle prestazioni.
## Ruolo Utente (Entrambe)
Un insieme di permessi che definisce le azioni consentite all'interno di DefectDojo. I ruoli applicano il controllo degli accessi su Asset ed Engagement.
## Universal Importer (Pro)
Un meccanismo di ingestione flessibile che consente di importare i dati di scansione senza un importatore specifico per lo strumento. Si basa su una mappatura dei campi normalizzata anziché su schemi di scanner predefiniti.
## DefectDojo-CLI (Pro)
Un'interfaccia a riga di comando utilizzata per interagire con DefectDojo in modo programmatico. La CLI è comunemente utilizzata nelle pipeline CI/CD per automatizzare il caricamento delle scansioni e la gestione degli oggetti.
## Connectors (Pro)
L'area unificata dell'interfaccia Pro (in Import) per tutti gli strumenti con cui DefectDojo comunica. Gli Upstream Connector importano i riscontri dagli scanner; i Downstream Connector esportano i riscontri verso i sistemi di issue tracking.
## Upstream Connectors / API Connectors (Pro)
Connettori predefiniti e gestiti che importano riscontri e inventario degli asset in DefectDojo da scanner esterni e strumenti di sicurezza tramite le rispettive API, riducendo la necessità di scripting personalizzato. In precedenza denominati API Connector.
## Downstream Connectors (Pro)
Integrazioni gestite che esportano Riscontri e Gruppi di Riscontri da DefectDojo verso sistemi di issue tracking e ticketing (ad esempio, Jira, Azure DevOps, GitHub). In precedenza denominate Integrations.
## Universal Parser (Pro)
Un motore di parsing generalizzato utilizzato dall'Universal Importer per interpretare i dati di scansione in ingresso. Applica una logica coerente di normalizzazione e deduplicazione tra i formati non supportati.
## Smart Upload (Pro)
Un flusso di lavoro di ingestione intelligente che determina automaticamente come i risultati di scansione debbano essere mappati su Asset o Engagement, riducendo la configurazione manuale durante l'import.
## Executive Insights (Pro)
Analisi di alto livello orientate al business, progettate per un pubblico dirigenziale, incentrate su tendenze, esposizione e salute del programma piuttosto che sui singoli Riscontri.
## Priority Insights (Pro)
Viste analitiche che evidenziano i rischi più critici in base al punteggio di priorità anziché alla sola gravità, supportando la pianificazione della remediation basata sul rischio.
## Program Insights (Pro)
Metriche e visualizzazioni che valutano l'efficacia e la maturità di un programma di sicurezza nel tempo. I Program Insights mettono in evidenza tendenze, copertura e prestazioni operative.
## Tool Insights (Pro)
Analisi incentrate sulle prestazioni degli scanner, sulla copertura e sul contributo ai Riscontri, che aiutano i team a ottimizzare l'uso degli strumenti e a ridurre il rumore.
## Rules Engine (Pro)
Un sistema di automazione basato su policy che applica logica condizionale ai Riscontri durante l'ingestione o gli eventi del ciclo di vita, automatizzando modifiche di gravità, assegnazioni o flussi di lavoro.
## Integrations (Entrambe)
Connessioni tra DefectDojo e strumenti o piattaforme esterne per l'ingestione dei dati, le notifiche o l'automazione dei flussi di lavoro. Pro include integrazioni più approfondite e gestite, oltre agli importatori di base e all'utilizzo dell'API.
