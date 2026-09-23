---
title: ❓ Domande frequenti
description: FAQ di DefectDojo
draft: 'false'
weight: 2
chapter: true
aliases:
- /it/en/about_defectdojo/faq
---

Ecco alcune domande frequenti su come lavorare con DefectDojo, sia in DefectDojo Pro che in DefectDojo OS.

## Domande generali

### Come dovrei organizzare i miei test di sicurezza in DefectDojo?

Sebbene DefectDojo possa supportare qualsiasi ambiente di sicurezza o di test, il team di sicurezza e le operazioni di ciascuna organizzazione sono diversi, quindi non esiste un approccio universale al suo utilizzo. Abbiamo un articolo molto dettagliato sui [casi d'uso comuni](/get_started/common_use_cases/common_use_cases/) che riporta esempi di come diverse organizzazioni applicano il RBAC e il modello dei dati di DefectDojo per soddisfare le proprie esigenze.

### Quali sono i flussi di lavoro consigliati per i test di sicurezza in DefectDojo?

DefectDojo è pensato per essere la fonte centrale di verità per la postura di sicurezza della tua organizzazione, e può soddisfare esigenze diverse a seconda dei requisiti della tua organizzazione, ad esempio:

- Consentire agli utenti di identificare i riscontri duplicati tra scansioni e strumenti diversi, riducendo l'affaticamento da notifiche.
- Applicare SLA sulle vulnerabilità, garantendo che la tua organizzazione gestisca ogni Riscontro entro un intervallo di tempo appropriato.
- [Inviare ticket](/connectors/issue_tracking/) a Jira, ServiceNow o altri software di Project Tracking, permettendo al tuo team di sviluppo di integrare la remediation dei problemi nel proprio normale processo di rilascio, senza dover imparare un altro strumento di gestione progetti.
- Integrarsi in [pipeline CI/CD](/import_data/import_scan_files/api_pipeline_modelling/) automatizzate per acquisire automaticamente i dati dei report dai repository, anche a livello di singolo branch.
- Creare [report](/metrics_reports/reports/) su qualsiasi insieme di vulnerabilità o contesto software, per condividere rapidamente i risultati delle scansioni o aggiornamenti di stato con gli stakeholder.
- Definire flussi di lavoro di accettazione e mitigazione, a supporto di un tracciamento formale della gestione del rischio.


DefectDojo è progettato per supportare e standardizzare il tuo attuale flusso di lavoro di sicurezza. Tutti questi metodi possono essere utilizzati per migliorare i processi del tuo team e adattarsi al modo in cui operi attualmente.

### Quali funzionalità sono disponibili in DefectDojo Pro?

DefectDojo Pro amplia ulteriormente i flussi di lavoro sopra descritti, aggiungendo:

- Una [UI migliorata](/get_started/about/ui_pro_vs_os/) progettata per velocità ed efficienza nella navigazione tra volumi di dati di livello enterprise. Include anche una modalità scura.
- La possibilità di [pre-triare i tuoi Riscontri](/asset_modelling/pro_hierarchy/priority_sla/) per Priorità e Rischio, permettendo al tuo team di identificare e risolvere prima i problemi più critici.
- Un [Motore di regole](/automation/rules_engine/about) per scriptare azioni collettive automatizzate e costruire flussi di lavoro personalizzati per gestire i Riscontri e altri oggetti, senza bisogno di esperienza di programmazione.
- [Funzionalità avanzate di generazione di report e metriche](/get_started/about/ui_pro_vs_os/#new-dashboards) per condividere facilmente la postura di sicurezza delle tue app e dei tuoi repository.
- [Impostazioni di deduplicazione avanzate](/triage_findings/finding_deduplication/pro__deduplication_tuning/) per mettere a punto il modo in cui DefectDojo identifica e gestisce i riscontri duplicati.
- Funzionalità di importazione semplificate, tra cui: 
  - Un metodo di caricamento ottimizzato che elabora i Riscontri in background.
  - La possibilità di costruire rapidamente una [pipeline da riga di comando](/import_data/pro/specialized_import/external_tools/) utilizzando le nostre app Universal Importer e DefectDojo CLI, che ti permettono di importare, reimportare ed esportare facilmente i dati verso la tua istanza DefectDojo Pro.
  - Un [Universal Parser](/import_data/pro/specialized_import/universal_parser/) per trasformare qualsiasi report .json o .csv in un insieme di Riscontri utilizzabile, con DefectDojo Pro che analizza i dati nel modo che preferisci.
  - I [Connettori](/connectors/upstream/about/), che forniscono una connessione immediata agli strumenti supportati per importare nuovi dati sui Riscontri, così da poter attivare una pipeline di importazione automatizzata senza dover configurare chiamate API o cron job.

### Come gestisce DefectDojo il controllo degli accessi?

DefectDojo può essere utilizzato da team di grandi dimensioni, e configurare il [RBAC (Rule Based Access Control)](/admin/user_management/about_perms_and_roles/) è vivamente consigliato, sia per stabilire correttamente il contesto per ciascun membro del team, sia per controllare l'accesso a determinate parti dell'infrastruttura.

L'assegnazione di ruoli e permessi avviene generalmente a livello di Tipo di prodotto / Prodotto.  Ogni membro del team può essere assegnato a uno o più Prodotti o Tipi di prodotto, e può ricevere un ruolo che determina come può interagire con i dati sulle vulnerabilità in essi contenuti (sola lettura, lettura-scrittura o controllo completo).  Per maggiori informazioni, consulta la nostra [guida al RBAC](/admin/user_management/about_perms_and_roles/).

### Come gestisce DefectDojo il controllo degli accessi per un team di utenti?

Che tu sia un team di sicurezza composto da una sola persona per una piccola organizzazione, o un CISO che supervisiona un ampio numero di progetti software,puoi organizzare facilmente il [Controllo degli accessi basato sui ruoli (RBAC)](/admin/user_management/about_perms_and_roles/) per stabilire correttamente il contesto di ciascun membro del team e controllare l'accesso a determinate parti dell'infrastruttura.

In genere, l'assegnazione di ruoli e permessi avviene a [livello di Tipo di prodotto/Prodotto](/asset_modelling/os_hierarchy/product_hierarchy/). Ogni membro del team può ricevere un ruolo relativo a uno o più Prodotti o Tipi di prodotto, che determina come può interagire con i dati sulle vulnerabilità in essi contenuti (ad es. sola lettura, lettura-scrittura o controllo completo). 

## Flussi di lavoro di importazione

### Quali strumenti sono supportati da DefectDojo?

DefectDojo supporta i report di [oltre 500](/supported_tools/) strumenti di sicurezza commerciali e open-source.

Se stai cercando di aggiungere un nuovo strumento alla tua suite, abbiamo un elenco di strumenti Open-Source consigliati che puoi consultare [qui](https://defectdojo.com/blog/announcing-the-defectdojo-open-source-security-awards).

### Qual è la differenza tra Import e Reimport?

Esistono due metodi diversi per importare un singolo report da uno strumento di sicurezza:

- **Import** gestisce il report come un singolo record puntuale nel tempo. Importare un report crea un Test contenente i Riscontri risultanti.
- **[Reimport](/import_data/import_intro/reimport/)** viene utilizzato per aggiornare un Test esistente con un nuovo insieme di risultati. Se il tuo processo di test segue un approccio più aperto, puoi eseguire continuamente il Reimport dell'ultima versione del tuo report su un Test esistente. DefectDojo confronterà i risultati del report in arrivo con i dati esistenti, registrerà eventuali modifiche e poi adeguerà i Riscontri nel Test in modo che corrispondano all'ultimo report.

Per comprendere la differenza, può essere utile pensare a Import come alla registrazione di una singola istanza di un evento di scansione, e a Reimport come all'aggiornamento di un registro continuo delle scansioni.

Ecco un'analogia; se fossi un contabile, potresti usare Import per registrare una singola ricevuta, mentre useresti Reimport per tenere un registro continuo delle spese

Entrambi i metodi utilizzano anche la Deduplicazione in modo diverso: mentre due Test Importati distinti nello stesso Prodotto identificheranno ed etichetteranno i Riscontri duplicati separatamente, Reimport non creerà alcun Riscontro che identifica come [duplicato](/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport/) all'interno del Test.

In generale, se hai bisogno di un report puntuale, Import è il metodo migliore da utilizzare. Se esegui e acquisisci continuamente report da uno strumento, Reimport è il metodo più adatto per mantenere tutto organizzato.

### Come posso risolvere i problemi di importazione?

DefectDojo supporta un'ampia varietà di strumenti. Se riscontri un comportamento incoerente durante l'importazione di un report, ti consigliamo di verificare che la struttura del file corrisponda a quella attesa dallo strumento. Consulta il nostro [Elenco dei parser](/supported_tools/) per confermare che il tuo strumento sia supportato, e verifica che il formato del file corrisponda a quello previsto dallo strumento. Puoi anche confrontare la struttura con i nostri Unit Test.

DefectDojo Pro dispone di un metodo di importazione Universal Parser che permette di gestire qualsiasi file JSON, CSV o XML. Gli utenti di DefectDojo OS possono scrivere parser personalizzati per lo stesso scopo.

Infine, è noto che i formati dei report di terze parti possono cambiare senza preavviso: la nostra community OS apprezza molto le [PR e i contributi](/get_started/contributing/how-to-write-a-parser/) per mantenere aggiornati i nostri parser.

### Come dovrei gestire file di scansione di grandi dimensioni?

Importare un report di grandi dimensioni in DefectDojo può essere un processo lungo. I report da 2MB contengono quantità sostanziali di dati, che possono richiedere molto tempo per essere tradotti in Riscontri a seconda del formato di report dello strumento di sicurezza.

Il nostro approccio consigliato è suddividere i report di grandi dimensioni prima dell'importazione, in modo da riflettere le diverse sottosezioni dei dati disponibili. Se il tuo strumento di sicurezza può filtrare i risultati per progetto software, applicazione o altro contesto, esportare report più piccoli rende più semplice per DefectDojo gestire e categorizzare i dati. Questo ha anche il vantaggio aggiuntivo di organizzare in modo proattivo i tuoi Riscontri in base a come sono stati suddivisi i dati, rendendo la generazione dei report più pertinente e veloce.

DefectDojo Pro può elaborare i report in background. Tuttavia, i file devono comunque essere caricati e convalidati da DefectDojo prima che possa iniziare il processo di creazione dei Riscontri in background.

### Come posso collegare una pipeline CI/CD a DefectDojo?

Molte delle funzionalità principali di DefectDojo possono essere completamente automatizzate.  CI/CD (o qualsiasi altro tipo di importazione automatizzata) può essere gestito chiamando la [API REST di DefectDojo](/import_data/import_scan_files/api_pipeline_modelling/).

Gli utenti di **DefectDojo Pro** hanno anche accesso agli [strumenti da riga di comando](/import_data/pro/specialized_import/external_tools/) **Universal Importer / DefectDojo CLI**, che possono essere installati per essere eseguiti in molti ambienti automatizzati.

## Gestione dei Riscontri

### Cosa significa lo stato di un Riscontro?

I Riscontri possono avere diversi stati. Uno stato Attivo o Inattivo è sempre impostato su un Riscontro, mentre altri stati come Verificato, Falso positivo o Fuori ambito possono essere applicati a tua discrezione.

Questi stati sono descritti in maggiore dettaglio nella nostra guida [Definizioni degli stati dei Riscontri](/triage_findings/findings_workflows/finding_status_definitions/), insieme a informazioni su come possono essere utilizzati.
 
### Come posso eliminare i Riscontri da DefectDojo?

In generale, consigliamo di mantenere i Riscontri chiusi come 'Inattivi' piuttosto che eliminarli definitivamente, poiché è importante conservare i record storici nel lavoro AppSec. Eliminare un Riscontro rimuove definitivamente tutte le Note e il tracciamento delle metriche relative a quel Riscontro, il che può portare a report imprecisi o a un archivio incompleto.

I Riscontri possono essere eliminati da DefectDojo in alcuni modi:
- Eseguendo un'azione di [Eliminazione collettiva](/triage_findings/findings_workflows/editing_findings/#bulk-delete-findings) sui Riscontri che desideri eliminare
- Chiamando `DELETE /findings/{id}` tramite l'API
- Eliminando un oggetto padre, come un Test, un Engagement, un Tipo di prodotto o un Prodotto.
  - Nota che le sottoclassi non vengono mantenute indipendentemente dal loro oggetto padre: eliminare un oggetto padre come un Tipo di prodotto eliminerà tutti i Prodotti, gli Engagement, i Test, i Riscontri e gli Endpoint contenuti nel Tipo di prodotto. Al contrario, eliminare un Engagement manterrà i Prodotti e i Tipi di prodotto che lo precedono.

## Reportistica e Jira

### Come posso generare un report in DefectDojo?

Puoi creare rapidamente un report personalizzato in DefectDojo utilizzando il [Generatore di report](/metrics_reports/reports/).

Gli utenti di DefectDojo Pro hanno anche accesso a [dashboard di Metriche di livello esecutivo](/get_started/about/ui_pro_vs_os/#new-dashboards) in grado di generare report su Tipi di prodotto, Prodotti o altri dati in tempo reale.

### Come posso integrare uno strumento di gestione progetti con DefectDojo?

Sia nell'edizione Pro che in quella Open-Source di DefectDojo, i Riscontri possono essere inviati a Jira come Issue, permettendoti di integrare la remediation dei problemi con il tuo team di sviluppo.

DefectDojo Pro aggiunge il supporto per le [Integrazioni aggiuntive di Project Tracking](/connectors/issue_tracking/)**: ServiceNow, Azure DevOps, GitHub e GitLab.
