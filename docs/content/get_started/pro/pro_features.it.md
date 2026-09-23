---
title: 📊 Elenco funzionalità Pro
description: Elenco delle funzionalità Pro in DefectDojo
draft: 'false'
weight: 4
chapter: true
exclude_search: true
audience: pro
aliases:
- /it/en/about_defectdojo/pro_features
---

Ecco un elenco delle numerose funzionalità aggiuntive di DefectDojo Pro, con link alla documentazione per vederle in azione:

## UX migliorata

### UI Pro

L'interfaccia utente di DefectDojo è stata rielaborata in DefectDojo Pro per essere più veloce, più funzionale, completamente personalizzabile e più efficace nel gestire la navigazione tra volumi di dati di livello enterprise.  Include anche una modalità scura.
Consulta la nostra [Guida all'UI Pro](/get_started/about/ui_pro_vs_os/) per maggiori informazioni.

![immagine](images/enabling_deduplication_within_an_engagement_2.png)

### Ricerca globale

Trova qualsiasi Riscontro, Asset, Engagement e altro ancora da un'unica casella di ricerca nella barra superiore. La ricerca globale di DefectDojo Pro copre tutti i tuoi oggetti con una ricerca full-text Postgres veloce e tollerante agli errori di battitura.

Consulta la nostra [Guida alla ricerca globale](/navigation/pro__global_search/) per maggiori informazioni.

### Asset/Organizzazioni

DefectDojo Pro consente una visualizzazione organizzativa migliorata per elenchi estesi di repository o altre strutture aziendali.  Consulta la [documentazione su Asset/Organizzazioni](/asset_modelling/pro_hierarchy/asset_hierarchy/) per i dettagli.

![immagine](images/asset_hierarchy_diagram.png)

### Priorità dei Riscontri

DefectDojo Pro può pre-triagare i tuoi Riscontri in base a Priorità e Rischio, consentendo al tuo team di identificare e correggere per primi i problemi più critici.
Consulta la nostra [Guida alla priorità dei Riscontri](/asset_modelling/pro_hierarchy/priority_sla/) per maggiori dettagli.

### Motore di regole

Il motore di regole di DefectDojo Pro ti consente di scrivere azioni collettive automatizzate e creare workflow personalizzati per gestire i Riscontri e altri oggetti, senza bisogno di esperienza di programmazione.

Consulta la nostra [Guida al motore di regole](/automation/rules_engine/about) per maggiori informazioni.

![immagine](images/rules_engine_4.png)

### Sensei

**Sensei** (BETA) di DefectDojo Pro è una funzionalità di scansione e correzione basata su IA: collega un repository tramite una GitHub App e Sensei lo analizza, importa i riscontri e apre pull request che li correggono, con un workflow basato sull'anteprima, in modo che nulla venga eseguito (e nessun costo LLM venga sostenuto) finché non approvi.

Consulta la nostra [Guida a Sensei](/sensei/about_sensei/) per maggiori informazioni.

### Dashboard Pro e reportistica

Genera [report e metriche istantanee](/get_started/about/ui_pro_vs_os/#new-dashboards) per condividere il livello di sicurezza delle tue app e dei tuoi repository, valutare i tuoi strumenti di sicurezza e analizzare le prestazioni del tuo team nella gestione dei problemi di sicurezza.

I grafici presenti nella pagina principale possono essere esportati come file SVG, e anche i dati utilizzati per crearli possono essere esportati come tabella.

Inoltre, DefectDojo Pro include diverse nuove [dashboard di insight](/metrics_reports/pro_metrics/pro__overview/), che offrono metriche avanzate per i vari destinatari del tuo programma di sicurezza.

### Ottimizzazione della deduplicazione

Le impostazioni avanzate di Deduplicazione ti consentono di ottimizzare il modo in cui DefectDojo identifica e gestisce i riscontri duplicati. Regola la Deduplicazione same-tool, **cross-tool** e in fase di reimport per una corrispondenza precisa tra tutti gli strumenti di sicurezza scelti e i riscontri di vulnerabilità.

Consulta la nostra [Guida all'ottimizzazione della deduplicazione](/triage_findings/finding_deduplication/pro__deduplication_tuning/) per maggiori informazioni.

![immagine](images/deduplication_tuning.png)

## Importazione semplificata

### Ulteriori opzioni di importazione

DefectDojo Pro include quattro metodi di importazione aggiuntivi: [Universal Importer](/import_data/pro/specialized_import/external_tools/), [Upstream Connectors](/connectors/upstream/about/), [Universal Parser](/supported_tools/parsers/universal_parser/) e [Smart Upload](/import_data/pro/specialized_import/smart_upload/).

![immagine](images/pro_import_methods.png)


### Importazioni in background

Per i report di livello enterprise, DefectDojo Pro offre un metodo di caricamento ottimizzato che elabora i Riscontri in background.

### Strumenti CLI

Crea rapidamente una pipeline da riga di comando per importare, reimportare ed esportare dati verso la tua istanza di DefectDojo Pro utilizzando le nostre app Universal Importer e DefectDojo-CLI; non è necessario alcuno scripting API (disponibile per Windows, Macintosh o Linux).

Consulta la nostra [Guida agli strumenti esterni](/import_data/pro/specialized_import/external_tools/) per maggiori informazioni.

### Upstream Connector

DefectDojo può connettersi istantaneamente a strumenti di scansione di livello enterprise per importare nuovi dati sui Riscontri, creando una pipeline di importazione automatizzata che funziona subito, senza la necessità di configurare chiamate API o cron job.

Consulta la nostra [Guida agli Upstream Connector](/connectors/upstream/about/) per maggiori informazioni.

![immagine](images/add_edit_connectors_2.png)

Gli strumenti supportati per gli Upstream Connector includono:

* Anchore
* AWS Security Hub
* BurpSuite
* Checkmarx ONE
* Dependency-Track
* Probely
* Semgrep
* SonarQube
* Snyk
* Tenable
* Wiz

### Universal Parser (Beta)

Se utilizzi uno strumento di scansione non supportato/personalizzato, o desideri semplicemente che DefectDojo gestisca un report in modo leggermente diverso, utilizza l'Universal Parser di DefectDojo Pro per trasformare qualsiasi report .json o .csv in un insieme di Riscontri utilizzabili. Il tuo parser analizzerà e mapperà i dati come preferisci.

Consulta la nostra [Guida all'Universal Parser](/import_data/pro/specialized_import/universal_parser//) per maggiori informazioni.

![immagine](images/universal_parser_3.png)

## Gestione delle funzionalità opzionali

Molte delle funzionalità sopra descritte sono opzionali e vengono rilasciate dietro un feature flag, in modo da poterle adottare quando sei pronto. Un superuser può attivarle e disattivarle direttamente da **Settings > Feature Flags**, senza dover contattare il supporto.

Consulta la guida ai [Feature Flag](/admin/feature_flags/pro__feature_flags/) per sapere come abilitare una funzionalità e per capire perché una funzionalità potrebbe essere bloccata o non disponibile per il tuo tipo di installazione.

## Supporto

Gli abbonamenti a DefectDojo Pro includono un supporto di livello mondiale sia per le installazioni on-premise sia per quelle Cloud.  Il nostro team è disponibile per aiutare la tua organizzazione a implementare e massimizzare l'utilizzo di DefectDojo Pro.  Il tuo abbonamento include:

- **Supporto completo**: sono disponibili ticket di supporto e seat illimitati per assistere l'intero team.
- **Attenzione ingegneristica dedicata**: i problemi segnalati dagli utenti, i bug e le richieste di funzionalità ricevono un'attenzione prioritaria dal nostro team di ingegneria.
- **Gestione SaaS**: forniamo monitoraggio, manutenzione e backup per tutte le istanze SaaS.
