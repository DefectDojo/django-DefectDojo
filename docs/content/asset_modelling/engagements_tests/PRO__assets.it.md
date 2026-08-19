---
title: Asset
description: Comprendere gli Asset in DefectDojo Pro
audience: pro
weight: 2
---

Organizzazioni → **ASSET** → Engagement → Test → Riscontri

## Panoramica

Gli **Asset** sono al centro del modo in cui il lavoro di sicurezza è organizzato all'interno della gerarchia degli oggetti di DefectDojo. Gli Asset rappresentano qualsiasi progetto, programma, software o bene fisico che il vostro team di sicurezza sta testando, e ospitano tutto il lavoro di sicurezza e la cronologia dei test relativi all'obiettivo del test. Esempi di Asset possono includere:
- Release software
- Software di terze parti
- Macchine virtuali o asset in produzione
- Una singola applicazione
- Un microservizio
- Un'API
- Una piattaforma SaaS
- Un'app mobile
- Un sistema interno
- Un servizio aziendale
- Una piattaforma rivolta ai clienti
- Un ambiente cloud o dominio infrastrutturale

In generale, un Asset dovrebbe rappresentare la “cosa” di cui volete monitorare la postura di sicurezza nel tempo. Ciò include la cronologia dei test associata, i Riscontri, le metriche, la proprietà, le integrazioni e i workflow di remediation relativi a quella “cosa”.

### Esempi di Asset

Gli Asset possono diventare ancora più granulari a seconda delle esigenze della vostra organizzazione. Ad esempio, potreste valutare di creare Asset DefectDojo separati nei seguenti scenari:

- “ExampleAsset” ha una versione Windows, una versione Mac e una versione Cloud
- “ExampleAsset 1.0” utilizza componenti software completamente diversi da “ExampleAsset 2.0”, ed entrambe le versioni sono attivamente supportate dalla vostra azienda.
- Il team assegnato a lavorare su “ExampleAsset versione A” è diverso dal team Asset assegnato a lavorare su “ExampleAsset versione B”, e di conseguenza necessita di permessi di sicurezza diversi.

Sebbene possiate anche scegliere di rappresentare queste varianti come Engagement all'interno di un singolo Asset, l'RBAC può essere impostato solo a livello di Asset o Organizzazioni, il che potrebbe limitare l'accesso degli utenti all'Engagement appropriato (nonché ai Test e ai Riscontri all'interno di tali Engagement) se organizzati in questo modo. Per maggiori informazioni su RBAC e permessi in DefectDojo, fate clic [qui](/admin/user_management/about_perms_and_roles/).

## Dati dell'Asset

Gli Asset includeranno sempre i seguenti componenti:

- **Organizzazione**
- **Nome univoco**
- **Descrizione**
- **Configurazione SLA**
- **Motore di prioritizzazione**

I metadati opzionali dell'Asset includono:

- **Tag**
- **Criticità aziendale**
- **Record utente** (ossia il numero stimato di record utente nell'Asset)
- **Fatturato**
- **Informazioni sul personale** (ad es. Asset Manager, Team Manager, Contatto Tecnico, ecc.)
- **Normative** (ad es. HIPAA, GLBA, OPPA, ecc.)
- **Piattaforma** (ad es. API, Desktop, IoT, Mobile, Web, ecc.)
- **Ciclo di vita** (ad es. Costruzione, Produzione, Dismissione, ecc.)
- **Origine** (ad es. Libreria di terze parti, Acquistato, Open Source, ecc.)

Questi metadati migliorano il filtraggio, il reporting e la prioritizzazione in tutto il vostro programma di sicurezza, ma soprattutto, gli Asset contengono anche tutti gli Engagement, i Test e i Riscontri relativi agli sforzi di test riguardanti quell'Asset. Tutti i Riscontri provenienti dai Test confluiscono infine a livello di Asset, consentendo il tracciamento a lungo termine, l'analisi delle tendenze e il reporting.

## Accesso agli Asset

Gli Asset sono accessibili tramite la barra laterale. Il sottomenu offre l'accesso alla [Gerarchia degli Asset](/asset_modelling/engagements_tests/pro__assets/#asset-nesting) e a All Assets, oltre all'opzione per creare un nuovo Asset.

![image](images/assets_ss1.png)

### Permessi

Agli Asset è possibile applicare regole di Role-Based Access Control (RBAC), che limitano la capacità dei membri del team di visualizzarli e interagire con essi.

I permessi si propagano verso il basso, il che significa che l'accesso a un Asset concede automaticamente l'accesso a tutti gli oggetti al suo interno (ad es. Engagement, Test e Riscontri).

Per maggiori informazioni sui ruoli utente, consultate il nostro articolo [Introduzione ai ruoli](/admin/user_management/set_user_permissions/#introduction-to-permission-types).

## Vista Asset

Le viste Asset contengono diverse tabelle e grafici per interpretare lo stato di un Asset a colpo d'occhio. Questi includono:

- **Open Finding Severity**
    - Un elenco dei Riscontri aperti all'interno dell'Asset, raggruppati per gravità
- **Asset Overview**
    - Una panoramica delle varie caratteristiche dell'Asset, tra cui Descrizione, Componenti, Contatti, [Gruppi Utenti](/admin/user_management/create_user_group/
), Membri, Tecnologie e Normative.
        - Tecnologie: next.js, vue.js, npm v.1.2.3, Django, nginx, Hugo
- **Metadata**
    - Inclusi Asset padre e figli, Organizzazione, criticità aziendale, fatturato e altri dettagli aggiunti dalle impostazioni dell'Asset.
- **Service Level Agreement by Severity**
    - Applica la configurazione SLA dell'Asset dalle impostazioni ai Riscontri all'interno dell'Asset.
- **Finding Severity Breakdown**
    - Un grafico dei Riscontri all'interno dell'Asset, organizzati per gravità.
- **Finding Distribution**
    - Una ripartizione dei Riscontri all'interno dell'Asset, organizzati per stato (ad es. Active, Mitigated, Static e Dynamic)
- **All Engagements**
    - Un elenco degli Engagement contenuti nell'Asset.

## Lavorare con gli Asset

### Creare Asset

Esistono due modi per creare Asset:

- Dall'opzione **New Asset** nel menu laterale
- Dal pulsante **New Asset** in cima all'elenco All Assets

## Modificare gli Asset

Gli Asset possono essere modificati facendo clic su **Edit Asset** dal menu a ingranaggio in alto a destra della vista dell'Asset. Lo stesso menu è accessibile anche facendo clic sul menu kebab ⋮ a sinistra dell'Asset nella vista All Assets.

Tutti i campi modificabili di seguito sono disponibili anche durante la creazione dell'Asset.

![image](images/assets_ss2.png)

### Eliminare gli Asset

È possibile eliminare un Asset selezionando **Delete Asset** dalle impostazioni dell'Asset. Questa azione non può essere annullata. Gli Asset non possono essere chiusi e riaperti in seguito.

L'eliminazione di un Asset comporta anche l'eliminazione di quanto segue:
- Qualsiasi Engagement e Test contenuto nell'Asset
- Tutta la cronologia di sicurezza associata, inclusi Riscontri e integrazioni
- Eventuali Epic Jira collegate
- Tutte le note e i file caricati associati agli Engagement e ai Test dell'Asset

## Confini dell'Asset

### Deduplicazione

Gli Asset sono “isolati” e non interagiscono con altri Asset. Le Smart Features di DefectDojo, come la Deduplicazione, si applicano solo nel contesto di un singolo Asset. I Riscontri tra Asset diversi non verranno deduplicati automaticamente.

### Reporting e metriche

La maggior parte del reporting e delle metriche aggrega i dati a livello di Asset, rendendo gli Asset l'unità principale per misurare e monitorare il rischio.

Di conseguenza, molte metriche chiave vengono calcolate per Asset, tra cui:

- Numero totale di Riscontri (per gravità o stato)
- Tempo medio di remediation (MTTR)
- Tassi di conformità e violazione degli SLA
- Tendenze del rischio nel tempo

Ciò significa che il modo in cui gli Asset sono strutturati influenzerà direttamente l'accuratezza e l'utilità dei report. Ad esempio, raggruppare più sistemi non correlati sotto un unico Asset può oscurare la visibilità del rischio, mentre strutture di Asset eccessivamente granulari possono frammentare il reporting, rendendo difficile individuare tendenze più ampie.

### Connettori

In DefectDojo Pro, i Connettori vengono mappati su Asset diversi, rendendoli il punto di integrazione principale tra DefectDojo e il vostro ecosistema di sicurezza più ampio.

Una volta collegato a un Asset, un Connettore importerà i risultati delle scansioni e creerà o aggiornerà Engagement, Test e Riscontri all'interno di quell'Asset.

Per maggiori informazioni sui Connettori, fate clic [qui](/connectors/upstream/about/#main-content).

### Pipeline CI/CD

Le pipeline CI/CD automatizzano l'importazione dei risultati delle scansioni. Indipendentemente dal metodo di integrazione, tutte le importazioni di scansioni devono essere associate a un Asset, rendendo l'Asset il punto di ancoraggio per i dati di sicurezza generati dalla pipeline.

Quando una pipeline invia i risultati di una scansione, deve:

- Specificare un Asset esistente (ed eventualmente un Engagement), oppure
- Essere configurata in modo da mappare in modo coerente i risultati sull'Asset corretto

Tutti i Riscontri importati erediteranno il contesto dell'Asset, inclusi proprietà, permessi, configurazione di priorità/rischio e ambito di reporting.

In pratica, gli Asset dovrebbero essere definiti in modo da riflettere come i sistemi vengono costruiti e distribuiti all'interno del CI/CD, per garantire che i risultati di sicurezza siano costantemente associati all'applicazione o al servizio corretto.

### SLA, Priorità e Rischio

In DefectDojo Pro, i Riscontri ereditano i propri obiettivi SLA, la Priorità e il Rischio dall'Asset che li contiene. I metadati dell'Asset (ad es. criticità aziendale, fatturato, ecc.) vengono utilizzati per calcolare automaticamente i valori di Priorità e Rischio.

Ciò significa che la stessa vulnerabilità può ricevere un punteggio di Priorità o Rischio diverso a seconda che riguardi un sistema di sviluppo interno o un asset di produzione a supporto di operazioni aziendali critiche.

### Relazioni con Jira / Connettori Downstream

Gli Asset possono essere mappati direttamente su istanze [Jira](/connectors/downstream/pro__jira_guide/#main-content) o [Integrators](/connectors/downstream/downstream_toolreference/#main-content) (ad es. GitHub, GitLab, ServiceNow, ecc.), che inviano i Riscontri dell'Asset verso l'esterno, in sistemi esterni di ticketing/gestione del lavoro.

Poiché i Riscontri ereditano rischio, priorità e proprietà dal loro Asset principale, l'Asset determina di fatto il contesto di remediation che confluisce nei ticket Jira e nei workflow dei Connettori Downstream.

È importante notare che gli Asset sono anche il fattore determinante principale per le caratteristiche SLA di un Riscontro. Pertanto, lo SLA di un Riscontro dipende dalla configurazione SLA del suo Asset principale. Maggiori informazioni sulle configurazioni SLA sono disponibili [qui](/asset_modelling/pro_hierarchy/priority_sla/#working-with-slas).

## Nidificazione degli Asset

DefectDojo supporta relazioni padre-figlio tra due Asset all'interno della stessa Organizzazione. Questa relazione può essere configurata durante la creazione dell'Asset o nelle impostazioni dell'Asset.

Potete visualizzare la struttura degli Asset in DefectDojo e modificare le relazioni utilizzando l'opzione **Asset Hierarchy** nella barra laterale.

Dopo aver selezionato dalla tabella corrispondente gli Asset da visualizzare, fate clic su **View Asset Hierarchy** per generare un diagramma di flusso della relazione tra gli Asset scelti, se presente.

Ulteriori informazioni sull'effetto della nidificazione degli Asset sulla deduplicazione, sull'RBAC e su altri dettagli, oltre a esempi di casi d'uso, sono disponibili [qui](/asset_modelling/pro_hierarchy/asset_hierarchy/#asset-nesting-examples).
