---
title: Asset
description: Comprendere gli Asset in DefectDojo OS
audience: opensource
weight: 2
aliases:
- /it/asset_modelling/engagements_tests/os__products/
- /it/en/asset_modelling/engagements_tests/os__products/
---

Organizations → **ASSET** → Engagement → Test → Riscontri

## Panoramica

Gli **Asset** sono al centro del modo in cui il lavoro di sicurezza è organizzato all'interno della gerarchia di oggetti di DefectDojo. Gli Asset rappresentano qualsiasi progetto, programma, software o bene fisico che il team di sicurezza sta testando, e ospitano tutto il lavoro di sicurezza e la cronologia dei test relativi all'obiettivo del test. Esempi di Asset possono includere:
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
- Un ambiente cloud o un dominio di infrastruttura

In generale, un Asset dovrebbe rappresentare la “cosa” di cui si vuole monitorare la postura di sicurezza nel tempo. Questo include la cronologia dei test associata, i Riscontri, le metriche, la proprietà, le integrazioni e i flussi di lavoro di remediation relativi a quella “cosa.”

### Esempi di Asset

Gli Asset possono diventare ancora più granulari a seconda delle esigenze della propria organizzazione. Ad esempio, si potrebbe considerare di creare Asset DefectDojo separati nei seguenti scenari:

- “ExampleAsset” ha una versione Windows, una versione Mac e una versione Cloud
- “ExampleAsset 1.0” utilizza componenti software completamente diversi da “ExampleAsset 2.0”, ed entrambe le versioni sono attivamente supportate dalla propria azienda.
- Il team assegnato a lavorare su “ExampleAsset version A” è diverso dal team Asset assegnato a lavorare su “ExampleAsset version B”, e di conseguenza necessita di permessi di sicurezza diversi.

Sebbene sia possibile scegliere di rappresentare queste variazioni come Engagement all'interno di un unico Asset, l'RBAC può essere impostato solo a livello di Asset o Organizations, il che può limitare l'accesso degli Utenti all'Engagement appropriato (così come ai Test e ai Riscontri all'interno di quegli Engagement) se organizzati in questo modo. Per maggiori informazioni su RBAC e permessi in DefectDojo, fare clic [qui](/admin/user_management/about_perms_and_roles/).

## Dati dell'Asset 

Gli Asset includono sempre i seguenti componenti:

- **Nome univoco**
- **Descrizione**
- **Organization**
- **Configurazione SLA**

I metadati opzionali dell'Asset includono: 

- **Tag**
- **Informazioni sul personale** (ad es. Asset Manager, Team Manager, Technical Contact, ecc.)
- **Normative** (ad es. HIPAA, GLBA, OPPA, ecc.)
- **Criticità aziendale**
- **Piattaforma** (ad es. API, Desktop, IoT, Mobile, Web, ecc.)
- **Ciclo di vita** (ad es. Costruzione, Produzione, Dismissione, ecc.)
- **Origine** (ad es. Libreria di terze parti, Acquistato, Open Source, ecc.)
- **Record utente** (ovvero il numero stimato di record utente nell'Asset)
- **Ricavi**

Questi metadati migliorano il filtraggio, il reporting e la definizione delle priorità nell'ambito del programma di sicurezza, ma soprattutto, gli Asset contengono anche tutti gli Engagement, i Test e i Riscontri relativi agli sforzi di test riguardanti quell'Asset. Tutti i Riscontri dei Test confluiscono infine a livello di Asset, consentendo il monitoraggio a lungo termine, l'analisi delle tendenze e il reporting.

## Accesso agli Asset 

Gli Asset sono accessibili dalla barra laterale. Il sottomenu offre anche l'opzione per creare un nuovo Asset.

![image](images/asset_ss3.png)

### Permessi 

Agli Asset possono essere applicate regole di controllo degli accessi basato sui ruoli (RBAC), che limitano la capacità dei membri del team di visualizzarli e interagire con essi.

I permessi si propagano verso il basso, il che significa che l'accesso a un Asset concede automaticamente l'accesso a tutti gli oggetti al suo interno (ad es. Engagement, Test e Riscontri).

Per maggiori informazioni sui ruoli Utente, consulta il nostro [articolo di introduzione ai ruoli](/admin/user_management/about_perms_and_roles/).

## Vista Asset 

Le viste degli Asset contengono una varietà di tabelle e grafici per interpretare a colpo d'occhio lo stato di un Asset. Questo include: 

- **Metadati**
    - Inclusi Organization, criticità aziendale, ricavi e altri dettagli aggiunti dalle impostazioni dell'Asset. 
- **Metriche**
    - Un elenco dei Riscontri aperti all'interno dell'Asset, raggruppati per gravità 
- **Service Level Agreement per gravità**
    - Applica la configurazione SLA dell'Asset dalle impostazioni ai Riscontri all'interno dell'Asset. 
- **Tecnologie**
    - Ad es. next.js, vue.js, npm v.1.2.3, Django, nginx, Hugo
- **Normative**
- **Avanzamento Benchmark**
- **Membri**
- **Gruppi**
- **Contatti**
- **Notifiche**
    - Attiva e disattiva le notifiche in base a eventi specifici (ad es. un Engagement è stato aggiunto o chiuso) 

## Utilizzo degli Asset

### Creare Asset 

Esistono più modi per creare un nuovo Asset, tra cui: 

- Il pulsante **Add Asset** nell'elenco All Assets 

![image](images/asset_ss2.png)

- Dal menu a discesa della tabella Asset all'interno della vista di un'Organization 
    - Questo creerà automaticamente l'Asset all'interno di quell'Organization. 

![image](images/asset_ss1.png)

- Il pulsante **Add Asset** nella barra laterale 

![image](images/asset_ss5.png)

### Modificare gli Asset 

Un Asset può essere modificato dalle sue impostazioni, accessibili in due modi: 

- Il pulsante **Edit** all'interno del menu kebab ⋮ a sinistra dell'Asset nella vista All Assets

![image](images/asset_ss6.png)

- Il pulsante **Edit** all'interno del menu a discesa **Settings** nella vista dell'Asset

![image](images/asset_ss7.png)

### Eliminare gli Asset 

L'opzione per eliminare un Asset si trova in fondo agli stessi menu descritti nella sezione **Edit Assets** sopra. Questa azione non può essere annullata. Un Asset non può essere chiuso e riaperto in seguito.

L'eliminazione di un Asset comporterà anche l'eliminazione di quanto segue: 
- Tutti gli Engagement e i Test contenuti nell'Asset
- Tutta la cronologia di sicurezza associata, inclusi Riscontri e integrazioni
- Eventuali Jira Epic collegati
- Tutte le note e i file caricati associati agli Engagement e ai Test dell'Asset

## Confini dell'Asset 

### Deduplicazione 

Gli Asset sono “isolati” e non interagiscono con altri Asset. Le Smart Features di DefectDojo, come la Deduplicazione, si applicano solo nel contesto di un singolo Asset. I Riscontri appartenenti ad Asset diversi non verranno deduplicati automaticamente.

### Metriche 

La maggior parte del reporting e delle metriche aggrega i dati a livello di Asset, rendendo gli Asset l'unità primaria per misurare e monitorare il rischio.

Di conseguenza, molte metriche chiave vengono calcolate per Asset, tra cui:

- Numero totale di Riscontri (per gravità o stato)
- Tempo medio di remediation (MTTR)
- Tassi di conformità e violazione dell'SLA
- Andamento del rischio nel tempo

Ciò significa che il modo in cui gli Asset sono strutturati influenzerà direttamente l'accuratezza e l'utilità dei report. Ad esempio, raggruppare più sistemi non correlati sotto un unico Asset può offuscare la visibilità del rischio, mentre strutture di Asset eccessivamente granulari possono frammentare il reporting, rendendo difficile identificare tendenze più ampie.

Le metriche specifiche di un Asset sono accessibili dal pulsante **Metrics** nella barra superiore della vista dell'Asset scelto. 

![image](images/asset_ss8.png)

### Pipeline CI/CD

Le pipeline CI/CD automatizzano l'importazione dei risultati delle scansioni. Indipendentemente dal metodo di integrazione, tutti gli import di scansioni devono essere associati a un Asset, rendendo l'Asset il punto di ancoraggio per i dati di sicurezza generati dalla pipeline.

Quando una pipeline invia i risultati di una scansione, deve:

- Specificare un Asset esistente (ed eventualmente un Engagement), oppure
- Essere configurata in modo da mappare in modo coerente i risultati sull'Asset corretto

Tutti i Riscontri importati erediteranno il contesto dell'Asset, inclusi proprietà, permessi, configurazione SLA e ambito di reporting.

In pratica, gli Asset dovrebbero essere definiti in modo da riflettere come i sistemi vengono costruiti e distribuiti all'interno del CI/CD, per garantire che i risultati di sicurezza siano costantemente associati all'applicazione o al servizio corretto.

### Relazioni con Jira 

Gli Asset possono essere mappati direttamente su Jira Project, che inviano i Riscontri dell'Asset a un'istanza Jira.

Poiché i Riscontri ereditano rischio, priorità e proprietà dal loro Asset padre, l'Asset determina di fatto il contesto di remediation che confluisce nei ticket Jira e nei flussi di lavoro dei Downstream Connector.

È importante notare che gli Asset sono anche il fattore determinante principale delle caratteristiche SLA di un Riscontro. Pertanto, l'SLA di un Riscontro dipende dalla configurazione SLA del suo Asset padre. Maggiori informazioni sulle configurazioni SLA sono disponibili [qui](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content). 
