---
title: Engagement
description: Informazioni sugli Engagement in DefectDojo OS
audience: opensource
weight: 3
---

Organizzazioni → Asset → **ENGAGEMENT** → Test → Riscontri 

## Panoramica 

Nella gerarchia dei prodotti di DefectDojo, gli Engagement sono contenitori delimitati nel tempo o legati a una pipeline che rappresentano gruppi di Test correlati all'interno di uno specifico Prodotto. Se hai pianificato un'attività di test, sia essa ricorrente o una tantum, un Engagement ti offre un luogo in cui archiviare tutti i risultati correlati.

Esempi di Engagement includono: 
- Penetration test una tantum
- Scansioni ricorrenti mensili o trimestrali
- Periodi di revisione per bug bounty
- Esecuzioni di pipeline CI/CD (per i team che trattano ogni pipeline come un proprio Engagement)
- Cicli di rilascio del codice (ad es. “revisione di sicurezza per il rilascio v4.2”)

### Tipi di Engagement 

DefectDojo supporta due tipi di Engagement: **Interattivo** e **CI/CD**. Questi tipi determinano il modo in cui i Test vengono generalmente creati e come vengono importati i risultati delle scansioni.

Un Engagement Interattivo viene generalmente condotto da un ingegnere. Gli Engagement Interattivi si concentrano sul test di un'applicazione mentre è in esecuzione, tramite un test automatizzato, un tester umano o qualsiasi attività che “interagisca” con le funzionalità dell'applicazione. 

Un Engagement CI/CD è pensato per l'integrazione automatizzata con una pipeline CI/CD. Gli Engagement CI/CD sono destinati a importare dati come azione automatizzata, attivata da una fase del processo di rilascio.

| **Categoria**                | **Engagement Interattivi**                             | **Engagement CI/CD**                                              |
|------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| **Caso d'uso principale**   | Test di sicurezza manuali o ad-hoc                            | Test di sicurezza automatizzati e ricorrenti all'interno delle pipeline             |
| **Durata**           | Delimitata nel tempo e finita                                        | Durata potenzialmente infinita                                      |
| **Frequenza**          | Periodica o una tantum                                          | Continua o per ogni commit                                           |
| **Flusso di lavoro**           | Il tester umano esegue lo strumento → importa manualmente i risultati            | La pipeline esegue lo strumento → invia automaticamente i risultati a DefectDojo    |
| **Metodo di importazione dei risultati** | Caricamento manuale tramite UI o CLI                                 | Importazione basata su API tramite automazione (ad es. CLI, connettori, cron job, script di pipeline) |
| **Tipo di test tipico** | Penetration test, esercitazioni red team, valutazioni manuali   | Analisi statica, scansione delle dipendenze, scansione dei container           |

### Dati dell'Engagement

In quanto contenitori che organizzano l'attività di test, gli Engagement possono archiviare o tracciare una varietà di dati:

- Date di inizio e fine previste
- Descrizione e note sull'ambito
- Stato (in corso, pianificato, completato, ecc.)
- Assegnatario / Responsabile
- Test associati (ad es. scansioni, penetration test, test manuali, ecc.)
- Riscontri e tipi di Riscontro (ad es. attivo, mitigato, rischio accettato, duplicato, ecc.) 
- Modelli di minaccia o informazioni sull'accettazione del rischio
- Tag
- File e note
- Impostazioni del progetto Jira
- Dettagli sull'ambiente (ad es. staging vs. produzione)
- ID di build (se collegato a CI/CD)
- Dati storici dei Test precedenti all'interno dell'Engagement 

## Accesso agli Engagement 

Gli Engagement sono accessibili tramite la barra laterale. Il sottomenu fornisce l'accesso a Engagement attivi e Tutti gli Engagement, oltre alla possibilità di visualizzare gli Engagement organizzati per Prodotto, tipo di Test e ambiente. 

![image](images/engagement_ss17.png)

In alternativa, è possibile accedere agli Engagement di un determinato Prodotto dal sottomenu dell'opzione Engagement nella barra superiore.

![image](images/engagement_ss18.png)

### Permessi 

Gli Engagement si collocano al di sotto dei Prodotti e al di sopra dei Test nella gerarchia degli oggetti. Di conseguenza, l'accesso a un Prodotto concede automaticamente l'accesso a tutti gli Engagement al suo interno. Gli Engagement non dispongono di liste di controllo degli accessi indipendenti.

## Utilizzo degli Engagement

### Creazione di Engagement 

Esistono diversi approcci per creare un Engagement. Ciascun approccio richiede che venga prima creato un Prodotto che lo contenga. 

Una volta creato un Prodotto, è possibile aggiungere un nuovo Engagement Interattivo o CI/CD nella sezione Engagement della barra di navigazione del Prodotto.

![image](images/engagement_ss4.png)

Ogni Engagement deve avere definiti i seguenti campi:
- Tipo (Interattivo o CI/CD)
- Un nome univoco 
- Date di inizio e fine previste 
    - Questo determinerà la comparsa dell'Engagement nella sezione Calendario
- Prodotto
- Stato 

#### Stati dell'Engagement

Gli Engagement possono essere contrassegnati con stati diversi al momento della creazione. Lo stato può anche essere modificato in seguito nelle impostazioni dell'Engagement. 

Un Engagement può avere uno dei seguenti stati: 
- Non iniziato
- Bloccato
- Annullato 
- Completato 
- In corso 
- In sospeso 
- Pianificato 
- In attesa di risorsa

Modificare lo stato di un Engagement in “Completato” comporterà che la maggior parte delle operazioni di scrittura (ad es. l'aggiunta di test, l'importazione di scansioni) diventino non disponibili o nascoste. Gli altri stati non influiscono in modo sostanziale sulla funzionalità dell'Engagement e servono principalmente a scopi di filtraggio/informativi.

### Modifica degli Engagement 

Gli Engagement possono essere modificati facendo clic sul pulsante **Modifica** all'interno delle impostazioni dell'Engagement. Tutti i campi modificabili sono disponibili anche durante la creazione dell'Engagement.

### Copia degli Engagement 

È possibile duplicare facilmente gli Engagement accedendo all'elenco degli Engagement all'interno di un Prodotto e facendo clic sul pulsante **Copia** dal menu kebab ⋮ accanto all'Engagement da copiare. Questo creerà una copia esatta dell'Engagement originale all'interno del Prodotto principale, inclusi i metadati, i Test e i Riscontri in esso contenuti.

![image](images/engagement_ss19.png)

### Chiusura degli Engagement 

Gli Engagement possono essere chiusi accedendo all'elenco degli Engagement all'interno di un Prodotto e facendo clic su “Chiudi” dal menu kebab ⋮ dell'Engagement scelto. 

![image](images/engagement_ss20.png)

Una volta chiuso, lo stato dell'Engagement verrà modificato in “Completato”. Tuttavia, la maggior parte delle operazioni di scrittura (ad es. l'aggiunta di test, l'importazione di scansioni) rimarrà disponibile. 

La chiusura di un Engagement non modifica lo stato dei Riscontri all'interno di nessuno dei Test dell'Engagement. I Riscontri rimangono attivi, mitigati o a rischio accettato in base al proprio ciclo di vita e restano accessibili per la visualizzazione e la reportistica.

Se l'Engagement è collegato a un Epic di Jira (vedi **[Integrazione Jira: Abilita il mapping Epic per gli Engagement](/connectors/os_jira/os__jira_guide/#enable-engagement-epic-mapping-for-products)**), la chiusura dell'Engagement attiverà un'attività asincrona che chiude l'Epic Jira associato nel tuo Jira Space collegato.

### Riapertura degli Engagement 

Se un Engagement è chiuso, può essere riaperto facendo clic su **Riapri** dal menu kebab ⋮ nella tabella degli Engagement chiusi. Questo renderà nuovamente attivo l'Engagement e riporterà il suo stato a “In corso”.

![image](images/engagement_ss21.png)

### Engagement scaduti 

Un Engagement scade una volta superata la data di fine prevista.

La scadenza dell'Engagement non ha un impatto diretto sulla sua funzionalità e serve principalmente come meccanismo di monitoraggio/notifica.  

Una volta scaduto, nel campo “Durata” dell'Engagement comparirà una notifica rossa “In ritardo di X giorni”, che tuttavia non limiterà alcuna funzionalità dell'Engagement. Lo stato dell'Engagement continuerà a comparire come “In corso”. 

Sebbene non sia abilitata per impostazione predefinita, nelle impostazioni di sistema è disponibile un'opzione per chiudere automaticamente un Engagement una volta scaduto da un determinato numero di giorni. 

![image](images/engagement_ss22.png)

### Eliminazione degli Engagement 

L'eliminazione di un Engagement può essere effettuata selezionando **Elimina** dalle impostazioni dell'Engagement. Questa azione non può essere annullata. 

L'eliminazione di un Engagement comporterà anche l'eliminazione di quanto segue: 
- Tutti i Test associati all'Engagement 
- Tutti i Riscontri contenuti in tali Test 
- Eventuali mapping con Epic Jira collegati (l'Epic stesso rimarrà in Jira, ma il collegamento tra DefectDojo e Jira verrà rimosso)
- Tutte le note e i file caricati associati all'Engagement 

A fini di audit, si consiglia di chiudere gli Engagement completati anziché eliminarli. 

| **Operazione** | **Risultati** | **Reversibile** |
|----------|---------|------------|
| **Chiudi** | Contrassegna come inattivo; i dati rimangono; può essere riaperto | Sì (riapertura) |
| **Scadenza** | Solo avviso visivo; chiusura automatica opzionale; notifiche | N/D |
| **Elimina** | Rimuove definitivamente Engagement, Test, Riscontri, note, file ed eventuali mapping con Epic Jira (gli Epic rimangono in Jira) | No |

## Integrazione con Jira

Gli Engagement possono essere collegati a uno Jira Space connesso, consentendo di inviare a Jira, come Issue, i Riscontri contenuti nell'Engagement. Per una guida completa alla configurazione di Jira, vedi **[Collegare DefectDojo a Jira](/connectors/os_jira/os__jira_guide/)**.

### Mapping Epic dell'Engagement

Quando l'opzione **Abilita mapping Epic per gli Engagement** è selezionata nelle impostazioni Jira di un Prodotto, gli Engagement verranno inviati a Jira come Epic. I Riscontri contenuti nell'Engagement vengono inviati come Issue figlie sotto l'Epic, rispecchiando la gerarchia Engagement → Riscontri di DefectDojo nella struttura Epic → Issue di Jira.

Per maggiori informazioni su questa impostazione, vedi **[Abilita mapping Epic per gli Engagement](/connectors/os_jira/os__jira_guide/#enable-engagement-epic-mapping-for-products)**.

### Impostazioni Jira a livello di Engagement

Per impostazione predefinita, gli Engagement ereditano le proprie impostazioni Jira dal Prodotto principale. Tuttavia, i singoli Engagement possono sovrascrivere queste impostazioni per utilizzare configurazioni Jira diverse. Le seguenti impostazioni possono essere personalizzate per ogni Engagement:

- **Project Key** — instrada i Riscontri verso uno Jira Space diverso
- **Issue Template** — utilizza un modello diverso per le Issue create da questo Engagement
- **Custom Fields** — applica mapping di campi personalizzati diversi
- **Jira Labels** — contrassegna le Issue con etichette specifiche dell'Engagement
- **Default Assignee** — assegna le Issue a un altro membro del team

Queste impostazioni sono accessibili dalla pagina **Modifica Engagement**. Per maggiori dettagli, vedi **[Impostazioni Jira a livello di Engagement](/connectors/os_jira/os__jira_guide/#engagement-level-jira-settings)**.
