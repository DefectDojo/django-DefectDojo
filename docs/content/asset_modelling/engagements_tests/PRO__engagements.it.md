---
title: Engagement
description: Comprendere gli Engagement in DefectDojo Pro
audience: pro
weight: 3
---

Organizzazioni → Asset → **ENGAGEMENT** → Test → Riscontri 

## Panoramica

Nella Gerarchia degli Asset di DefectDojo, gli Engagement sono contenitori delimitati nel tempo o legati a una pipeline che rappresentano gruppi di Test correlati all'interno di un Asset specifico. Se si dispone di un'attività di test pianificata, su base ricorrente o una tantum, un Engagement offre un luogo in cui archiviare tutti i risultati correlati.

Esempi di Engagement includono: 
- Penetration test una tantum
- Scansioni mensili o trimestrali ricorrenti
- Periodi di revisione bug bounty
- Esecuzioni di pipeline CI/CD (per i team che trattano ogni pipeline come un proprio Engagement)
- Cicli di rilascio del codice (ad es., "revisione di sicurezza per il rilascio v4.2")

### Tipi di Engagement 

DefectDojo supporta due tipi di Engagement: **Interactive** e **CI/CD**. Questi tipi determinano come vengono generalmente creati i Test e come vengono importati i risultati delle scansioni.

Un Engagement Interactive viene tipicamente condotto da un ingegnere. Gli Engagement Interactive si concentrano sul test di un'applicazione mentre è in esecuzione, utilizzando un test automatizzato, un tester umano o qualsiasi attività che "interagisce" con le funzionalità dell'applicazione. 

Un Engagement CI/CD è destinato all'integrazione automatizzata con una pipeline CI/CD. Gli Engagement CI/CD hanno lo scopo di importare i dati come azione automatizzata, attivata da una fase del processo di rilascio.

| **Categoria**                | **Engagement Interactive**                             | **Engagement CI/CD**                                              |
|------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| **Caso d'uso principale**   | Test di sicurezza manuali o ad hoc                            | Test di sicurezza automatizzati e ricorrenti all'interno delle pipeline             |
| **Durata**           | Delimitata nel tempo e finita                                        | Potenzialmente di durata infinita                                      |
| **Frequenza**          | Periodica o una tantum                                          | Continua o per commit                                           |
| **Workflow**           | Un tester umano esegue lo strumento → importa manualmente i risultati            | La pipeline esegue lo strumento → invia automaticamente i risultati a DefectDojo    |
| **Metodo di importazione dei risultati** | Caricamento manuale tramite UI o CLI                                 | Importazione basata su API tramite automazione (ad es. CLI, connettori, cron job, script di pipeline) |
| **Tipo di test tipico** | Penetration test, esercitazioni red team, valutazioni manuali   | Analisi statica, scansione delle dipendenze, scansione dei container           |

### Dati dell'Engagement 

In quanto contenitori che organizzano l'attività di test, gli Engagement possono archiviare o tracciare una serie di dati:

- Date di inizio e fine previste
- Descrizione e note sull'ambito
- Stato (ongoing, planned, completed, ecc.)
- Assegnatario / Responsabile
- Test associati (ad es. scansioni, pen test, test manuali, ecc.)
- Riscontri e tipi di Riscontro (ad es. active, mitigated, risk accepted, duplicate, ecc.) 
- Modelli di minaccia o informazioni sull'accettazione del rischio
- Tag
- File e note
- Impostazioni del progetto Jira
- Dettagli sull'ambiente (ad es. staging o produzione)
- ID di build (se collegato a CI/CD)
- Dati storici dei Test precedenti all'interno dell'Engagement 

## Accesso agli Engagement 

Gli Engagement sono accessibili tramite la barra laterale. Il sottomenu offre l'accesso agli Engagement attivi e a tutti gli Engagement, oltre alla possibilità di crearne di nuovi.

![image](images/engagement_ss13.png)

In alternativa, è possibile accedere agli Engagement all'interno di un Asset nella finestra in fondo alla vista dell'Asset.

![image](images/engagement_ss14.png)

### Permessi 

Gli Engagement si trovano al di sotto degli Asset e al di sopra dei Test nella gerarchia degli oggetti. Di conseguenza, l'accesso a un Asset garantisce automaticamente l'accesso a tutti gli Engagement al suo interno. Gli Engagement non dispongono di elenchi di controllo degli accessi indipendenti.

## Utilizzo degli Engagement

### Creazione degli Engagement 

Prima di creare un Engagement, è necessario aver già [creato un Asset](/asset_modelling/engagements_tests/pro__assets/#create-assets) che lo contenga. 

Esistono diversi modi per creare un Engagement: 

- All'interno del menu a tendina Engagement nella sezione Manage della barra laterale
    - Sarà necessario selezionare l'Asset a cui attribuire l'Engagement durante la compilazione del modulo New Engagement

![image](images/engagement_ss1.png)

- L'icona a forma di ingranaggio situata nell'angolo in alto a destra della vista di un Asset

![image](images/engagement_ss9.png)

- Il pulsante "+ New Engagement" presente nell'elenco degli Engagement all'interno di un Asset

![image](images/engagement_ss2.png)

- Se non è già stato creato un Engagement all'interno di un Asset, è possibile farlo durante l'importazione di una scansione. 

![image](images/engagement_ss3.png)

Ogni Engagement deve avere definiti i seguenti campi:
- Tipo (Interactive o CI/CD)
- Un nome univoco 
- Date di inizio e fine previste 
    - Questo determinerà la comparsa dell'Engagement nella sezione Calendario
- Asset 
- Stato 

#### Stati dell'Engagement 

Gli Engagement possono essere contrassegnati con stati diversi al momento della creazione. Lo stato può anche essere modificato successivamente nelle impostazioni dell'Engagement. 

Un Engagement può avere uno dei seguenti stati: 
- Not Started
- Blocked
- Cancelled 
- Completed 
- In Progress 
- On Hold 
- Scheduled 
- Waiting for Resource 

Modificare lo stato di un Engagement in "Completed" comporterà che la maggior parte delle operazioni di scrittura (ad es. aggiunta di test, importazione di scansioni) diventino non disponibili o nascoste. Gli altri stati non influiscono in modo sostanziale sulla funzionalità dell'Engagement e servono principalmente a scopi di filtraggio/informativi.

### Modifica degli Engagement 

Gli Engagement possono essere modificati facendo clic su **Edit Engagement** all'interno del menu a forma di ingranaggio. Lo stesso menu è accessibile anche facendo clic sul menu kebab ⋮ a sinistra dell'Asset nella vista All Assets. 

Tutti i campi successivamente modificabili sono disponibili anche al momento della creazione dell'Engagement. 

![image](images/engagements_ss99.png)

### Copia degli Engagement 

È possibile duplicare facilmente gli Engagement selezionando "Copy Engagement" all'interno delle impostazioni dell'Engagement. Questo creerà una copia esatta dell'Engagement originale all'interno dell'Asset principale, inclusi i metadati, i Test e i Riscontri al suo interno.

### Chiusura degli Engagement 

Gli Engagement vengono chiusi selezionando **Close Engagement** all'interno delle impostazioni dell'Engagement. Una volta chiuso, lo stato dell'Engagement verrà modificato in "Completed." Ciononostante, la maggior parte delle operazioni di scrittura (ad es. aggiunta di test, importazione di scansioni) rimarrà disponibile.

La chiusura di un Engagement non modifica lo stato dei Riscontri all'interno dei Test dell'Engagement. I Riscontri rimangono attivi, mitigati o con rischio accettato in base al proprio ciclo di vita, e restano accessibili per la visualizzazione e la reportistica.

Se l'Engagement è collegato a un Epic Jira (vedere **[Integrazione Jira: Enable Engagement Epic Mapping](/connectors/downstream/pro__jira_guide/#enable-engagement-epic-mapping)**), la chiusura dell'Engagement attiverà un'attività asincrona che chiude l'Epic Jira associato nel proprio Spazio Jira connesso.

### Riapertura degli Engagement 

Se un Engagement è chiuso, può essere riaperto selezionando **Reopen Engagement** all'interno delle sue impostazioni. Questo renderà nuovamente attivo l'Engagement e riporterà il suo stato a "In Progress." 

### Engagement scaduti 

Un Engagement scade una volta superata la data di fine prevista.

Rispetto alla chiusura o all'eliminazione di un Engagement, la scadenza di un Engagement non ha un impatto diretto sulla sua funzionalità, e serve principalmente come meccanismo di monitoraggio/notifica.  

Una volta scaduto, accanto all'Engagement comparirà un tag "Overdue", ma questo non limiterà alcuna funzionalità dell'Engagement. Lo stato dell'Engagement continuerà a essere visualizzato come "In Progress." 

Sebbene non sia abilitata per impostazione predefinita, è disponibile un'opzione nelle impostazioni di sistema per chiudere automaticamente un Engagement una volta scaduto da un determinato numero di giorni. 

![image](images/engagement_ss15.png)

### Eliminazione degli Engagement

L'eliminazione di un Engagement può essere effettuata selezionando **Delete Engagement** dalle impostazioni dell'Engagement. Questa azione non può essere annullata.

L'eliminazione di un Engagement comporterà anche l'eliminazione di quanto segue:
Tutti i Test associati all'Engagement
Tutti i Riscontri all'interno di tali Test
Eventuali mappature di Epic Jira collegate (l'Epic stesso rimarrà in Jira, ma il collegamento tra DefectDojo e Jira verrà rimosso)
Tutte le note e i file caricati associati all'Engagement

Per finalità di audit, si consiglia di chiudere gli Engagement completati anziché eliminarli.

| **Operazione** | **Risultati** | **Reversibile** |
|----------|---------|------------|
| **Chiusura** | Contrassegna come inattivo; i dati rimangono; può essere riaperto | Sì (riapertura) |
| **Scadenza** | Solo avviso visivo; chiusura automatica opzionale; notifiche | N/D |
| **Eliminazione** | Rimuove permanentemente l'Engagement, i Test, i Riscontri, le note, i file ed eventuali mappature di Epic Jira (gli Epic rimangono in Jira) | No |

## Integrazione con Jira

Gli Engagement possono essere collegati a uno Jira Space connesso, consentendo di inviare i Riscontri all'interno dell'Engagement a Jira come Issue. Per una guida completa alla configurazione di Jira, vedere **[Connessione di DefectDojo a Jira](/connectors/downstream/pro__jira_guide/)**.

### Mappatura degli Epic per gli Engagement

Quando l'opzione **Enable Engagement Epic Mapping** è selezionata nelle impostazioni Jira di un Prodotto, gli Engagement verranno inviati a Jira come Epic. I Riscontri all'interno dell'Engagement vengono inviati come Issue figlie sotto l'Epic, rispecchiando la gerarchia Engagement → Riscontri di DefectDojo nella struttura Epic → Issue di Jira.

Per maggiori informazioni su questa impostazione, vedere **[Enable Engagement Epic Mapping](/connectors/downstream/pro__jira_guide/#enable-engagement-epic-mapping)**.

### Impostazioni Jira a livello di Engagement

Per impostazione predefinita, gli Engagement ereditano le impostazioni Jira dal proprio Asset principale (Prodotto). Tuttavia, i singoli Engagement possono sovrascrivere queste impostazioni per utilizzare configurazioni Jira diverse. Le seguenti impostazioni possono essere personalizzate per singolo Engagement:

- **Project Key** — instrada i Riscontri verso uno Jira Space diverso
- **Issue Template** — utilizza un modello diverso per le Issue create da questo Engagement
- **Custom Fields** — applica mappature di campi personalizzati diverse
- **Jira Labels** — contrassegna le Issue con etichette specifiche dell'Engagement
- **Default Assignee** — assegna le Issue a un membro del team diverso

Queste impostazioni sono accessibili dalla pagina **Edit Engagement**. Per maggiori dettagli, vedere **[Impostazioni Jira a livello di Engagement](/connectors/downstream/pro__jira_guide/#engagement-level-jira-settings)**.
