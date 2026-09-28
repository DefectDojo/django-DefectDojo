---
title: Organizzazioni
description: Comprendere le Organizzazioni in DefectDojo Pro
audience: pro
weight: 1
---

**ORGANIZZAZIONI** → Asset → Engagement → Test → Riscontri

## Panoramica

Le **Organizzazioni** si trovano al vertice della gerarchia dei prodotti di DefectDojo. Le Organizzazioni si distinguono dagli oggetti sottostanti nella gerarchia — Asset, Engagement, Test e Riscontri — perché non sono target tecnici di scansione, ma servono principalmente come astrazioni organizzative che suddividono i tuoi sforzi di sicurezza in base a: 
- Dominio aziendale
- Team di sviluppo
- Team di sicurezza
- Applicazioni software
- Famiglia di prodotti generale
- Cliente o filiale
- Struttura di reportistica
- ecc. 

Il filo conduttore degli esempi precedenti esemplifica l'utilità essenziale delle Organizzazioni: esse dovrebbero generalmente rappresentare confini stabili e di lunga durata all'interno del tuo programma di sicurezza.

## Dati e struttura dell'Organizzazione

Poiché le Organizzazioni non vengono scansionate direttamente, l'unico campo obbligatorio richiesto per crearle è un nome. Al di là di questo, esse fungono da contenitori per gli Asset e i relativi Engagement, Test e Riscontri sottostanti. 

Quando crei un'Organizzazione, considera come la sua struttura influenzerà la tua reportistica. Hai principalmente bisogno che le Organizzazioni rappresentino i team che lavorano sui progetti (Asset) che le Organizzazioni conterranno? Oppure le Organizzazioni rappresenterebbero meglio progetti generali che contengono diverse iterazioni dei progetti (Asset) al loro interno?

Se disponi di un'unica Organizzazione che contiene tutte le informazioni rilevanti per un determinato dominio aziendale o team di sviluppo, rappresentarla come un'Organizzazione faciliterà una reportistica più fluida, invece di dover assemblare un report a partire da vari Asset e Organizzazioni. 

Se un particolare progetto software ha molti deployment o versioni distinti, potrebbe valere la pena creare un'unica Organizzazione che copra l'ambito dell'intero progetto e far sì che ogni versione esista come Asset individuale. In alcuni flussi di lavoro, le Organizzazioni possono essere utilizzate anche per separare le fasi del ciclo di vita del software: un'Organizzazione per “In sviluppo”, un'Organizzazione per “In produzione”, ecc.
​
Le Organizzazioni possono essere utilizzate per determinare l'accesso a filiali, aziende acquisite o altre unità aziendali regolamentate ai fini RBAC. Nelle aziende complesse, dove esistono molti progetti unici con regole di accesso diverse, le Organizzazioni sono particolarmente rilevanti.

In definitiva, la decisione su come utilizzare Organizzazioni e Asset dipende da come preferisci riflettere la struttura organizzativa unica della tua azienda e le esigenze del tuo team di sicurezza. 

Di seguito sono riportate alcune strutture di esempio per aiutarti a decidere come designare i tuoi oggetti come Organizzazioni o Asset. 

- **Organizzazione**: Divisione Pagamenti
    - Asset: Payments API - Produzione
    - Asset: Payments API - Staging
    - Asset: Billing Worker

- **Organizzazione**: Prodotto Software A
    - Asset: Web Portal
    - Asset: Mobile Backend

Inoltre, la tabella seguente è una guida illustrativa per capire se qualcosa è meglio rappresentato da un'Organizzazione o da un Asset: 

| Organizzazioni | Asset |
|--------------|--------|
| Unità aziendali | Applicazioni individuali |
| Dipartimenti | Deployment/ambienti |
| Domini di proprietà della sicurezza | Componenti infrastrutturali |
| Famiglie di prodotti | Microservizi specifici |
| Reportistica a livello di portfolio | Target di scansione |
| Clienti | Versioni software specifiche |

Come indicato, la tua struttura potrebbe variare in base alle esigenze di sicurezza specifiche della tua azienda. 

## Accesso alle Organizzazioni

Le Organizzazioni sono accessibili tramite la barra laterale. Il sottomenu offre l'accesso a Tutte le Organizzazioni, oltre all'opzione per creare una nuova Organizzazione.

![image](images/org_ss1.png)

## Vista dell'Organizzazione

La vista di un'Organizzazione contiene una serie di tabelle e grafici per interpretarne lo stato a colpo d'occhio. Questo include: 

- **Descrizione**
- **Commercio** 
    - Se l'Organizzazione è stata determinata come Critica o Chiave
        - Selezionare Critica o Chiave viene utilizzato esclusivamente a scopo di filtraggio 
- **Membri assegnati** (Utenti DefectDojo)
- **Gruppi di utenti assegnati** 
    - I gruppi di utenti che sono stati assegnati all'Organizzazione per il controllo delle autorizzazioni. Ulteriori informazioni sui gruppi di utenti sono disponibili [qui](/admin/user_management/create_user_group/). 
- **Elenco degli Asset all'interno dell'Organizzazione**

## Lavorare con le Organizzazioni 

### Creazione delle Organizzazioni 

Esistono due modi per creare le Organizzazioni: 

- Dall'opzione **Nuova Organizzazione** nel menu laterale
- Dal pulsante **Nuova Organizzazione** nella parte superiore dell'elenco Tutte le Organizzazioni 

### Modifica delle Organizzazioni 

Le Organizzazioni possono essere modificate cliccando su **Modifica Organizzazione** nel menu a ingranaggio in alto a destra della vista dell'Organizzazione. Lo stesso menu è accessibile anche cliccando sul menu kebab ⋮ a sinistra dell'Organizzazione nella vista Tutte le Organizzazioni. 

Tutti i campi modificabili successivamente sono disponibili anche durante la creazione dell'Organizzazione.

### Eliminazione delle Organizzazioni 

L'eliminazione di un'Organizzazione può essere effettuata selezionando **Elimina Organizzazione** dalle impostazioni dell'Organizzazione. 

Poiché le Organizzazioni si trovano al vertice della gerarchia, eliminarle rimuove tutta la cronologia di sicurezza, le relazioni e gli oggetti figli a valle, come: 
- Qualsiasi Asset, Engagement e Test contenuto nell'Organizzazione
- Tutta la cronologia di sicurezza associata, inclusi Riscontri e integrazioni
- Qualsiasi Epic Jira collegata
- Tutte le note e i file caricati associati agli Asset, Engagement e Test all'interno di quell'Organizzazione

L'eliminazione di un'Organizzazione non può essere annullata. Se desideri “dismettere” un'organizzazione senza eliminare i dati sottostanti (ad esempio, per conservare i registri di test software legacy a fini di audit), puoi modificare il nome dell'Organizzazione o aggiungere un Tag per indicare che si trova in uno stato deprecato.

## Organizzazioni vs. Metadati 

Le Organizzazioni sono pensate per rappresentare la proprietà strutturale o i confini di reportistica, piuttosto che classificazioni leggere. Attributi come lo stato di deployment, le etichette interne o gli stati temporanei dei flussi di lavoro potrebbero essere meglio rappresentati tramite tag o metadati piuttosto che tramite Organizzazioni separate.

## Confini dell'Organizzazione 

Le Organizzazioni stabiliscono sia i confini di reportistica sia quelli di accesso all'interno di DefectDojo. Poiché le integrazioni, le autorizzazioni RBAC, la proprietà, le metriche e i modelli di deduplicazione ereditano spesso la struttura delle Organizzazioni, progettare confini chiari fin dall'inizio aiuta a evitare in seguito una proliferazione incontrollata della gerarchia e la frammentazione della reportistica.

### Riscontri e automazione 

Sebbene le integrazioni siano tipicamente configurate su oggetti di livello inferiore come Asset, Engagement o Riscontri, le Organizzazioni definiscono comunque i confini di proprietà, reportistica e accesso all'interno dei quali tali integrazioni operano.

Le autorizzazioni si propagano verso il basso, il che significa che l'accesso a un'Organizzazione garantisce automaticamente l'accesso a tutti gli oggetti all'interno di quell'Organizzazione (ad esempio, Asset, Engagement, Test e Riscontri). 

Il modello RBAC di DefectDojo può essere utilizzato per regolamentare l'accesso degli utenti umani, ma può anche limitare l'accesso dei token API a particolari Organizzazioni.

Per maggiori informazioni sui ruoli utente, consulta il nostro articolo [Introduzione ai tipi di autorizzazione](/admin/user_management/set_user_permissions/#introduction-to-permission-types).

### Proprietà

In quanto oggetti di primo livello, le Organizzazioni implicano anche la proprietà sugli oggetti figli al loro interno. Il tracciamento degli SLA, i flussi di lavoro di correzione, l'instradamento dei ticket e la governance generale procedono in modo più fluido quando le Organizzazioni sono state configurate per riflettere accuratamente le persone responsabili.

### Metriche/Reportistica 

Le dashboard, i riquadri e le viste delle metriche possono essere filtrati per Organizzazione, rendendoli una componente fondamentale del modo in cui i tuoi dati di sicurezza vengono calcolati, visualizzati e infine esportati. 

Ai fini della reportistica, è generalmente più semplice combinare più Organizzazioni in un unico documento piuttosto che suddividere una singola Organizzazione in documenti separati. Pertanto, consigliamo di impostare le Organizzazioni al livello di granularità più adatto ai report del tuo team. Ad esempio, non è necessario rappresentare una grande divisione aziendale come un'Organizzazione se prevedi di produrre report principalmente per i singoli dipartimenti all'interno di quella divisione.

Strutturare efficacemente le tue Organizzazioni in modo che riflettano le tue esigenze di reportistica è fondamentale per valutare accuratamente la tua postura di sicurezza. Per maggiori informazioni sulle Metriche, clicca [qui](/metrics_reports/pro_metrics/pro__overview/).

### Deduplicazione

La deduplicazione in DefectDojo avviene a livello di Asset e non è influenzata dall'Organizzazione principale.
