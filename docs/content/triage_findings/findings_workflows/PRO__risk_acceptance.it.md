---
title: Accettazioni del rischio
description: Sfruttare le Accettazioni del rischio in DefectDojo Pro
audience: pro
weight: 2
aliases:
- /it/en/working_with_findings/findings_workflows/risk_acceptances/
---

**Accettazioni del rischio** sono uno stato speciale che può essere applicato ai Riscontri utilizzando gli oggetti **Accettazione del rischio completa** oppure il flusso di lavoro **Accettazione del rischio semplice**.  Le Accettazioni del rischio vengono utilizzate per documentare formalmente e rendere operativa la decisione di riconoscere un Riscontro vulnerabile senza rimediarvi immediatamente.

DefectDojo Pro include funzionalità avanzate di Accettazione del rischio per scalare le decisioni di gestione del rischio, tra cui:
- **Accettazioni del rischio cross-prodotto**: una singola Accettazione del rischio può essere applicata su più prodotti, consentendo di raggruppare tutte le istanze dello stesso Riscontro o di Riscontri simili nell'intero portafoglio di Asset in un unico oggetto di Accettazione del rischio.
- **Gestione massiva delle Accettazioni del rischio**: filtra e cerca Riscontri specifici per ID di vulnerabilità e applica l'Accettazione del rischio a tutti i risultati contemporaneamente, indipendentemente dall'Asset a cui appartengono.

### Accesso ai Riscontri con rischio accettato

La barra laterale include una sezione dedicata alle Accettazioni del rischio, che comprende tre sottosezioni nel relativo menu a discesa:
- **Riscontri con rischio accettato**
    - Questa sezione include una tabella di tutti i Riscontri il cui rischio è stato accettato, sia come parte di un oggetto di Accettazione del rischio completa sia tramite il flusso di lavoro di Accettazione del rischio semplice.
- **Tutte le Accettazioni del rischio**
    - Questa sezione include una tabella di tutti gli oggetti di Accettazione del rischio completa, ordinati cronologicamente.
- **Nuova Accettazione del rischio**
    - Facendo clic su questa opzione nella barra laterale si avvia il flusso di lavoro per creare un oggetto di Accettazione del rischio completa.

![Risk acceptance sidebar](images/RA_image1.png)

## Creazione delle Accettazioni del rischio

Quando il rischio di un Riscontro viene accettato, si verifica quanto segue:

- Lo stato del Riscontro non sarà più "Attivo".
- Lo stato del Riscontro verrà cambiato in "Rischio accettato".
- Il Riscontro non verrà più conteggiato nelle Metriche, ma continuerà a comparire all'interno del Test da cui ha avuto origine.

Il rischio di un Riscontro può essere accettato in due modi: aggiungendolo a oggetti di Accettazione del rischio completa, oppure utilizzando il flusso di lavoro di Accettazione del rischio semplice.

### Accettazioni del rischio complete

Un'Accettazione del rischio completa consente agli Utenti di accettare il rischio di più Riscontri raggruppandoli in un unico oggetto, indipendentemente dall'Asset, dall'Engagement o dal Test da cui hanno avuto origine.

Se la politica organizzativa richiede accettazioni del rischio formali e documentate, oppure se gli Utenti desiderano che le accettazioni del rischio scadano automaticamente dopo una certa data, l'Accettazione del rischio completa è la scelta migliore, poiché registra il processo decisionale interno e può fungere da fonte di verità.

Ogni Accettazione del rischio completa aggiunge contesto ulteriore all'Accettazione del rischio, tra cui:
- Il nome dell'oggetto di Accettazione del rischio.
- Il proprietario dell'oggetto di Accettazione del rischio.
- La raccomandazione di sicurezza e la decisione su come gestire il/i Riscontro/i.
- Qualsiasi prova associata alla raccomandazione o alla decisione.
- Dettagli relativi alla raccomandazione o alla decisione.
- L'Utente che accetta il rischio associato alla decisione.
- La data di scadenza.
    - Se lo stato del Riscontro tornerà ad "Attivo" alla scadenza.
    - Se lo SLA verrà riavviato alla scadenza.

La scadenza è una caratteristica esclusiva degli oggetti di Accettazione del rischio completa e consente di riesaminare, al momento opportuno, eventuali Riscontri il cui rischio sia stato accettato. Una volta scaduta un'Accettazione del rischio, i Riscontri interessati torneranno allo stato Attivo.

Se non si specifica una data, verranno utilizzati i giorni di Accettazione del rischio predefinita / Scadenza predefinita dell'Accettazione del rischio impostati nella pagina Impostazioni di sistema.

#### Come completare un'Accettazione del rischio completa

Un oggetto di Accettazione del rischio completa può essere creato in tre modi diversi:
- Utilizzando il pulsante **Nuova Accettazione del rischio** nella barra laterale.
- Utilizzando il pulsante **Aggiungi Accettazione del rischio** su un singolo Riscontro.
- Facendo clic sul pulsante **Azioni di Accettazione del rischio** che compare dopo aver selezionato uno o più Riscontri all'interno di una tabella.

##### Nuova Accettazione del rischio (barra laterale)

Facendo clic su Nuova Accettazione del rischio nella barra laterale si apre una pagina in cui l'Utente può stabilire i dati e i dettagli associati a un nuovo oggetto di Accettazione del rischio completa. La seconda pagina consente all'Utente di filtrare e selezionare i Riscontri da aggiungere a tale oggetto.

##### Aggiungi Accettazione del rischio (singolo Riscontro)

Dopo aver aperto un singolo Riscontro, fai clic sull'icona a forma di ingranaggio nell'angolo in alto a destra della vista e seleziona **Aggiungi Accettazione del rischio**. Da qui sarà possibile aggiungere il Riscontro a un oggetto di Accettazione del rischio completa esistente, oppure crearne uno nuovo.

![Risk Acceptance in Finding Submenu](images/RA_image2.png)

##### Azioni di Accettazione del rischio (tabella)

Dopo aver selezionato uno o più Riscontri all'interno di una tabella, fai clic sul pulsante **Azioni di Accettazione del rischio** che compare in alto e seleziona **Aggiungi a un nuovo oggetto di Accettazione del rischio** oppure **Aggiungi a un oggetto di Accettazione del rischio esistente**, quindi compila i campi richiesti.

I Riscontri possono essere aggiunti a una sola Accettazione del rischio alla volta.  Se il pulsante Azioni di Accettazione del rischio non è cliccabile, è probabile che uno dei Riscontri selezionati sia già stato aggiunto a un oggetto di Accettazione del rischio completa.

![Risk Acceptance Actions button](images/RA_image5.png)

##### Modifica delle Accettazioni del rischio complete

Una volta creato un oggetto di Accettazione del rischio completa, puoi modificarne i dettagli, caricare un file con la prova dell'Accettazione del rischio oppure eliminare completamente l'oggetto facendo clic sull'icona a forma di ingranaggio in alto a destra nella vista dell'oggetto.

I Riscontri possono anche essere aggiunti o rimossi dall'oggetto tramite lo stesso menu. In alternativa, i Riscontri possono essere rimossi dall'oggetto facendo clic sul menu kebab ⋮ accanto a un singolo Riscontro, selezionando **Azioni di aggiornamento massivo** e scegliendo **Rifiuta rischio** dal menu a discesa Stato Accettazione del rischio semplice.

Infine, se aggiungi Riscontri a un oggetto di Accettazione del rischio completa e successivamente elimini tale oggetto, i Riscontri contenuti torneranno automaticamente allo stato "Attivo."

### Accettazioni del rischio semplici

Le Accettazioni del rischio semplici non hanno metadati o data di scadenza associati. Sono più indicate quando è ancora necessario tracciare i Riscontri con rischio accettato ai fini della conformità, ma non c'è alcuna necessità associata di un oggetto per tracciare o modificare lo stato dei Riscontri interessati.

L'Accettazione del rischio semplice non è abilitata per impostazione predefinita, ma può essere attivata nella sezione Campi opzionali delle impostazioni dell'Asset, dopo aver fatto clic sull'icona a forma di ingranaggio in alto a destra nella vista dell'Asset.

![Enabling simple risk acceptance](images/RA_image3.png)

Una volta abilitata, l'Accettazione del rischio semplice può essere eseguita dalla tabella dei Riscontri all'interno della vista di un Test.

#### Come completare un'Accettazione del rischio semplice

Puoi completare il flusso di lavoro di Accettazione del rischio semplice sia dalla tabella Tutti i Riscontri (accessibile dalla barra laterale) sia dalla tabella dei Riscontri all'interno di un test specifico. Il flusso di lavoro è identico nei due casi.

Seleziona i Riscontri di cui vuoi accettare il rischio e fai clic sul pulsante **Azioni di aggiornamento massivo** che compare in alto nella tabella. Da qui, seleziona **Accetta rischio** dal menu a discesa Stato Accettazione del rischio semplice. Poiché i Riscontri sono stati sottoposti ad Accettazione del rischio semplice, non è presente alcun oggetto di Accettazione del rischio completa associato. I Riscontri il cui rischio è stato accettato sono accessibili dal menu **Riscontri con rischio accettato** nella barra laterale.

![Risk Acceptance Actions in Table](images/RA_image4.png)

Al contrario, se vuoi rifiutare il rischio precedentemente accettato per uno o più Riscontri, seleziona **Rifiuta rischio**. Se un Riscontro è stato sottoposto ad Accettazione del rischio semplice, il rischio deve essere rifiutato prima di poterlo aggiungere a un oggetto di Accettazione del rischio completa.

## Autorizzazioni e visibilità delle Accettazioni del rischio

La visibilità dell'Accettazione del rischio è **regolata da un'autorizzazione minima distinta rispetto alla visibilità del Riscontro**.  Un utente che può visualizzare un Riscontro non dispone automaticamente dell'autorizzazione per visualizzare un'Accettazione del rischio che contiene tale Riscontro.

### Ruolo minimo per le azioni di Accettazione del rischio

| Azione | Ruolo minimo sull'Asset (Prodotto) principale |
| --- | --- |
| Visualizzare un'Accettazione del rischio | Writer |
| Aggiungere o modificare un'Accettazione del rischio | Writer |

Per la tabella completa dei ruoli e delle autorizzazioni, che elenca le autorizzazioni sulle Accettazioni del rischio insieme ad altre azioni a livello di Asset, consulta [Action permission charts](/admin/user_management/user_permission_chart/#role-permission-chart).

## Scadenza e ripristino di un'Accettazione del rischio

Un'Accettazione del rischio scaduta viene contrassegnata come **Scaduta** accanto alla relativa data di scadenza nella tabella delle Accettazioni del rischio, in modo da poter individuare a colpo d'occhio quelle che non sopprimono più i rispettivi Riscontri.

Il menu a forma di ingranaggio su un'Accettazione del rischio — nella tabella o nella relativa pagina di dettaglio — offre l'opzione applicabile tra queste:

- **Fai scadere Accettazione del rischio**, su una ancora attiva.  Scade immediatamente anziché attendere la data di scadenza prevista, e i suoi Riscontri vengono riattivati in base alle impostazioni **Riattiva Riscontri scaduti** e **Riavvia SLA scaduto**.
- **Ripristina Accettazione del rischio**, su una già scaduta.  I relativi Riscontri vengono nuovamente accettati e l'Accettazione del rischio scade dopo il numero di giorni indicato nell'impostazione **Giorni predefiniti del modulo di Accettazione del rischio**.

Entrambe le azioni richiedono la stessa autorizzazione necessaria per modificare l'Accettazione del rischio ed entrambe chiedono prima una conferma.  Per ripristinare per una durata specifica anziché quella predefinita, modifica la data di scadenza invece di utilizzare l'azione Ripristina — vedi sotto.

## Quando viene modificata la data di scadenza di un'Accettazione del rischio

La data di scadenza di un'Accettazione del rischio può essere modificata in qualsiasi momento dopo la creazione.  Il comportamento di DefectDojo dipende dal fatto che l'Accettazione del rischio sia attualmente attiva oppure già scaduta.

### Modifica della data su un'Accettazione del rischio attiva

Se un'Accettazione del rischio non è ancora scaduta — la sua data di scadenza è nel futuro, oppure è appena trascorsa ma il job periodico di scadenza non l'ha ancora elaborata — modificare la data è semplice:

- La nuova data viene salvata così com'è.  Se l'utente ha scelto `2027-01-15`, l'Accettazione del rischio memorizza `2027-01-15`.
- I Riscontri collegati restano con il rischio accettato.
- L'oggetto di Accettazione del rischio resta attivo.

### Posticipare la data su un'Accettazione del rischio già scaduta

Se l'Accettazione del rischio è **già scaduta** — ossia il job periodico ne ha elaborato la scadenza, i Riscontri collegati sono stati riportati ad Attivo secondo le impostazioni di scadenza dell'Accettazione del rischio, e l'Accettazione del rischio si trova nello stato scaduto — modificare la data di scadenza portandola a un valore futuro avvia un flusso di lavoro di **ripristino**:

- L'Accettazione del rischio viene ripristinata e non è più nello stato scaduto.
- Ogni Riscontro che era collegato all'Accettazione del rischio e che è attualmente Attivo viene nuovamente accettato (riportato a Rischio accettato / Inattivo).
- Gli stati degli Endpoint su tali Riscontri vengono aggiornati per riflettere la nuova accettazione.
- Un commento viene pubblicato su eventuali issue Jira collegate, a registrazione del ripristino.

La data che inserisci è la data che viene salvata.  L'impostazione di sistema **Giorni predefiniti del modulo di Accettazione del rischio** (predefinito: 180) viene utilizzata solo quando non è stata richiesta una data specifica — ad esempio quando usi l'azione **Ripristina**, che ripristina l'Accettazione del rischio senza modificarne la data di scadenza, impostandola quindi a oggi + N giorni.

### Spostare la data indietro o a una data ancora nel passato

Spostare la data di scadenza a una data anteriore ma comunque futura non comporta alcun comportamento particolare — l'Accettazione del rischio resta attiva e la nuova data viene salvata.

Spostare la data a una data nel passato non fa scadere immediatamente l'Accettazione del rischio dal modulo di modifica; il successivo job periodico di scadenza la rileverà e applicherà il comportamento di scadenza standard (Riscontri riattivati in base all'impostazione **Riattiva Riscontri scaduti** dell'Accettazione del rischio, con riavvio dello SLA se è impostata l'opzione **Riavvia SLA scaduto**).

### Cosa espone l'API

I consumatori dell'API possono osservare lo stato di scadenza sull'oggetto Accettazione del rischio tramite i campi `expiration_date`, `expiration_date_handled` ed `expiration_date_warned`:

- `expiration_date` è la data configurata.
- `expiration_date_handled` è `null` mentre l'Accettazione del rischio è attiva, e viene impostato su un timestamp quando il job periodico ne ha elaborato la scadenza.  Un'Accettazione del rischio è "scaduta" esattamente quando `expiration_date_handled` non è nullo.
- `expiration_date_warned` viene impostato quando il sistema ha inviato la notifica di avviso di scadenza.

Quando avviene un ripristino, sia `expiration_date_handled` sia `expiration_date_warned` vengono riportati a `null`, ed `expiration_date` conserva la data inviata — oppure oggi + N giorni, quando il ripristino è stato avviato senza una nuova data.  Gli strumenti che monitorano le Accettazioni del rischio per rilevare cambi di stato possono utilizzare il campo `expiration_date_handled` come indicatore canonico di "questa Accettazione del rischio è attualmente scaduta?".

La scadenza e il ripristino sono disponibili anche direttamente, senza dover intervenire modificando `expiration_date`:

- `POST /api/v2/risk_acceptance/{id}/expire/` la fa scadere immediatamente.  Restituisce `400` se è già scaduta.
- `POST /api/v2/risk_acceptance/{id}/reinstate/` ripristina una scaduta, accettando nuovamente i Riscontri che copre.  Restituisce `400` se non è scaduta.  Invia `expiration_date` per scegliere per quanto tempo; omettilo per usare oggi + N giorni.

Entrambe accettano un `reason` opzionale, che viene registrato come nota sull'Accettazione del rischio insieme a chi ha eseguito l'azione.  Entrambe richiedono la stessa autorizzazione necessaria per modificare l'Accettazione del rischio.

## Best practice per le Accettazioni del rischio

Sebbene sia possibile influire sui Riscontri contenuti in oggetti di Accettazione del rischio completa utilizzando i flussi di lavoro di Accettazione del rischio semplice (e viceversa), in generale è preferibile adottare uno solo dei due processi in modo esclusivo, anziché tenerli entrambi abilitati contemporaneamente.

Ad esempio, se gli oggetti di Accettazione del rischio completa sono l'approccio predefinito, quando il rischio di un Riscontro viene accettato tramite Accettazione del rischio semplice, ciò può generare confusione se non esiste un oggetto associato che contenga il Riscontro interessato. Allo stesso modo, se i Riscontri vengono normalmente sottoposti ad Accettazione del rischio semplice, aggiungere alcuni Riscontri a un oggetto di Accettazione del rischio completa, quando la maggior parte degli altri Riscontri non ha oggetti di questo tipo, può creare una confusione simile.
