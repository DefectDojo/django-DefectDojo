---
title: Accettazioni del rischio
description: Utilizzo delle Accettazioni del rischio in DefectDojo OS
audience: opensource
weight: 2
---

**Le Accettazioni del rischio** sono uno stato speciale che può essere applicato ai Riscontri per documentare formalmente e rendere operativa la decisione di prenderne atto senza porvi immediatamente rimedio.

A differenza di DefectDojo Pro, in DefectDojo OS le Accettazioni del rischio non sono oggetti indipendenti. Sono invece collegate esclusivamente agli Engagement. Di conseguenza, possono contenere solo Riscontri appartenenti all'Engagement in cui si trovano. Se 3 istanze dello stesso Riscontro compaiono in un Test in 3 Engagement diversi, saranno necessarie 3 diverse Accettazioni del rischio per accettare completamente quei Riscontri.

### Accesso alle Accettazioni del rischio

Le Accettazioni del rischio includono i Riscontri specifici dei Test all'interno di ciascun Engagement. Di conseguenza, è possibile accedervi dall'Engagement che contiene il Test da cui provengono tali Riscontri.

![immagine](images/OS_RA_image1.png)

Un elenco completo dei singoli Riscontri con rischio accettato è visibile nel sottomenu **Riscontri con rischio accettato** della sezione **Riscontri** nella barra laterale.

![immagine](images/OS_RA_image2.png)

## Creazione delle Accettazioni del rischio

Quando a un Riscontro viene applicato il Rischio accettato, si verifica quanto segue:
- Lo stato del Riscontro non sarà più "Attivo", ma resterà interrogabile, includibile nei report e verificabile.
- Lo stato del Riscontro verrà modificato in "Rischio accettato."
- Il Riscontro non verrà più conteggiato nelle metriche, ma continuerà a comparire nel Test da cui ha avuto origine.

I Riscontri possono ricevere il Rischio accettato in due modi: possono essere aggiunti manualmente a un'**Accettazione del rischio completa**, oppure tramite il flusso di lavoro **Accettazione del rischio semplice**.

### Accettazioni del rischio complete

Un'Accettazione del rischio completa consente agli Utenti di accettare il rischio di più Riscontri all'interno di un Engagement e di raggrupparli in un'unica unità. Se le policy organizzative richiedono accettazioni del rischio formali e documentate, oppure se gli Utenti desiderano attivare determinate azioni allo scadere di un'Accettazione del rischio, le Accettazioni del rischio complete sono la scelta migliore, poiché registrano il processo decisionale interno e possono fungere da fonte di riferimento.

Ogni Accettazione del rischio completa aggiunge un contesto ulteriore, ad esempio:
- Il nome dell'Accettazione del rischio.
- Il proprietario dell'Accettazione del rischio.
- La raccomandazione di sicurezza e la decisione su come gestire il/i Riscontro/i.
- Eventuali prove associate alla raccomandazione o alla decisione.
- Dettagli relativi alla raccomandazione o alla decisione.
- L'Utente che accetta il rischio associato alla decisione.
- La data di scadenza.
    - Se lo stato del Riscontro tornerà ad "Attivo" alla scadenza.
    - Se lo SLA verrà riavviato alla scadenza.

La scadenza è una caratteristica esclusiva delle Accettazioni del rischio complete e consente di riesaminare, al momento opportuno, i Riscontri a cui è stato applicato il Rischio accettato. Alla scadenza di un'Accettazione del rischio completa, i Riscontri torneranno allo stato Attivo. Se non si specifica una data, verrà utilizzata la data configurata in **Default Risk Acceptance** / **Default Risk Acceptance Expiration** nella pagina delle Impostazioni di sistema.

È importante notare che, poiché le Accettazioni del rischio complete sono limitate ai singoli Engagement, non esiste un'unica sezione in cui visualizzarle tutte. Possono essere visualizzate solo all'interno del rispettivo Engagement che include i Riscontri contenuti nell'Accettazione del rischio completa.

#### Come creare un'Accettazione del rischio completa

Per creare un'Accettazione del rischio completa, accedere alla visualizzazione dell'Engagement e fare clic sul simbolo **+** nel riquadro Accettazione del rischio.

![immagine](images/OS_RA_image3.png)

Da qui, compilare i dettagli dell'Accettazione del rischio completa e selezionare i Riscontri da includere. **Riscontri accettati** contiene un elenco a discesa di tutti i Riscontri disponibili da aggiungere all'Accettazione del rischio. L'elenco dei Riscontri all'interno dell'Engagement verrà visualizzato in ordine decrescente di gravità (i Riscontri Critici in cima, quelli Bassi in fondo). Se a un Riscontro è già stato applicato il Rischio accettato, non comparirà nell'elenco a discesa.

Una volta completata, l'Accettazione del rischio completa comparirà nel riquadro Accettazione del rischio nella visualizzazione dell'Engagement.

Un'Accettazione del rischio può anche essere creata facendo clic sul pulsante **Aggiungi Accettazione del rischio** nel menu kebab ⋮ di un singolo Riscontro.

![immagine](images/OS_RA_image7.png)

#### Interazione con le Accettazioni del rischio complete

Una volta creata, un'Accettazione del rischio completa può essere aperta per visualizzare i Riscontri che vi sono stati aggiunti, oltre a tutti i dettagli inseriti al momento della creazione (ad esempio la data, il proprietario, la decisione, la scadenza, ecc.).

Per rimuovere un Riscontro da un'Accettazione del rischio completa, fare clic sul pulsante **Rimuovi** nella tabella dei Riscontri accettati.

![immagine](images/OS_RA_image8.png)

La visualizzazione dell'Accettazione del rischio completa include anche, in fondo, una tabella con tutti gli altri Riscontri provenienti dai Test di quell'Engagement. Da qui è possibile selezionare ulteriori Riscontri e aggiungerli a quell'Accettazione del rischio completa.

Inoltre, è disponibile una funzione Note che consente agli Utenti di aggiungere contesto ulteriore all'Accettazione del rischio completa. Tutte le note pubbliche compariranno in qualsiasi Report generato per l'Accettazione del rischio completa. Le note impostate come **Private** sono visibili solo al loro autore e ai superuser e vengono escluse dai report.

È importante notare che, se un'Accettazione del rischio completa viene eliminata interamente, lo stato dei Riscontri in essa contenuti verrà automaticamente riportato ad "Attivo."

### Accettazioni del rischio semplici

Mentre l'Accettazione del rischio completa è abilitata per impostazione predefinita, l'Accettazione del rischio semplice deve essere abilitata manualmente, sia al momento della creazione di un Asset sia nelle impostazioni dell'Asset.

![immagine](images/OS_RA_image4.png)

Un'Accettazione del rischio semplice può essere eseguita in uno dei due modi seguenti:
1. All'interno della visualizzazione di un Test, tramite il menu Modifiche in blocco che compare dopo aver selezionato uno o più Riscontri nella tabella dei Riscontri.

![immagine](images/OS_RA_image5.png)

2. Facendo clic su **Accetta rischio** nel menu kebab ⋮ di un singolo Riscontro.

![immagine](images/OS_RA_image6.png)

Una volta applicata l'Accettazione del rischio semplice a un Riscontro, questo continuerà a comparire nella tabella dei Riscontri del Test, ma il suo stato verrà modificato in **Inattivo, Rischio accettato.** Un elenco completo dei singoli Riscontri con rischio accettato è visibile nel sottomenu **Riscontri con rischio accettato** della sezione **Riscontri** nella barra laterale.

Se si applica l'Accettazione del rischio semplice a un Riscontro e in seguito si desidera aggiungerlo a un'Accettazione del rischio completa, il rischio deve prima essere annullato prima di poterlo aggiungere a un'Accettazione del rischio completa.

## Quando la data di scadenza di un'Accettazione del rischio viene modificata

La data di scadenza di un'Accettazione del rischio completa può essere modificata in qualsiasi momento dopo la creazione. Il comportamento di DefectDojo dipende dal fatto che l'Accettazione del rischio sia attualmente attiva o sia già scaduta.

### Modifica della data su un'Accettazione del rischio attiva

Se un'Accettazione del rischio non è ancora scaduta — la sua data di scadenza è nel futuro, oppure è appena trascorsa ma il job periodico di scadenza non l'ha ancora elaborata — modificare la data è un'operazione semplice:

- La nuova data viene salvata così com'è.
- I Riscontri collegati restano con il Rischio accettato.
- L'oggetto Accettazione del rischio resta attivo.

### Spostare in avanti la data su un'Accettazione del rischio già scaduta

Se l'Accettazione del rischio è **già scaduta** — cioè il job periodico di scadenza ne ha elaborato la scadenza e i Riscontri collegati sono stati riportati ad Attivo — modificare la data di scadenza impostandola a un valore futuro attiva un flusso di lavoro di **ripristino**:

- L'Accettazione del rischio viene ripristinata e non è più nello stato di scaduta.
- Ogni Riscontro collegato all'Accettazione del rischio che è attualmente Attivo viene nuovamente accettato (riportato a Rischio accettato / Inattivo).
- Un commento viene pubblicato su eventuali issue Jira collegate per registrare il ripristino.

La data inserita è la data che viene salvata.  L'impostazione di sistema **Risk Acceptance Form Default Days** (predefinita: 180) viene utilizzata solo quando non è stata richiesta una data specifica — ad esempio quando si utilizza l'azione **Reinstate**, che ripristina l'Accettazione del rischio senza modificarne la data di scadenza, impostandola quindi a oggi + N giorni.

### Spostare la data indietro o a una data ancora nel passato

Spostare la data di scadenza a una data anteriore ma comunque futura non comporta alcun comportamento particolare — l'Accettazione del rischio resta attiva e la nuova data viene salvata.

Spostare la data a una data nel passato non fa scadere immediatamente l'Accettazione del rischio dal modulo di modifica; sarà il successivo job periodico di scadenza a rilevarla e ad applicare il comportamento di scadenza standard.  Questo vale anche per un'Accettazione del rischio **già scaduta**: una data nel passato resta comunque la data scelta, quindi viene salvata così com'è e la successiva esecuzione del job di scadenza farà scadere di nuovo l'Accettazione del rischio.

### Cosa espone l'API

I consumer dell'API possono osservare lo stato di scadenza dell'oggetto Accettazione del rischio tramite i campi `expiration_date`, `expiration_date_handled` e `expiration_date_warned`.  Un'Accettazione del rischio è "scaduta" esattamente quando `expiration_date_handled` non è nullo.  Quando avviene un ripristino, sia `expiration_date_handled` sia `expiration_date_warned` vengono riportati a `null`, e `expiration_date` contiene la data inviata — oppure oggi + N giorni se non è stata richiesta alcuna data.

La scadenza e il ripristino sono disponibili anche direttamente, quindi non è necessario gestirli modificando `expiration_date`:

- `POST /api/v2/risk_acceptance/{id}/expire/` la fa scadere immediatamente.  Restituisce `400` se è già scaduta.
- `POST /api/v2/risk_acceptance/{id}/reinstate/` ripristina un'Accettazione del rischio scaduta, riaccettando i Riscontri che copre.  Restituisce `400` se non è scaduta.  Inviare `expiration_date` per scegliere per quanto tempo; ometterlo per usare oggi + N giorni.

Entrambe accettano un campo `reason` opzionale, che viene registrato come nota sull'Accettazione del rischio insieme a chi ha eseguito l'azione.  Entrambe richiedono lo stesso permesso necessario per modificare l'Accettazione del rischio.

## Best practice per le Accettazioni del rischio

Come prassi standard, è generalmente preferibile utilizzare esclusivamente le Accettazioni del rischio complete oppure quelle semplici, anziché ricorrere a entrambe.

Ad esempio, se l'approccio predefinito prevede le Accettazioni del rischio complete, applicare l'Accettazione del rischio semplice a un Riscontro può generare confusione qualora non esista un'Accettazione del rischio completa associata che contenga il Riscontro interessato. Allo stesso modo, se i Riscontri ricevono di norma l'Accettazione del rischio semplice, può creare confusione aggiungere alcuni Riscontri a un'Accettazione del rischio completa quando la maggior parte degli altri Riscontri non dispone di tali oggetti.
