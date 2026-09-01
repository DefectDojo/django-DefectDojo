---
title: Threat Modeling
description: Genera un modello di minaccia, i percorsi di attacco e i requisiti di
  sicurezza a partire dal design di una funzionalità, prima ancora che il codice esista
draft: false
audience: pro
weight: 4
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Threat Modeling è una funzionalità esclusiva di DefectDojo Pro ed è attualmente in BETA.</span>

**Threat Modeling** trasforma il design di una funzionalità in un modello di minaccia sottoposto a revisione. Fornisci il design — testo incollato, un documento di progettazione e facoltativamente un diagramma architetturale — e DefectDojo produce i componenti e i flussi di dati che descrive, le minacce a loro carico e i requisiti di sicurezza che le mitigano. I requisiti possono poi essere inviati a DefectDojo come riscontri, in modo che il lavoro della fase di design passi attraverso lo stesso meccanismo di triage, SLA, Jira e reportistica di tutto il resto.

Questa è la capacità **pre-code** di Sensei. Mentre [scan-and-fix](/sensei/about_sensei/) lavora su un repository già esistente, il threat modeling lavora sul design, prima ancora che ci sia codice da sottoporre a scansione.

> **🔎 BETA:** Threat Modeling è in sviluppo attivo ed è contrassegnato come **BETA** in tutta l'interfaccia. Il comportamento e le schermate possono cambiare tra una release e l'altra. Durante la fase BETA viene abilitato per singola istanza da DefectDojo — contatta il tuo referente DefectDojo per farlo attivare.

> **📍 Dove trovarlo:** apri **Threat Modeling** dalla navigazione a sinistra, subito sotto Sensei.

## Cosa ti serve

- La funzionalità con licenza **Sensei**. Threat modeling viene distribuito con lo stesso entitlement di scan-and-fix.
- Un ruolo globale di **Maintainer** o **Owner**. Gli utenti privi di questo ruolo non vedono la pagina.
- Un Prodotto a cui allegare il modello di minaccia. Le istanze che usano la denominazione 3.0 vedono i Prodotti chiamati **asset**; questa pagina usa sempre il termine *Prodotto*, e l'interfaccia segue la denominazione impostata sulla tua istanza.

Non viene installato nulla e non viene collegato alcun repository. Threat modeling legge solo il design che fornisci.

## Generare un modello di minaccia

Scegli **New threat model**, seleziona il Prodotto, assegnagli un nome e fornisci il design nel formato che hai a disposizione:

- **Incolla la descrizione** direttamente, oppure
- **Carica un documento di progettazione** — `.md`, `.markdown`, `.txt`, `.text` o `.pdf`. L'estrazione del testo dai PDF è best-effort; se un PDF è composto per lo più da immagini, incolla invece il testo.
- **Facoltativamente aggiungi un diagramma architetturale** — PNG, JPEG, WebP o GIF. Il diagramma viene letto insieme al testo, quindi un componente che compare solo nell'immagine viene comunque rilevato.

Puoi combinarli: un breve riepilogo incollato più un diagramma spesso produce un modello migliore rispetto a ciascuno dei due da solo.

La generazione viene eseguita in background e attraversa quattro fasi, mostrate sull'esecuzione man mano che procede:

1. **Extracting architecture** — componenti, trust boundary, data asset e flussi di dati.
2. **Enumerating threats** — minacce per categoria STRIDE.
3. **Writing security requirements** — requisiti verificabili, ciascuno collegato alle minacce che mitiga.
4. **Assembling results** — il diagramma e i controlli finali di coerenza.

Un'esecuzione richiede in genere diversi minuti. Puoi lasciare la pagina; l'avanzamento e i risultati vengono conservati sull'esecuzione.

## Leggere i risultati

### Architecture

La scheda **Architecture** visualizza quanto estratto come diagramma di flusso dei dati: componenti raggruppati per trust boundary, con i flussi etichettati per protocollo. I flussi che **attraversano un trust boundary** vengono disegnati in modo diverso, perché sono quelli più interessanti. Selezionando un componente vengono mostrate le minacce che lo interessano.

Il modello registra anche ciò che **non** è riuscito a determinare — le assunzioni che ha dovuto fare e i punti che risultavano poco chiari nel design. Leggi prima questi: indicano dove il design stesso è ambiguo, il che è spesso il risultato più utile dell'esercizio.

### Minacce

Ogni minaccia riporta:

- La sua **categoria STRIDE** (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege) e una **gravità**.
- Il **profilo dell'attaccante** — ad esempio un attaccante esterno non autenticato, un insider o una compromissione della supply chain — e il livello di competenza richiesto.
- Un **percorso di attacco** ordinato: i passaggi che un attaccante compirebbe, con i relativi prerequisiti.
- Un **CWE**, dove applicabile, tratto da un elenco fisso anziché inventato.
- I **componenti, i flussi e i data asset** che colpisce.

### Requisiti di sicurezza

Ogni requisito è scritto come un'affermazione verificabile, con un passaggio di **verifica** che descrive come confermarne la validità, una categoria (autenticazione, autorizzazione, validazione dell'input, crittografia e così via) e una priorità. Ogni requisito indica le minacce che mitiga.

La copertura viene contabilizzata esplicitamente: una minaccia è mitigata da almeno un requisito oppure elencata come **coverage gap**. Le lacune vengono mostrate anziché nascoste, in modo che nessuna minaccia venga scartata silenziosamente.

## Evidenza e di cosa fidarsi

Ogni componente, minaccia e requisito riporta l'**evidenza** da cui proviene, ed è etichettata per fonte:

- **Dal testo del design** — una citazione che è stata confrontata, parola per parola, con il testo fornito.
- **Dal diagramma** — letta dall'immagine, quindi non c'è testo da citare.
- **Inferita** — non dichiarata affatto nel design.

Una citazione che non può essere confrontata con il testo fornito viene mantenuta ma **contrassegnata come non verificata**, con la citazione dichiarata mostrata in modo che tu possa valutarla da solo. Gli elementi vengono contrassegnati anziché rimossi, perché una minaccia scartata silenziosamente è un rischio di cui nessuno viene a conoscenza. Gli elementi strutturalmente non validi — una minaccia che fa riferimento a un componente mai estratto — vengono scartati, e il conteggio di ciò che è stato scartato viene registrato sull'esecuzione.

**Considera l'output come una bozza da rivedere, non come un artefatto finito.** Viene generato da un documento di design tramite un modello linguistico; le etichette di evidenza esistono per permetterti di vedere quali parti si basano su ciò che hai scritto e quali sono inferenze.

## Trasformare i requisiti in riscontri

I requisiti diventano attuabili tramite **Push to findings**. Seleziona i requisiti desiderati e DefectDojo crea un Riscontro per ogni requisito, in un Engagement dedicato chiamato **Sensei Threat Modeling** su quel Prodotto, con un Test per ogni versione del modello di minaccia.

Ogni Riscontro riporta:

- L'enunciato del requisito, più la narrazione di ogni minaccia che mitiga — categoria STRIDE, attaccante e il percorso di attacco numerato — in modo che chiunque prenda in carico il ticket abbia il contesto senza dover aprire il modello di minaccia.
- Il passaggio di verifica come mitigazione.
- La gravità e il CWE del requisito.
- Il tag `sensei-threat-model`, un tag `tm-v<version>` e un tag STRIDE.

I Riscontri vengono creati **attivi ma non verificati**: un requisito generato è una proposta che un essere umano deve confermare.

Il push è **idempotente**. Ogni requisito possiede il proprio Riscontro, quindi eseguire di nuovo il push dello stesso modello aggiorna sul posto invece di creare duplicati — e se modifichi un requisito e rifai il push, il Riscontro si aggiorna di conseguenza. Ripetere il push non riscrive chi ha sollevato per primo il Riscontro.

## Versioni e sostituzione

I modelli di minaccia sono **versionati per Prodotto**. Rigenerare da un design aggiornato crea una nuova versione invece di sovrascrivere quella precedente, così mantieni la cronologia di come appariva il design quando è stata presa una decisione.

Quando esegui il push di una versione più recente, i Riscontri della versione precedente che non corrispondono più a un requisito attuale vengono **mitigati** anziché lasciati aperti, in modo che l'Engagement rifletta il design corrente.

## Esportazione

Un modello di minaccia può essere scaricato come **Markdown** per una revisione del design o un ticket, oppure come **JSON** per qualsiasi utilizzo programmatico. Entrambi sono disponibili direttamente dal modello di minaccia.

## Attività di generazione

La scheda **Activity** elenca ogni generazione, il suo stato e la fase raggiunta. Le esecuzioni in corso possono essere **annullate**. Un'esecuzione fallita mostra **il motivo** del fallimento — un problema di configurazione, un input troppo lungo o un errore temporaneo del servizio — e le fasi completate vengono salvate come checkpoint, quindi un nuovo tentativo riprende invece di ripartire da capo.

## Costi

Threat modeling richiama un modello linguistico di grandi dimensioni, e ogni generazione ha un costo. Una generazione effettua circa otto chiamate, e l'utilizzo viene registrato per esecuzione insieme all'altro utilizzo LLM di Sensei, così puoi vedere quanto è costato produrre un modello. Annullare un'esecuzione interrompe ulteriori chiamate al successivo limite di fase.
