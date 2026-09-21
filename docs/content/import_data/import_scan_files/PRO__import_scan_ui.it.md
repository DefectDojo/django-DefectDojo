---
title: Modulo Aggiungi riscontri
description: ''
weight: 1
audience: pro
aliases:
- /it/en/connecting_your_tools/import_scan_files/import_scan_ui
---

Se disponi di una nuova istanza di DefectDojo, il modulo di importazione della scansione (Import Scan Form) è un logico primo passo per imparare a conoscere il software e configurare il tuo ambiente. Da questo modulo puoi caricare un file di scansione da uno strumento supportato, che creerà dei Riscontri per rappresentare quelle vulnerabilità. Durante la compilazione del modulo, puoi decidere se:

* Archiviare questi Riscontri in un Tipo di Prodotto / Prodotto / Engagement esistente **oppure**
* Creare un nuovo Tipo di Prodotto / Prodotto / Engagement per archiviare questi Riscontri

È facile riorganizzare la gerarchia dei Prodotti in DefectDojo, quindi va bene se non sei ancora sicuro di come impostare le cose.

Per ora, è utile sapere che gli **Engagement** possono archiviare dati provenienti da più strumenti, il che può essere utile se stai eseguendo strumenti diversi contemporaneamente come parte di un unico sforzo di test.

## Accesso al modulo di importazione della scansione (Pro UI)

Il modulo Import Scan può essere raggiunto da più punti:

1. Tramite l'opzione di menu **Import > Add Findings** nella barra laterale
2. Dal menu **'⋮' (tre puntini orizzontali)** di un **Prodotto**, in una **tabella dei Prodotti**
3. Dal **Menu ⚙️ Ingranaggio** in una **pagina Prodotto**

## Completamento del modulo di importazione della scansione

Il modulo Import Scan creerà un nuovo Test annidato all'interno di un Engagement, che conterrà un Riscontro univoco per ogni vulnerabilità presente nel tuo file di scansione.

Il Test verrà creato con un nome che corrisponde al tipo di scansione: ad esempio, una scansione Tenable verrà denominata 'Tenable Scan'.

### Opzioni del modulo

* **File di scansione:** facendo clic sul pulsante Scegli, puoi selezionare un file dal tuo computer da caricare.
* **Data di scansione (opzionale):** se vuoi selezionare un'unica data di scansione da applicare a tutti i Riscontri risultanti da questa importazione, puoi selezionare la data in questo campo.
Se non selezioni una data di scansione, i Riscontri creati da questo report utilizzeranno la data specificata dallo strumento. Gli SLA di ciascun Riscontro verranno calcolati in base alla loro data.
* **Tipo di scansione:** seleziona lo strumento utilizzato per creare questi dati.
* **Nome di Tipo di Prodotto / Prodotto / Engagement:** seleziona il Tipo di Prodotto, il Prodotto e il nome dell'Engagement sotto cui vuoi creare un nuovo Test. Puoi anche creare un nuovo Tipo di Prodotto, Prodotto e/o Engagement in questo momento, se lo desideri, inserendo i nomi degli oggetti che vuoi creare.
* **Ambiente:** seleziona un Ambiente corrispondente ai dati che stai caricando.
* **Tag:** se vuoi utilizzare i tag per organizzare ulteriormente i dati del Test, puoi aggiungere Tag tramite questo modulo. Digita il nome del tag che vuoi creare e premi Invio sulla tastiera per aggiungerlo all'elenco dei tag.
* **Elabora i Riscontri in modo asincrono**: questo campo è abilitato per impostazione predefinita, ma può essere disabilitato se lo desideri. Vedi la spiegazione di seguito.

### Elaborazione asincrona dei Riscontri

Quando questo campo è abilitato, DefectDojo utilizzerà un processo in background per popolare il tuo file di Test con i Riscontri. Questo ti permette di continuare a lavorare con DefectDojo mentre i Riscontri vengono creati a partire dal tuo file di scansione.

Quando questo campo è disabilitato, DefectDojo attenderà che tutti i Riscontri siano stati creati con successo prima di permetterti di procedere alla schermata successiva. Questo potrebbe richiedere un tempo significativo a seconda delle dimensioni del file.

Questa opzione è particolarmente rilevante quando si utilizza l'API per importare dati. Se carichi dati con l'elaborazione asincrona dei Riscontri **disattivata**, DefectDojo non restituirà una risposta di successo finché tutti i Riscontri non saranno stati creati correttamente.

### Campi opzionali

Per aprire i Campi opzionali, fai clic sul pulsante etichettato **"Optional Fields +"** sopra il pulsante **Submit**

![image](images/import_scan_ui.png)

#### Descrizioni dei campi opzionali
* **Gravità minima**: se vuoi creare Riscontri solo per un determinato livello di Gravità e superiore, puoi selezionare qui il livello di Gravità minimo. Tutte le vulnerabilità con una gravità inferiore a questo valore verranno ignorate.
* **Attivo**: se vuoi impostare tutti i Riscontri in arrivo su Attivo o Inattivo, puoi specificarlo qui. In caso contrario, DefectDojo utilizzerà i dati sulla vulnerabilità dello strumento per determinare se il Riscontro è Attivo o Inattivo. Questa opzione è rilevante se hai bisogno che il tuo team esegua manualmente il triage e verifichi i Riscontri di un determinato strumento.
* **Verificato**: come per Attivo, puoi impostare il nuovo insieme di Riscontri su Verificato o Non verificato per impostazione predefinita. Questo dipende dalle preferenze del tuo workflow. Ad esempio, se il tuo team preferisce presumere che i Riscontri siano verificati salvo prova contraria, puoi impostare questo campo su True.
* **Version, Branch Tag, Commit Hash, Build ID, Service** possono tutti essere specificati se vuoi includere questi dettagli nel Test.
* **Source Code Management URI** può essere specificato anch'esso. Questa opzione del modulo deve essere un URI valido.
* **Group By:** se vuoi creare Gruppi di Riscontri a partire da questo file, puoi specificare qui il metodo di raggruppamento.

### Chiusura dei vecchi Riscontri

Durante l'importazione di una scansione, puoi chiudere automaticamente i Riscontri di scansioni precedenti che non sono più presenti nel nuovo report. Abilita questa opzione selezionando la casella **Close Old Findings** nell'interfaccia utente oppure impostando `close_old_findings: true` nell'API.

#### Ambito: Engagement vs. Prodotto

Per impostazione predefinita, `close_old_findings` chiude i Riscontri dello stesso tipo di scansione all'interno dello **stesso Engagement**. DefectDojo Pro aggiunge una seconda opzione — **Close Old Findings Within This Product** — che estende l'ambito a tutti i Riscontri dello stesso tipo di scansione nell'**intero Prodotto**, indipendentemente dall'Engagement a cui appartengono.

| Option | UI checkbox | API parameter | Scope |
|---|---|---|---|
| Chiusura vecchi riscontri (ambito Engagement) | **Close Old Findings** | `close_old_findings: true` | Stesso Engagement |
| Chiusura vecchi riscontri (ambito Prodotto) | **Close Old Findings Within This Product** | `close_old_findings_product_scope: true` | Intero Prodotto |

`close_old_findings_product_scope` richiede che anche `close_old_findings` sia abilitato. Impostare `close_old_findings_product_scope` senza `close_old_findings` non ha alcun effetto.

> **Nota:** `close_old_findings_product_scope` si applica solo all'endpoint di Import (`/import-scan`). Non ha alcun effetto sull'endpoint di Reimport (`/reimport-scan`), dove l'ambito è sempre limitato al Test corrente.

Viene rispettato anche il campo `service`: solo i Riscontri con un valore `service` identico (o nessun valore `service`, se non ne è stato specificato uno al momento dell'importazione) saranno presi in considerazione per la chiusura.

### Scanner senza triage: campo Do Not Reactivate

Alcuni scanner potrebbero non includere informazioni di triage nei loro report (ad es. tfsec). Si limitano a scansionare codice o dipendenze, segnalare i problemi e restituire tutto, indipendentemente dal fatto che una vulnerabilità sia già stata sottoposta a triage o meno.

Per gestire questo caso, DefectDojo include anche una casella "Do not reactivate" durante il caricamento dei report (anche nell'API di reimport), in modo da poter usare DefectDojo come fonte di verità per il triage, invece di riattivare i Riscontri già sottoposti a triage a ogni import/reimport.

### Utilizzo del campo Data di completamento della scansione (API: `scan_date`)

DefectDojo offre un'ampia gamma di report di scanner supportati, ma non tutti contengono le informazioni più importanti per un utente. Il campo `scan_date` è una funzionalità intelligente e flessibile che permette agli utenti di impostare la data di completamento di un determinato report di scansione, e di propagarla a tutti i riscontri importati. Questo campo **non** è obbligatorio, ma il valore predefinito per questo campo è la data di importazione (nel momento in cui la richiesta viene elaborata e viene restituita una risposta di successo).

Ecco i seguenti casi d'uso per questo campo:

1. Il report **non** imposta la data, e `scan_date` **non** è impostato all'importazione
    - La data del Riscontro sarà il valore predefinito di `scan_date`
2. Il report **imposta** la data, e `scan_date` **non** è impostato all'importazione
    - La data del Riscontro sarà quella impostata dal report
3. Il report **non** imposta la data, e `scan_date` **è impostato** all'importazione
    - La data del Riscontro sarà quella impostata dall'utente per `scan_date`
4. Il report **imposta** la data, e `scan_date` **è impostato** all'importazione
    - La data del Riscontro sarà quella impostata dall'utente per `scan_date`
