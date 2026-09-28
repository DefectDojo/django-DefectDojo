---
title: Gestione dei record
description: Indirizza il flusso di dati dal tuo strumento a DefectDojo
aliases:
- /it/import_data/pro/connectors/manage_records/
- /it/en/connecting_your_tools/connectors/manage_records
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: i connettori Upstream sono una funzionalità disponibile solo in DefectDojo Pro.</span>

Una volta eseguita la prima operazione di Rilevamento, dovresti vedere un elenco di record Mappati o Non mappati nella pagina **Manage Records and Operations**.

## Cos'è un record?

Un record è una connessione tra un **Prodotto** di DefectDojo e un **Prodotto Equivalente del Fornitore**. Puoi usare l'elenco dei record per controllare il flusso di dati tra il tuo strumento e DefectDojo.

I record vengono creati e aggiornati durante l'operazione di **[Rilevamento](../manage_operations/#discover-operations)**, che DefectDojo esegue quotidianamente per cercare nuovi Prodotti Equivalenti del Fornitore.

![image](images/manage_records.png)

I record hanno vari attributi, tra cui:

* Lo **Stato** del record
* Il **Prodotto** verso cui il record importa i dati
* Quando il record è stato **rilevato per la prima e per l'ultima volta** (dal processo di **Rilevamento**)
* Quando la mappatura del record è stata **finalizzata** da un utente
* Un link al **Prodotto** DefectDojo

## Come vengono mappati i record

A ogni record deve essere assegnata una mappatura. La mappatura indica a DefectDojo dove archiviare i dati di scansione provenienti dallo strumento. Un record mappato assegna il Prodotto Equivalente del Fornitore a un Prodotto DefectDojo e indica al connettore di iniziare a importare i dati di scansione in quella posizione (come Engagement e Test).

Puoi assegnare le mappature manualmente, oppure lasciare che DefectDojo le assegni automaticamente.

### Mappatura automatica

Se hai attivato la **Mappatura automatica**, i nuovi record verranno mappati automaticamente ai prodotti. Ogni volta che DefectDojo **rileva** un nuovo record, viene creato automaticamente un Prodotto DefectDojo corrispondente per ciascun record. Quel record verrà archiviato tra i **Record mappati** per indicare che è pronto per importare dati in DefectDojo.

Se non hai attivato la Mappatura automatica, puoi decidere tu dove far confluire i dati. Ogni volta che il connettore trova un nuovo Prodotto Equivalente del Fornitore (tramite il **Rilevamento**), aggiungerà un nuovo record al tuo elenco di **Record non mappati**, e potrai quindi assegnare manualmente quel record a un Prodotto nuovo o esistente in DefectDojo.

#### Esempio di flusso di lavoro per la mappatura

David ha appena finito di configurare un connettore per il suo strumento BurpSuite ed esegue un'operazione di Rilevamento. David ha configurato Burp per eseguire la scansione di 4 diversi 'Site', e DefectDojo crea un nuovo record per ciascuno di questi Site.

* Se David decide di usare la Mappatura automatica, DefectDojo creerà un nuovo Prodotto per ciascun Site. Da quel momento in poi, quando DefectDojo esegue un'operazione di Sincronizzazione, il connettore importerà i dati di scansione direttamente dal Site al Prodotto (tramite la mappatura del record)  
​
* Se David lascia disattivata la Mappatura automatica, DefectDojo rileverà comunque quei 4 Site e creerà i record, ma non importerà alcun dato finché David non creerà lui stesso le mappature.  
​
* David può sempre modificare in seguito la configurazione di queste mappature. Magari vuole consolidare l'output di più Site Burp diversi in un unico Prodotto. Oppure vuole avere un Prodotto che registri i dati di scansione di più strumenti diversi, incluso Burp. Per David è semplice cambiare dove vengono archiviati i dati di scansione di Burp in DefectDojo modificando la mappatura di questi record.

## Come i record interagiscono con i prodotti

Una volta che un record è mappato, DefectDojo sarà pronto a importare le scansioni del tuo strumento tramite un'operazione di Sincronizzazione. I connettori possono funzionare insieme ad altri processi di importazione di DefectDojo o ai test interattivi.

* Le mappature dei record sono progettate per essere non invasive. Se mappi un Prodotto a un record che contiene Engagement o Riscontri già esistenti, tali Engagement e Riscontri non verranno alterati o sovrascritti dal processo di sincronizzazione dei dati.  
​
* Tutti i dati creati tramite un connettore verranno archiviati in un unico Engagement chiamato **Global Connectors**. Quell'Engagement creerà un Test separato per ciascun connettore mappato al Prodotto.

![image](images/manage_records_2.jpg)

Questo rende possibile inviare dati di scansione da più connettori allo stesso Prodotto. Tutti i dati verranno archiviati nello stesso Engagement, ma ciascun connettore memorizzerà i dati in un Test separato.

Per saperne di più su Prodotti, Engagement e Test, consulta la nostra [Panoramica della gerarchia dei prodotti](/asset_modelling/os_hierarchy/product_hierarchy/).

## Glossario degli stati dei record

Ogni record ha uno stato associato che comunica come sta funzionando il record.

Per accedere all'elenco completo dei record di un connettore, apri il connettore da **Connect > Upstream**: la pagina è intitolata **All <Connector> Records**. Nonostante il nome, elenca tutti i record appartenenti a **quel singolo connettore**, non tutti i record presenti nell'istanza.

Quell'elenco può essere **filtrato per stato** dalla colonna **Stato**, ed è possibile selezionare più di uno stato alla volta. Questo è il modo più rapido per rispondere alle domande che emergono più spesso su una grande flotta di connettori — *cosa è in attesa di essere mappato?* (**Nuovo**) e *cosa ha smesso di inviare dati?* (**Mancante** o **Errore**) — senza dover leggere ogni singolo record.

Non tutti gli stati si applicano a ogni connettore. **Obsoleto** viene impostato dalla pipeline di importazione dei riscontri, quindi si verifica solo sui connettori che importano riscontri; gli **Asset Connector** non lo assumono mai, e non viene proposto come opzione di filtro per loro.

### Nuovo

Un record Nuovo è un record non mappato che DefectDojo ha rilevato. Può essere mappato a un Prodotto oppure ignorato. Per mappare un nuovo record a un Prodotto, consulta la nostra guida su [Modifica dei record]().

### Buono

'Buono' indica che un record è mappato e funziona correttamente. Le successive operazioni di Rilevamento verificano se il Prodotto Equivalente del Fornitore sottostante esiste ancora, per garantire che l'operazione di Sincronizzazione venga eseguita correttamente.

### Ignorato

I record 'Ignorati' sono stati rilevati correttamente, ma un utente di DefectDojo ha deciso di non mappare i dati a un Prodotto.

## Stati di avviso: obsoleto o mancante

Se la connessione tra lo strumento e DefectDojo cambia, lo stato di un record cambierà per avvisarti.

### Obsoleto

Una mappatura passa allo stato 'Obsoleto' quando un Prodotto, Engagement o Test correlato è stato eliminato da DefectDojo. La mappatura esiste ancora, ma non c'è più un punto in DefectDojo verso cui importare i dati dello strumento.

I record obsoleti possono essere rimappati a un Prodotto esistente, oppure ignorati se i dati di scansione non sono più rilevanti.

### Mancante

Se un record è stato mappato, ma i dati di origine (o il Prodotto Equivalente del Fornitore) non vengono rilevati da DefectDojo, il record verrà etichettato come **Mancante**.

I connettori DefectDojo si adattano a cambi di nome, cambi di directory e altri spostamenti di dati, quindi è possibile che il Prodotto Equivalente del Fornitore correlato sia stato eliminato dallo strumento che stai utilizzando.

Se avevi intenzione di rimuovere il Prodotto Equivalente del Fornitore dal tuo strumento, puoi eliminare un record Mancante. In caso contrario, dovrai risolvere il problema all'interno dello strumento affinché i dati di origine possano essere rilevati correttamente.

### Errore

**Errore** indica che DefectDojo non è riuscito a elaborare il record. È disponibile per ogni tipo di connettore e può essere selezionato nel filtro **Stato** insieme agli stati precedenti, il che lo rende il modo più rapido per verificare se qualcosa in un connettore richiede attenzione dopo un'esecuzione.

## Modifica dei record: rimappa, ignora o elimina

I record possono essere modificati, ignorati o eliminati dalla pagina **Gestione dei record e delle operazioni**.

Sebbene i record mappati e non mappati si trovino in tabelle separate, possono comunque essere modificati allo stesso modo.

Dalla tabella dei record, fai clic sulla freccia blu ▼ accanto alla colonna Stato di un determinato record. Da lì potrai selezionare **Modifica record** oppure **Elimina record**.

![image](images/edit_ignore_delete_records.png)

### Modificare la mappatura di un record

Facendo clic su **Modifica record** si aprirà una finestra che ti permette di cambiare il prodotto di destinazione in DefectDojo. Puoi selezionare un Prodotto esistente dal menu a tendina, oppure digitare il nome di un nuovo Prodotto che desideri creare.

![image](images/edit_ignore_delete_records_2.png)

I dati di scansione associati a un record possono essere indirizzati verso un Prodotto diverso modificando la mappatura.

Seleziona, oppure digita il nome di un nuovo Prodotto nel menu a tendina a destra.

#### Modificare lo stato di un record

Anche lo stato di un record può essere modificato da questo menu. I record possono essere cambiati da Buono a Ignorato (o viceversa) scegliendo un'opzione dall'elenco a discesa **Stato**.

### Ignorare un record

Se desideri 'disattivare' uno dei record o ignorare i dati che sta inviando a DefectDojo, puoi scegliere di 'ignorare' il record. Un record 'ignorato' passerà all'elenco dei record non mappati e non invierà più nuovi dati a DefectDojo.

Puoi ignorare un record mappato (il che rimuoverà la mappatura), oppure un record Nuovo (dall'elenco dei record non mappati).

#### Ripristinare un record ignorato

Se desideri rimuovere lo stato Ignorato da un record, puoi riportarlo a Nuovo utilizzando lo stesso menu a discesa Stato.

* Se la Mappatura automatica dei record è attivata, il record tornerà alla sua mappatura originale non appena verrà eseguita nuovamente l'operazione di Rilevamento.  
* Se la Mappatura automatica dei record non è attivata, DefectDojo non ripristinerà automaticamente una mappatura precedente, quindi dovrai configurare nuovamente la mappatura per questo record.

### Eliminare un record

Puoi anche eliminare i record, il che li rimuoverà dalla tabella dei record non mappati o mappati.

Tieni presente che la funzione di Rilevamento importerà sempre tutti i record da uno strumento, il che significa che anche se un record viene eliminato da DefectDojo, verrà rilevato di nuovo in seguito (e tornerà nell'elenco dei record da mappare nuovamente).

* Se hai intenzione di rimuovere il Prodotto Equivalente del Fornitore sottostante dal tuo strumento di scansione, eliminare il record è una buona opzione. Altrimenti, la successiva operazione di Rilevamento rileverà che i dati associati sono mancanti e questo record cambierà stato in 'Mancante'.  
​
* Tuttavia, se il Prodotto Equivalente del Fornitore sottostante esiste ancora, verrà rilevato di nuovo in una futura operazione di Rilevamento. Per evitare questo comportamento, puoi invece ignorare il record.

#### Questo influisce sui dati importati?

No. Tutti i Riscontri, i Test e gli Engagement creati da un record di sincronizzazione rimarranno in DefectDojo anche dopo l'eliminazione del record. Eliminare un record o una configurazione rimuoverà solo il processo di flusso dei dati e non eliminerà alcun dato di vulnerabilità da DefectDojo o dal tuo strumento.
