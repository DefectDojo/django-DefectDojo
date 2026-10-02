---
title: Modifica dei Riscontri
description: Modifica lo Stato di un Riscontro o aggiungi altri metadati durante la
  risoluzione di un problema
weight: 2
aliases:
- /it/en/working_with_findings/findings_workflows/editing_findings
---

Se desideri aggiungere note o aggiornare il testo di un Riscontro per renderlo più pertinente alla situazione attuale, puoi farlo tramite il modulo di modifica del Riscontro.

## Aprire il modulo di modifica del Riscontro

Puoi aggiornare un Riscontro aprendo il **Menu** dell'**⚙️ ingranaggio** in alto e facendo clic su **Modifica Riscontro.**

![image](images/Editing_Findings.png)

Si aprirà così il modulo **Modifica Riscontro**, dove puoi modificare i metadati, cambiare lo Stato del Riscontro e aggiungere ulteriori informazioni.

![image](images/Editing_Findings_2.png)

### Modulo di modifica del Riscontro: campi

* **"Test" non può essere modificato:** i Riscontri devono sempre essere associati a un oggetto Test e non possono essere spostati al di fuori di quel contesto. Tuttavia, l'Engagement che contiene un Test può essere spostato in un altro Prodotto.
​
* **Rilevato da** è lo strumento di scansione che ha individuato questo Riscontro. Nota che puoi aggiungere ulteriori strumenti di scansione oltre a quello associato al Test.
​
* **Titolo** viene creato a partire dal report di scansione, ma puoi modificare questo titolo per renderlo più significativo, se necessario. Nota che questo può influire sulla Deduplicazione, poiché la Deduplicazione utilizza generalmente i titoli dei Riscontri per identificare i duplicati.
​
* **Data** ha lo scopo di rappresentare la data in cui il Riscontro è stato individuato dallo scanner \- non necessariamente la data in cui il Riscontro è stato importato in DefectDojo. Questa data viene ricavata dal report di scansione, ma puoi aggiornarla per renderla più accurata, se necessario (ad esempio quando si lavora con dati storici, o quando si utilizza uno strumento di scansione che non registra le date di individuazione).
​
* **Descrizione** è la descrizione di un Riscontro fornita dallo strumento di scansione. Puoi aggiungere o rimuovere informazioni dalla descrizione del Riscontro, se lo desideri.
​
* **Gravità** viene calcolata in base a diversi fattori. A un livello base, corrisponde alla Gravità segnalata da uno strumento, ma la Gravità di un Riscontro può essere influenzata dalle variazioni EPSS. Puoi anche regolare manualmente la Gravità del Riscontro al livello appropriato.
​
* **Tag** sono etichette di testo generiche che puoi utilizzare per organizzare i tuoi Riscontri tramite i Filtri \- oppure possono semplicemente essere usate come scorciatoia per identificare un Riscontro specifico.
​
* **Attivo / Verificato** sono gli stati principali dei Riscontri utilizzati da uno strumento. I Riscontri Attivi sono Riscontri attualmente attivi nella tua rete e segnalati da uno strumento. Verificato significa che un membro del team ha confermato l'esistenza di questo Riscontro.
​
* **SAST / DAST** sono etichette utilizzate per organizzare i tuoi Riscontri in base al contesto in cui sono stati individuati. In genere questa etichetta viene compilata in base allo strumento di scansione utilizzato, ma puoi correggerla per renderla più accurata (ad esempio, se il Riscontro è stato individuato sia da uno strumento SAST sia da uno strumento DAST).

### Modifica della Data di mitigazione e del campo Mitigato da

Per impostazione predefinita, i valori **Data di mitigazione** e **Mitigato da** di un Riscontro **non sono modificabili**. Questi campi sono nascosti sia nel modulo di modifica del Riscontro sia nella finestra di dialogo di chiusura del Riscontro, e la Data di mitigazione viene sempre impostata automaticamente al momento in cui il Riscontro viene chiuso. Per lo stesso motivo, il tentativo di impostare o retrodatare questi valori tramite API viene rifiutato.

La modifica può essere abilitata tramite l'impostazione del server `DD_EDITABLE_MITIGATED_DATA`. Quando è abilitata, i campi **Data di mitigazione** e **Mitigato da** compaiono nel modulo di modifica del Riscontro e nella finestra di dialogo di chiusura del Riscontro, e possono anche essere impostati tramite API — ma solo per gli utenti con stato di **superuser**. In altre parole, la modifica richiede *sia* che l'impostazione sia abilitata *sia* che l'utente che esegue l'azione sia un superuser.

* **Perché è disattivata per impostazione predefinita:** consentire di retrodatare una mitigazione può rappresentare in modo scorretto la conformità allo SLA — un Riscontro effettivamente rimediato *al di fuori* della sua finestra SLA potrebbe risultare registrato come se fosse stato mitigato *entro* lo SLA. L'abilitazione dell'impostazione ha effetto solo per il futuro; **non** modifica la Data di mitigazione né l'età di alcun Riscontro esistente.
* **Tutto resta tracciabile:** ogni modifica a un Riscontro, incluse le modifiche a Data di mitigazione e Mitigato da, viene registrata nel log cronologico del Riscontro — chi ha effettuato la modifica, quando, e i valori precedenti e nuovi.
* **Applicare l'impostazione:** `DD_EDITABLE_MITIGATED_DATA` è una variabile d'ambiente a livello di server (vedi [Configuration](/get_started/open_source/configuration/)). Modificarla richiede il riavvio del servizio per avere effetto.
* **DefectDojo Cloud / Pro:** questa impostazione non può essere modificata dall'interfaccia utente. Contatta il supporto DefectDojo per farla abilitare sulla tua istanza.

## Modifica massiva dei Riscontri

I Riscontri possono essere modificati in massa da un elenco di Riscontri, disponibile sia nella pagina dei Riscontri stessa, sia all'interno di un Test.

### Selezionare i Riscontri per la modifica massiva

Quando visualizzi una tabella con più Riscontri, come la tabella 'Findings From \[tool]' in una pagina Test o l'elenco di tutti i Riscontri, puoi utilizzare le caselle di controllo accanto ai Riscontri per contrassegnarli per la modifica massiva.

Selezionando uno o più Riscontri in questo modo si apre il menu (nascosto) di modifica massiva, che contiene le seguenti quattro opzioni:

* **Azioni di aggiornamento massivo**: applica modifiche ai metadati ai Riscontri selezionati.
* **Azioni di Accettazione del rischio: crea un'Accettazione del rischio completa per gestire i Riscontri selezionati, oppure aggiungi i Riscontri a un'Accettazione del rischio completa esistente**
* **Azioni sul Finding Group: crea un Finding Group composto dai Riscontri selezionati. Nota che i Finding Group possono essere creati solo all'interno di un singolo Test.**
* **Elimina: elimina i Riscontri selezionati. Dovrai confermare questa azione in una nuova finestra.**

![image](images/Bulk_Editing_Findings.png)

### Azioni di aggiornamento massivo

Tramite il menu Azioni di aggiornamento massivo, puoi applicare le seguenti modifiche a qualsiasi Riscontro selezionato:

* Aggiornare la **Gravità**
* Applicare un nuovo **Stato del Riscontro**
* Modificare la Data di scoperta o la Data di rimedio pianificata dei Riscontri
* Aggiungere un'**Accettazione del rischio semplice,** se l'opzione è abilitata a livello di Prodotto
* Applicare **Tag** o **Note** a tutti i Riscontri selezionati.

![image](images/Bulk_Editing_Findings_2.png)

### Azioni di Accettazione del rischio

Questa pagina consente di aggiungere un'**Accettazione del rischio completa** ai Riscontri selezionati. Puoi creare una nuova **Accettazione del rischio completa** oppure aggiungere i Riscontri a una già esistente.

![image](images/Bulk_Editing_Findings_3.png)

### Azioni sul Finding Group

Questa pagina consente di creare un nuovo Finding Group a partire dai Riscontri selezionati, oppure di aggiungerli a un Finding Group esistente.

Tuttavia, i Finding Group possono essere creati solo all'interno di un singolo **Test** \- i Riscontri appartenenti a Test, Engagement o Prodotti diversi non possono essere aggiunti allo stesso Finding Group.

![image](images/Bulk_Editing_Findings_4.png)

### Eliminazione massiva dei Riscontri

Puoi anche eliminare i Riscontri selezionati facendo clic sul pulsante rosso **Elimina**. Comparirà una finestra popup che ti chiederà di confermare questa decisione.

![image](images/Bulk_Editing_Findings_5.png)
