---
title: Sondaggi
description: Comprendere i Sondaggi in DefectDojo Pro
audience: pro
weight: 2
---

In DefectDojo, un modello di Sondaggio è un insieme riutilizzabile di Domande che serve a raccogliere informazioni da sviluppatori, team e stakeholder sia interni che esterni. Può essere utilizzato per raccogliere input prima dell'inizio dei lavori, garantire l'allineamento tra persone e team man mano che il lavoro procede, e consentire un'analisi retrospettiva una volta completato il lavoro.

In DefectDojo, il sistema dei Sondaggi è composto da tre elementi:
- **Modelli di Sondaggio**, che raggruppano e ordinano le Domande.
- **Distribuzioni del Sondaggio**, ovvero le istanze attive che raccolgono le risposte.
- **Risposte**, ovvero le risposte inviate dagli Utenti.

La creazione di un modello di Sondaggio non lo rende automaticamente disponibile per la raccolta di risposte. Per raccogliere risposte, un modello di Sondaggio deve essere distribuito.

## Permessi

La sezione Sondaggi nella barra laterale è visibile solo agli Utenti con stato di Superuser, e solo i Superuser possono creare modelli di Sondaggio, creare Domande e distribuire i Sondaggi.

Gli Utenti privi dello stato di Superuser possono comunque rispondere ai Sondaggi condivisi con loro, ma non possono crearli né gestirli, né gestire le Domande associate.

## Accesso a Sondaggi e Domande

Gli Utenti con stato di Superuser possono accedere a Sondaggi e Domande dalla barra laterale facendo clic sull'opzione **Surveys**. Il sottomenu fornisce accesso a **Tutti i Sondaggi** e **Tutte le Domande**, oltre all'opzione per creare nuovi Sondaggi e Domande.

![immagine](images/pq_ss1.png)

### Accesso ai Sondaggi

La vista Tutti i Sondaggi include una tabella contenente tutti i modelli di Sondaggio, con relativo ID, nome, descrizione e stato attivo. La tabella può essere filtrata utilizzando parole chiave e può essere riorganizzata facendo clic sull'intestazione di ciascuna colonna.

### Accesso alle Domande

La vista Tutte le Domande include una tabella di Domande che possono essere aggiunte a un Sondaggio. La tabella può essere filtrata utilizzando parole chiave e può essere riorganizzata facendo clic sull'intestazione di ciascuna colonna.

## Gestione dei modelli di Sondaggio

### Creazione di modelli di Sondaggio

I modelli di Sondaggio possono essere creati facendo clic su **Nuovo Sondaggio** nella barra laterale, oppure facendo clic sul pulsante **Nuovo Sondaggio** nella parte superiore della vista Tutti i Sondaggi.

![immagine](images/pq_ss2.png)

Prima della creazione, al modello di Sondaggio devono essere assegnati un nome e una descrizione, oltre ad almeno una Domanda scelta dal menu a tendina.

#### Aggiungere Domande a un modello di Sondaggio esistente

Per aggiungere Domande a un modello di Sondaggio esistente, fai clic sull'icona a kebab ⋮ a sinistra del Sondaggio desiderato, fai clic su **Modifica Sondaggio**, seleziona dal menu a tendina eventuali nuove Domande da aggiungere al Sondaggio, quindi fai clic su **Invia**.

Come buona pratica, si raccomanda vivamente di evitare di modificare o aggiungere Domande a un modello di Sondaggio mentre ha distribuzioni attive. L'aggiunta di nuove Domande non influirà sulle Risposte esistenti, ma tali Risposte saranno state inviate senza rispondere alle Domande appena aggiunte, il che potrebbe determinare dati incompleti.

### Creazione di Domande

Analogamente ai modelli di Sondaggio, le Domande possono essere create facendo clic su **Nuova Domanda** nella barra laterale, oppure facendo clic sul pulsante **Nuova Domanda** nella parte superiore della vista Tutte le Domande.

#### Tipi di Domanda

Quando si crea una nuova Domanda, questa può essere formattata come domanda testuale o come domanda a scelta multipla selezionando **Domanda testuale** o **Domanda a scelta multipla** nella parte superiore della vista Nuova Domanda.

![immagine](images/pq_ss3.png)

#### Ordine delle Domande

Determina l'ordine di una Domanda assegnandole un numero d'ordine. Ad esempio, se una Domanda ha il valore 1 nel campo Ordine, quella Domanda apparirà sopra una Domanda con il valore 2 nel campo Ordine.

#### Risposte opzionali

Sia le domande testuali che le domande a scelta multipla possono essere contrassegnate come **Opzionale** facendo clic sulla casella di controllo corrispondente.

#### Consentire risposte multiple

È possibile aggiungere un numero illimitato di risposte potenziali a una domanda a scelta multipla. Selezionando la casella di controllo **Consenti selezioni multiple** è possibile selezionare più risposte (disponibile solo per le domande a scelta multipla).

### Modifica delle Domande

Per modificare una Domanda, vai alla vista Tutte le Domande, fai clic sull'icona a kebab ⋮ a sinistra della Domanda da modificare, fai clic su Modifica Domanda, apporta la modifica desiderata e finalizza la modifica facendo clic su Invia. Le Domande non possono essere eliminate.

![immagine](images/pq_ss4.png)

È importante evitare di modificare Domande che fanno parte di Questionari attivi o di aggiungere Domande a Questionari attivi. Farlo non influirà sulle risposte raccolte in precedenza, ma potrebbe determinare dati incompleti o inaffidabili.

## Distribuzione dei Sondaggi

Una volta creato con successo un modello di Sondaggio, distribuire un Sondaggio crea un'istanza attiva che accetta risposte.

Per distribuire un Sondaggio, vai alla vista Tutti i Sondaggi, fai clic sull'icona a kebab ⋮ a sinistra del Sondaggio da distribuire, fai clic su **Apri Sondaggio**, imposta la data di scadenza e fai clic su Invia.

Se desideri distribuire nuovamente lo stesso Sondaggio, segui la stessa procedura. Tutte le distribuzioni appariranno nella tabella Istanze Sondaggio aperte nella vista del Sondaggio, e possono essere distinte in base a ID, orario di creazione e data di scadenza.

![immagine](images/pq_ss10.png)

Un Sondaggio si chiuderà alla data scelta, allo stesso orario in cui è stato distribuito. Ad esempio, se distribuisci un Sondaggio alle 8:00 del 1° febbraio 2026 e programmi la chiusura per il 1° marzo 2026, il sondaggio si chiuderà alle 8:00 del mattino del 1° marzo 2026.

Una volta aperto un Sondaggio, la sua data e ora di scadenza non possono essere modificate. Se è necessario un intervallo di tempo diverso, è necessario creare una nuova distribuzione.

Una volta trascorsa una data di scadenza, non sarà più possibile inviare risposte a quella distribuzione del Sondaggio, ma la distribuzione continuerà a comparire nella tabella Istanze Sondaggio aperte nella vista di quel Sondaggio.

#### Condivisione di un Sondaggio

Una volta distribuito, un Sondaggio può essere condiviso con altri Utenti facendo clic sull'icona ↗ a sinistra del Sondaggio all'interno della tabella Istanze Sondaggio aperte nella vista del modello di Sondaggio. Questo mostrerà un link univoco per quella distribuzione, che può essere copiato e condiviso con i destinatari previsti.

![immagine](images/pq_ss5.png)

![immagine](images/pq_ss9.png)

#### Chiusura di un Sondaggio

Per chiudere un Sondaggio, fai clic sulla **X** rossa a sinistra del Sondaggio all'interno della tabella Istanze Sondaggio aperte nella vista del modello di Sondaggio.

![immagine](images/pq_ss13.png)

Come indicato nella successiva sezione Risposte, questo impedirà solo l'invio di ulteriori risposte. Le risposte inviate in precedenza rimarranno visibili nella tabella Risposte in fondo alla vista del modello di Sondaggio.

## Rispondere ai Sondaggi

Per rispondere a un Sondaggio, agli utenti non Superuser deve essere condiviso direttamente il link, seguendo le istruzioni riportate nella sezione [Condivisione di un Sondaggio](#sharing-a-survey) sopra. Anche i Superuser possono rispondere utilizzando lo stesso link.

#### Abilitazione delle risposte anonime

Per impostazione predefinita, i Sondaggi sono accessibili solo agli Utenti di DefectDojo. Per consentire a soggetti esterni di rispondere ai Sondaggi di DefectDojo, assicurati che l'opzione **Abilita risposte anonime ai Sondaggi** sia attivata nelle **Impostazioni di sistema**, disponibili in **Impostazioni > Sistema** nella barra laterale (all'interno del sottomenu **Impostazioni Pro** sulle istanze che utilizzano ancora il layout di menu precedente).

![immagine](images/pq_ss6.png)

Le risposte esterne appariranno come anonime, poiché non è presente alcun ID utente DefectDojo associato alla risposta.

Se l'ambito di un Sondaggio include sia Utenti interni che esterni, specifica il nome dell'Engagement nella descrizione al momento della creazione, il che consentirà di filtrare i risultati.

![immagine](images/pq_ss7.png)

![immagine](images/pq_ss8.png)

## Gestione delle Risposte

Un singolo modello di Sondaggio può essere distribuito più volte contemporaneamente. Tutte le risposte alle diverse distribuzioni dello stesso modello di Sondaggio verranno visualizzate insieme nella tabella Risposte in fondo alla vista di quel Sondaggio.

![immagine](images/pq_ss11.png)

Anche dopo che una distribuzione di un Sondaggio è scaduta o è stata chiusa, le relative risposte rimangono visibili nella tabella Risposte in fondo alla vista del Sondaggio, a condizione che il modello di Sondaggio stesso non sia stato eliminato. Queste risposte sono permanenti e non possono essere rimosse.

Come mostrato nell'immagine seguente, non ci sono attualmente distribuzioni di Sondaggi aperte, eppure le risposte delle distribuzioni precedenti sono ancora presenti nella tabella Risposte.

![immagine](images/pq_ss12.png)

### Eliminazione dei modelli di Sondaggio

Per eliminare un modello di Sondaggio, vai alla vista Tutti i Sondaggi, fai clic sull'icona a kebab ⋮ a sinistra del Sondaggio scelto, quindi fai clic su **Elimina Sondaggio**. Questa operazione elimina definitivamente il modello di Sondaggio e tutte le distribuzioni e Risposte associate. Questa azione non può essere annullata.
