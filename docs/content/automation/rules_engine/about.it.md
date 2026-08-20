---
title: Automazione di Rules Engine
description: Come utilizzare l'automazione di Rules Engine
weight: 1
audience: pro
aliases:
- /it/en/customize_dojo/rules_engine
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine è una funzionalità disponibile solo in DefectDojo Pro.</span>

Il Rules Engine di DefectDojo consente di creare flussi di lavoro personalizzati e azioni collettive per gestire i Finding e altri oggetti. Rules Engine consente di creare azioni automatizzate che vengono attivate quando un oggetto corrisponde a una Regola.

Rules Engine è accessibile solo tramite la [Pro UI](/get_started/about/ui_pro_vs_os/).

**Cerchi l'editor a grafo?** [Rules Engine 2.0](/automation/rules_engine_2/about/) costruisce l'automazione come grafi di nodi visuali, e aggiunge la ramificazione, azioni in uscita come ticket e messaggi, tracce per ogni run e un registro delle consegne. I due motori funzionano in parallelo, e le regole esistenti possono essere [convertite](/automation/rules_engine_2/converting_from_rules_engine/).

## Abilitare Rules Engine

Rules Engine è in versione Beta ed è disattivato per impostazione predefinita. Un superuser può attivarlo da **Settings > Feature Flags**, sia sulle istanze Cloud sia On-Premise. Vedere [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Attualmente le Regole possono essere create solo per i Finding, ma in futuro saranno supportati altri tipi di oggetto.

Le Regole possono essere attivate manualmente dalla pagina **All Rules**, oppure pianificate per l'esecuzione automatica secondo una ricorrenza. Quando una regola viene attivata, viene applicata a tutti i Finding esistenti che corrispondono alle condizioni di filtro impostate.

## Possibili azioni delle regole
Ogni Regola può applicare una o più di queste modifiche a un Finding quando viene attivata con successo (ossia corrisponde alle condizioni di Filtro impostate).

### Modifiche ai campi
* **Impostare un campo** su un Finding, tra cui Title, Description, Severity, CVSSv3 Vector, Active, Verified, Risk Accepted, False Positive, Mitigated
* **Aggiungere testo in coda o in testa** al Title o alla Description di un Finding
* **Impostare Priority** — sostituisce il valore di Priority calcolato su un Finding (sovrascrive il calcolo automatico della priorità)
* **Impostare Risk** — sostituisce il livello di Risk calcolato su un Finding (sovrascrive il calcolo automatico del rischio)
* **Sommare, sottrarre, moltiplicare o dividere** il valore di Priority su un Finding per un numero indicato

### Assegnazioni e proprietà
* **Impostare un Utente per la revisione** di un Finding
* **Assegnare un Gruppo come proprietario** di un Finding
* **Impostare una Mitigation Policy** su un Finding — assegna al Finding una Mitigation Policy preconfigurata
* **Aggiungere a Risk Acceptance** — aggiunge un Finding a un record di Risk Acceptance esistente (imposta risk_accepted=True, active=False, e gestisce l'integrazione con Jira e gli stati degli endpoint)

### Tag, note e avvisi
* **Aggiungere Tag** a un Finding
* **Aggiungere una Nota** a un Finding
* **Creare un Alert** in DefectDojo con testo personalizzato

### Condizioni di filtro
Le Regole vengono attivate automaticamente quando un Finding soddisfa specifiche condizioni di Filtro. Per maggiori informazioni sui Filtri utilizzabili per creare Azioni delle Regole, vedere la pagina [Filter Index](/navigation/pro__filter_index).

## Creare una nuova Regola
Avvia questo processo dalla pagina New Rule. Nella [Pro UI](/get_started/about/ui_pro_vs_os/), sotto **Manage Category**, espandi il menu a tendina **Rules Engine** e fai clic su **+ New Rule**.

![image](images/rules_engine_1.png)

### Passaggio 1: assegna un'etichetta alla tua Regola
Inserisci un'etichetta come identificatore per la nuova regola, quindi fai clic su Next.

![image](images/rules_engine_2.png)

### Passaggio 2: imposta le condizioni di attivazione con un Filtro
Vedrai una tabella All Findings. Utilizzando la tabella All Findings, imposta le condizioni di Filtro per filtrare l'insieme di Finding a cui vuoi che la tua regola si applichi. Per maggiori informazioni sull'applicazione dei Filtri a una tabella, vedere [la nostra guida alla Pro UI](/get_started/about/ui_pro_vs_os/#navigational-changes).

La tabella mostrerà in anteprima l'elenco dei Finding esistenti che hai filtrato.

Ad esempio, in questa schermata stiamo filtrando tutti i Finding che si trovano in 'Product One'. Una volta applicato questo filtro (facendo clic al di fuori del menu Filters), verrà aggiunto al nostro elenco di Filtri applicabili.

![image](images/rules_engine_3.png)

Nella schermata precedente, tutti i Finding che si trovano nel Prodotto 'Product One' subiranno le azioni impostate.

Una volta definito l'insieme di Filtri che vuoi applicare, fai clic sul pulsante Next.

### Passaggio 3: imposta le Azioni della Regola 
Dal menu a tendina **Action**, seleziona l'Azione che vuoi applicare a un Finding che corrisponde a tutti i filtri del Passaggio 2. È possibile applicare più Azioni.

Puoi impostare dei Valori Condizionali aggiuntivi che permettono di eseguire ulteriori azioni se vengono soddisfatti determinati criteri.  

![image](images/rules_engine_4.png)


Ad esempio, nella schermata precedente abbiamo impostato 4 Azioni della Regola. Due di queste azioni sono Condizionali.

Tutti i Finding che corrispondono alle condizioni di filtro attiveranno queste Azioni non condizionali:

* Il Finding verrà assegnato al gruppo utenti 'Group 1'
* Il Finding verrà taggato con `all_group_1`

Eventuali Finding che corrispondono alle condizioni di filtro, più queste condizioni **aggiuntive**, attiveranno queste Azioni Condizionali in aggiunta alle due Azioni non condizionali elencate sopra:

* **se il Finding ha Severity Critical**, verrà taggato con `critical_group_1`.
* **se il Finding ha Severity High**, verrà taggato con `high_group_1`.

### Passaggio 4 - Anteprima della tua Regola

La Rule Preview mostra tutti i Finding che verranno modificati da questa regola una volta eseguita, insieme a un'anteprima delle Azioni intraprese. Verifica di essere soddisfatto delle modifiche proposte, quindi fai clic su Submit per salvare la tua regola. 

Se ritieni che questa regola non sia stata applicata correttamente, puoi selezionare il pulsante Back e tornare a uno qualsiasi dei passaggi precedenti. 

![image](images/rules_engine_5.png)

Ad esempio, nella schermata precedente abbiamo un elenco di Finding che verranno interessati dalla Regola una volta eseguita. Possiamo vedere che nuovi Tag e Owner verranno applicati a ciascuno di questi Finding dalle colonne a destra dell'elenco dei Finding.

Ti verrà chiesto nuovamente di confermare che vuoi creare la tua Regola. Nota che **la Regola non verrà applicata immediatamente** e deve essere attivata manualmente.

## Eseguire una Regola
Dalla pagina All Rules, puoi selezionare una Regola che desideri eseguire. Fai clic sul titolo della regola per visualizzarla in dettaglio.

![image](images/rules_engine_6.png)

In questa pagina, puoi vedere informazioni dettagliate su questa regola sotto **Metadata**, incluse informazioni su quando la regola è stata attivata l'ultima volta. Puoi anche vedere un'anteprima dei Finding che verranno interessati da una nuova esecuzione di questa Regola, sotto **Rule Preview**.

Per eseguire la Regola, fai clic sul pulsante verde Run Rule. Dopo aver confermato che vuoi eseguire la regola, apparirà un messaggio che indica che la regola è in coda per l'esecuzione in background.

Una volta che la Regola ha terminato con successo l'esecuzione, il numero di Items Changed verrà aggiornato nella sezione Rule Metadata della descrizione della Regola.

## Riferimento ai metadati della Regola
* **Rule For**: gli oggetti governati dalla Regola.
* **Rule Name**: il nome della Regola.
* **Filters**: il numero di Filtri applicati da questa Regola.
* **Actions**: il numero di Azioni intraprese da questa Regola.
* **Owner**: l'Utente che ha creato questa Regola.
* **Status**: il resoconto dello Status dell'ultima esecuzione di questa Regola.  
    'E' = 'Error', 'R' = 'Running', 'S' = 'Success'.
* **Last Run**: il timestamp dell'ultima esecuzione di questa Regola.
* **Items Changed:** conteggio degli oggetti modificati nell'ultima esecuzione della regola.
* **Items Skipped:** conteggio degli oggetti saltati nell'ultima esecuzione della regola. Se un oggetto filtrato corrisponde già al 'risultato' di un'Azione della Regola applicata su di esso (ad esempio, se ha già i Tag che verrebbero applicati da un'Azione della Regola), l'oggetto verrà semplicemente saltato.
