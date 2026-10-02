---
title: Gestione delle Operazioni
description: Controlla lo stato delle operazioni di Discover e Sync del tuo Connettore
aliases:
- /it/import_data/pro/connectors/manage_operations/
- /it/en/connecting_your_tools/connectors/manage_operations
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: i Connettori Upstream sono una funzionalità esclusiva di DefectDojo Pro.</span>

Una volta configurato un Connettore Upstream, eseguirà due Operazioni a intervalli regolari:

* **Discover** apprenderà la struttura dello strumento collegato e creerà in DefectDojo dei record per ogni dato non mappato;
* **Sync** importerà nuovi Riscontri dallo strumento in base alle tue mappature.

Entrambe queste Operazioni vengono gestite nella pagina Operations di un Connettore. La tabella terrà anche traccia delle esecuzioni passate di queste Operazioni, così da poter verificare che il tuo Connettore sia aggiornato.

Per accedere alla pagina Operations di un Connettore, apri **Manage Records & Operations** per il Connettore con cui vuoi lavorare, quindi passa alla scheda **</\> Operations From (tool)**.

![image](images/operations_discover.png)

La pagina **Manage Records & Operations** può essere usata anche per gestire i Record, ovvero le singole mappature di Prodotto del tuo strumento collegato.  Consulta [Gestione dei Record](../manage_records) per maggiori informazioni.

## La pagina Operations

![image](images/operations_page.png)

Ogni voce nella tabella della pagina Operations è un record di un evento operativo, con le seguenti caratteristiche:

* **Type** descrive se l'evento è stata un'operazione **Sync** oppure **Discover**.
* **Status** descrive se l'evento è stato eseguito con successo.
* **Trigger** descrive come è stato attivato l'evento \- si trattava di un'operazione **Scheduled** eseguita automaticamente, oppure di un'operazione **Manual** attivata da un utente DefectDojo?
* L'**orario di inizio e fine** di ciascuna operazione è registrato qui, insieme alla **Duration**.

## Operazioni Discover

Il primo passo che un Connettore DefectDojo deve compiere è eseguire una **Discover** dell'ambiente del tuo strumento per vedere come organizzi i tuoi dati di scansione.

Supponiamo che tu abbia uno strumento BurpSuite, configurato per scansionare cinque repository diversi alla ricerca di vulnerabilità. Il tuo Connettore prenderà nota di questa struttura organizzativa e configurerà dei **Record** per aiutarti a tradurre quei repository separati nella gerarchia Prodotto/Engagement/Test di DefectDojo.

### Creazione di nuovi Record

Ogni volta che il tuo Connettore esegue un'operazione **Discover**, cercherà nuovi **Vendor\-Equivalent\-Products (VEP)**. DefectDojo osserva il modo in cui lo strumento del fornitore è configurato e creerà dei **Record** dei VEP in base a come è organizzato il tuo strumento.

![image](images/operations_discover_2.png)

### Eseguire Discover manualmente

Le operazioni **Discover** vengono eseguite automaticamente a intervalli regolari, ma possono anche essere eseguite manualmente. Se stai configurando questo Connettore per la prima volta, puoi fare clic sul pulsante **Discover** accanto all'intestazione **Unmapped Records**. Dopo aver aggiornato la pagina, vedrai il tuo elenco iniziale di **Record**.

![image](images/operations_discover_3.png)

Per saperne di più su come lavorare con i record e configurare le mappature verso i Prodotti, consulta la nostra guida a [Gestione dei Record](../manage_records).

## Operazioni Sync

Su base giornaliera, DefectDojo esaminerà ciascun **Mapped Record** alla ricerca di nuovi dati di scansione. DefectDojo eseguirà quindi una **Reimport**, che confronta lo stato dei dati di scansione esistenti con un report in arrivo.

### Dove vengono archiviati i dati di vulnerabilità?

* DefectDojo creerà un **Engagement** annidato sotto il Prodotto specificato nella **Record Mapping**. Questo Engagement si chiamerà **Global Connectors**.
* L'Engagement **Global Connectors** terrà traccia di ogni singolo Connettore associato al Prodotto come un **Test**.
* In questa sincronizzazione, e in ogni sincronizzazione successiva, il **Test** archivierà ogni vulnerabilità rilevata dallo strumento come un **Riscontro**.

### Come Sync gestisce i nuovi dati di vulnerabilità

Ogni volta che Sync viene eseguito, confronterà gli ultimi dati di scansione con l'elenco esistente di Riscontri per individuare le modifiche.

* Se vengono rilevati nuovi Riscontri, verranno aggiunti al Test come nuovi Riscontri.
* Se ci sono Riscontri che non vengono rilevati nell'ultima scansione, verranno contrassegnati come Inattivi nel Test.

Per saperne di più su Prodotti, Engagement, Test e Riscontri, consulta la nostra [Panoramica della gerarchia dei Prodotti](/asset_modelling/os_hierarchy/product_hierarchy/).

### Eseguire Sync manualmente

Per far eseguire a DefectDojo un'operazione Sync fuori programma:

1. Vai alla pagina **Manage Records \& Operations** per il connettore che vuoi usare. Dalla pagina **Upstream Connectors**, fai clic sul menu a tendina **Manage Configuration** sul Connettore con cui vuoi lavorare, e seleziona **Manage Records \& Operations**.  
​
2. Da questa pagina, fai clic sul pulsante **Sync**. Questo pulsante si trova accanto all'intestazione **Mapped Records**.

![image](images/operations_sync.png)
