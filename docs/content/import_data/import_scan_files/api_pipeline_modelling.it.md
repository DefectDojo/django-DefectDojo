---
title: Importazione tramite API
description: ''
aliases:
- /it/en/connecting_your_tools/import_scan_files/api_pipeline_modelling
---

L'API di DefectDojo consente soluzioni di pipeline robuste, che acquisiscono automaticamente nuove scansioni nella tua istanza. Un'automazione di questo tipo può assumere diverse forme:

* Un'importazione giornaliera che scansiona il tuo ambiente su base quotidiana e poi importa i risultati della scansione in DefectDojo (simile alla nostra funzionalità **Connectors**)
* Una pipeline CI/CD che scansiona il nuovo codice man mano che viene distribuito, e importa i risultati in DefectDojo come azione attivata

Queste pipeline possono essere create chiamando direttamente il nostro endpoint API **/reimport** con un file di scansione allegato, in un modo che ricorda molto da vicino il nostro **Import Scan Form**.

## L'API di DefectDojo

L'API di DefectDojo è documentata direttamente nell'app utilizzando il framework OpenAPI. Puoi accedere a questa documentazione dal Menu Utente nell'angolo in alto a destra, sotto **'API v2 OpenAPI3'**.

\- La documentazione può essere usata per testare le chiamate API con vari parametri, e lo fa utilizzando il Token API del tuo utente.

Se hai bisogno di accedere a un token API per uno script o un'altra integrazione, puoi trovare questa informazione sotto l'opzione **API v2 Token** dello stesso menu.

![image](images/api_pipeline_modelling.png)

### Considerazioni generali sull'API

* Sebbene la nostra documentazione OpenAPI sia dettagliata per quanto riguarda i parametri utilizzabili con ciascun endpoint, essa presuppone che il lettore abbia una solida comprensione dei concetti chiave di DefectDojo (gerarchia dei Prodotti, Riscontri, deduplicazione, ecc.).
* Gli utenti che desiderano un'integrazione di importazione funzionante ma hanno meno familiarità con DefectDojo nel suo complesso dovrebbero considerare il nostro **Universal Importer**.
* L'API di DefectDojo può a volte creare oggetti dati non intenzionali, in particolare se su l'endpoint **/import** o **/reimport** viene utilizzato 'Auto-Create Context'.
* Fortunatamente, è molto difficile eliminare accidentalmente dati tramite l'API. La maggior parte degli oggetti può essere rimossa solo tramite una chiamata **DELETE** dedicata all'endpoint pertinente.

### Note specifiche sugli endpoint /import e /reimport

L'endpoint **/reimport** può essere usato sia per un'importazione iniziale, sia per un "Reimport" che estende un Test con Riscontri aggiuntivi. Non è necessario creare prima un Test con **/import** prima di poter usare l'endpoint **/reimport**. Finché 'Auto Create Context' è abilitato, l'endpoint /reimport può creare un nuovo Test, Engagement, Prodotto o Tipo di Prodotto. In quasi tutti i casi, puoi usare esclusivamente l'endpoint **/reimport** quando aggiungi dati tramite API.

Tuttavia, l'endpoint **/import** può essere usato invece per una pipeline in cui vuoi sempre archiviare ogni risultato di scansione in un oggetto Test distinto, anziché usare **/reimport** per gestire il diff all'interno di un singolo oggetto Test. Entrambe le opzioni sono accettabili, e l'endpoint che scegli dipende dalla tua struttura di reporting, o dal fatto che tu debba ispezionare un'esecuzione isolata di una Pipeline.

### Utilizzo del campo Data di completamento della scansione (API: `scan_date`)

DefectDojo offre un'ampia gamma di report di scanner supportati, ma non tutti i report contengono le informazioni più importanti per un utente. Il campo `scan_date` è una funzionalità intelligente e flessibile che permette agli utenti di impostare la data di completamento di un determinato report di scansione, e di propagarla a tutti i riscontri importati.

Questo campo **non** è obbligatorio, ma il valore predefinito per questo campo è la data di importazione (nel momento in cui la richiesta viene elaborata e viene restituita una risposta di successo).

Ecco i seguenti casi d'uso per questo campo, e i risultati applicati al Test:

1. Se il report **non** imposta la data, e `scan_date` **non** è impostato all'importazione
    - La data del Riscontro sarà il valore predefinito di `scan_date`
2. Se il report **imposta** la data, e `scan_date` **non** è impostato all'importazione
    - La data del Riscontro sarà quella impostata dal report
3. Se il report **non** imposta la data, e `scan_date` **è impostato** all'importazione
    - La data del Riscontro sarà quella impostata dall'utente per `scan_date`
4. Se il report **imposta** la data, e `scan_date` **è impostato** all'importazione
    - La data del Riscontro sarà quella impostata dall'utente per `scan_date`
