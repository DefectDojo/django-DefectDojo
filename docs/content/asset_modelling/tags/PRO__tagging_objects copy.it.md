---
title: Tagging degli oggetti
description: Utilizza i Tag per creare una nuova suddivisione del tuo modello dati
draft: false
weight: 2
exclude_search: false
audience: pro
aliases:
- /it/en/working_with_findings/organizing_engagements_tests/tagging_objects
---

I Tag sono ideali per raggruppare gli oggetti in un modo che consenta di filtrarli in blocchi più piccoli e gestibili. Possono essere utilizzati per indicare uno stato, oppure per creare insiemi personalizzati di Tipi di Prodotto, Prodotti, Engagement o Riscontri in tutto il modello dati.

In DefectDojo, i Tag sono cittadini di prima classe e sono riconosciuti come i facilitatori
dell'organizzazione a ogni livello del modello dati.

Ecco un esempio con un Prodotto con due tag e quattro riscontri, ciascuno con un singolo tag:

![Esempio di alto livello dell'utilizzo dei tag](images/tags-high-level-example.png)

### Formati dei Tag

I tag possono essere formattati in uno dei seguenti modi:
- StringWithNoSpaces
- string-with-hyphens
- string_with_underscores
- colons:acceptable

## Gestione dei Tag (UI Pro)

### Aggiunta e rimozione

I tag possono essere gestiti nei seguenti modi:

1. **Creazione o modifica di nuovi oggetti**

   Quando un nuovo oggetto viene creato o modificato tramite l'interfaccia utente o l'API, è presente un campo per specificare
   i tag da impostare su un determinato oggetto.

   ![tag](images/tags_product.png)

2. **Durante l'importazione/reimportazione dei Riscontri**

  I tag sono disponibili nel modulo di importazione/reimportazione, sia nell'interfaccia utente che tramite l'API.  Quando questo modulo viene inviato, al **Test** verranno assegnati i tag `[tag]` e `[daily-import]`.  Se viene selezionata l'opzione "Apply Tags to Findings" o "Apply Tags to Endpoints", anche quegli oggetti verranno taggati.  I tag offrono l'opportunità di aggiungere dettagli sull'esecuzione dell'automazione e informazioni sullo strumento che potrebbero non essere acquisite direttamente nell'oggetto Test o Riscontro.

   ![tag](images/tags_importscan.png)

3. **Tramite la modifica collettiva**

  Quando vengono selezionati più Riscontri da una tabella, è possibile utilizzare il menu di modifica collettiva per modificare contemporaneamente i Tag associati a più Riscontri. Tieni presente che questa operazione sostituirà tutti i Tag a livello di Riscontro con quelli specificati; i Tag esistenti sui Riscontri verranno sovrascritti.

  ![modifica collettiva dei riscontri](images/Bulk_Editing_Findings.png)


## Gestione dei Tag (UI classica / Open Source)

### Aggiunta e rimozione

I tag possono essere gestiti nei seguenti modi:

1. Creazione o modifica di nuovi oggetti

   Quando un nuovo oggetto viene creato o modificato tramite l'interfaccia utente o l'API, è presente un campo per specificare
   i tag da impostare su un determinato oggetto. Questo campo è un campo a selezione multipla che dispone anche del
   completamento automatico, per rendere semplicissima la ricerca e l'aggiunta di tag esistenti. Ecco come si presenta il campo
   sul Prodotto, nella schermata della sezione precedente:

   ![Gestione dei tag su un oggetto](images/tags-management-on-object.png)

2. Importazione e reimportazione

    I tag possono anche essere applicati a un determinato test al momento dell'importazione o della reimportazione. Questo è un
    caso d'uso molto utile quando si importa tramite API con l'automazione, poiché offre l'opportunità di
    aggiungere dettagli sull'esecuzione dell'automazione e informazioni sullo strumento che potrebbero non essere acquisite direttamente nell'oggetto test
    o riscontro.

    Il campo ha lo stesso aspetto e lo stesso comportamento di quello presente su un determinato oggetto

3. Menu di modifica collettiva (solo Riscontri)

    Quando è necessario aggiornare molti Riscontri con lo stesso insieme di tag, il menu di modifica collettiva può essere
    utilizzato per semplificare l'operazione.

    Nell'esempio seguente, supponiamo di voler aggiornare i tag dei due riscontri con il tag "tag-group-alpha" in un nuovo elenco di tag come questo ["tag-group-charlie", "tag-group-delta"].
    Per prima cosa selezionerei i tag da aggiornare:

    ![Selezione dei riscontri per l'aggiornamento collettivo dei tag](images/tags-select-findings-for-bulk-edit.png)

    Una volta selezionato un riscontro, appare un nuovo pulsante denominato "Modifica collettiva". Facendo clic su questo pulsante
    viene visualizzato un menu a tendina con molte opzioni, ma per ora ci concentriamo solo sui tag. Aggiorna il
    campo con l'elenco di tag desiderato come segue, quindi fai clic su invia

    ![Applicazione delle modifiche per l'aggiornamento collettivo dei tag](images/tags-bulk-edit-submit.png)

    I tag sui Riscontri selezionati verranno aggiornati con quanto specificato nel campo dei tag
    all'interno del menu di modifica collettiva

    ![Aggiornamento collettivo dei tag completato](images/tags-bulk-edit-complete.png)

## Ereditarietà dei Tag

**Nota sull'UI Pro: sebbene l'ereditarietà dei Tag possa essere configurata tramite l'UI Pro, i Tag ereditati possono attualmente essere consultati e filtrati solo tramite l'UI classica o l'API.**

Quando l'Ereditarietà dei Tag è abilitata, i tag applicati a un determinato Prodotto verranno applicati automaticamente a tutti gli oggetti sottostanti ai Prodotti nella [Gerarchia dei Prodotti](/asset_modelling/os_hierarchy/product_hierarchy/).

### Configurazione

L'Ereditarietà dei Tag può essere abilitata ai seguenti livelli di ambito:
- Ambito globale
  - Ogni Prodotto a livello di sistema inizierà ad applicare i tag a tutti gli oggetti figli (Engagement, Test e Riscontri)
  - Questa impostazione si configura all'interno delle Impostazioni di sistema
- Ambito Prodotto
  - Solo il Prodotto selezionato inizierà ad applicare i tag a tutti gli oggetti figli (Engagement, Test e Riscontri)
  - Questa impostazione si configura nella pagina di creazione/modifica del Prodotto

### Comportamenti

Quando l'Ereditarietà dei Tag è abilitata, i Tag standard possono essere aggiunti e rimossi dagli oggetti nel modo consueto.
Tuttavia i tag ereditati non possono essere rimossi da un oggetto figlio senza rimuoverli dall'oggetto padre
Vedi il seguente esempio di aggiunta di un tag "test_only_tag" all'oggetto Test e di un tag "engagement_only_tag" all'Engagement.

![Esempio di tag ereditati](images/tags-inherit-exmaple.png)

Quando vengono apportati aggiornamenti all'elenco dei tag di un Prodotto, le stesse modifiche vengono applicate in modo asincrono a tutti gli oggetti all'interno del Prodotto. La durata di questa operazione è direttamente correlata al numero di oggetti contenuti in un riscontro.

**Open Source:** se le modifiche ai Tag non vengono osservate entro un periodo di tempo ragionevole, consulta i log del worker celery per individuare l'origine di eventuali problemi.


### Filtro per Tag (UI classica)

I tag possono essere filtrati in molti modi, sia tramite l'interfaccia utente che tramite l'API. Ad esempio, ecco un estratto
dei filtri dei Riscontri:

![Estratto dei filtri dei riscontri](images/tags-finding-filter-snippet.png)

Sono presenti dieci campi relativi ai tag:

 - Tag: filtra in base a qualsiasi tag associato a un determinato Riscontro
   - Esempi:
     - Il Riscontro verrà restituito
       - Tag del Riscontro: ["A", "B", "C"]
       - Query di filtro: "B"
     - Il Riscontro *non* verrà restituito
       - Tag del Riscontro: ["A", "B", "C"]
       - Query di filtro: "F"
 - Non Tag: filtra in base a qualsiasi tag *non* associato a un determinato Riscontro
   - Esempi:
     - Il Riscontro verrà restituito
       - Tag del Riscontro: ["A", "B", "C"]
       - Query di filtro: "F"
     - Il Riscontro *non* verrà restituito
       - Tag del Riscontro: ["A", "B", "C"]
       - Query di filtro: "B"
 - Il nome del Tag contiene: filtra in base a qualsiasi tag che contenga in parte o interamente la query nel Riscontro indicato
   - Esempi:
     - Il Riscontro verrà restituito
       - Tag del Riscontro: ["Alpha", "Beta", "Charlie"]
       - Query di filtro: "et" (parte di "Beta")
     - Il Riscontro *non* verrà restituito
       - Tag del Riscontro: ["Alpha", "Beta", "Charlie"]
       - Query di filtro: "meg" (parte di "Omega")
 - Non Tag: filtra in base a qualsiasi tag che *non* contenga in parte o interamente la query nel Riscontro indicato
   - Esempi:
     - Il Riscontro verrà restituito
       - Tag del Riscontro: ["Alpha", "Beta", "Charlie"]
       - Query di filtro: "meg" (parte di "Omega")
     - Il Riscontro *non* verrà restituito
       - Tag del Riscontro: ["Alpha", "Beta", "Charlie"]
       - Query di filtro: "et" (parte di "Beta")

Per gli altri sei filtri di tag, valgono le stesse regole di "Tag" e "Non Tag" descritte sopra,
ma a livelli diversi del modello dati:

 - Tag (Test): filtra in base a qualsiasi tag associato al Test di un determinato Riscontro
 - Non Tag (Test): filtra in base a qualsiasi tag *non* associato al Test di un determinato Riscontro
 - Tag (Engagement): filtra in base a qualsiasi tag associato all'Engagement di un determinato Riscontro
 - Non Tag (Engagement): filtra in base a qualsiasi tag *non* associato all'Engagement di un determinato Riscontro
 - Tag (Prodotto): filtra in base a qualsiasi tag associato al Prodotto di un determinato Riscontro
 - Non Tag (Prodotto): filtra in base a qualsiasi tag *non* associato al Prodotto di un determinato Riscontro
