---
title: Assegnazione dei Tag agli Oggetti
description: Usa i Tag per creare una nuova suddivisione del tuo modello dei dati
draft: false
weight: 2
exclude_search: false
audience: opensource
---

I Tag sono ideali per raggruppare gli oggetti in un modo che può essere filtrato in porzioni più piccole e più digeribili.  Possono essere usati per indicare lo stato, o per creare insiemi personalizzati di Organizzazioni, Asset, Engagement o Riscontri in tutto il modello dei dati.

In DefectDojo, i tag sono cittadini di prima classe e sono riconosciuti come i facilitatori
dell'organizzazione a ogni livello del modello dei dati.

Ecco un esempio con un Asset con due tag e quattro riscontri, ciascuno con un singolo tag:

![High level example of usage with tags](images/tags-high-level-example.png)

### Formati dei Tag

I tag possono essere formattati in uno dei seguenti modi:
- StringaSenzaSpazi
- stringa-con-trattini
- stringa_con_underscore
- duepunti:accettabili

## Gestione dei Tag

### Aggiunta e rimozione

I tag possono essere gestiti nei seguenti modi:

1. Creazione o modifica di nuovi oggetti

   Quando un nuovo oggetto viene creato o modificato tramite l'interfaccia utente o l'API, è presente un campo per specificare
   i tag da impostare su un dato oggetto. Questo campo è un campo a selezione multipla che dispone anche di
   completamento automatico per rendere semplice la ricerca e l'aggiunta di tag esistenti. Ecco come appare il campo
   sull'Asset dello screenshot nella sezione precedente:

   ![Tag management on an object](images/tags-management-on-object.png)

2. Import e Reimport

    I tag possono anche essere applicati a un dato test al momento dell'import o del reimport. Questo è un caso d'uso molto
    utile quando si importa tramite API con automazione, poiché offre l'opportunità di
    aggiungere dettagli sull'esecuzione automatica e informazioni sullo strumento che potrebbero non essere acquisite nel test
    o nell'oggetto riscontro direttamente. 

    Il campo appare e si comporta esattamente come su un dato oggetto

3. Menu di modifica in blocco (solo Riscontri)

    Quando è necessario aggiornare molti Riscontri con lo stesso insieme di tag, si può usare il menu di modifica in blocco per
    alleggerire l'onere.

    Nell'esempio seguente, supponiamo di voler aggiornare i tag dei due riscontri con il tag "tag-group-alpha" in un nuovo elenco di tag come questo ["tag-group-charlie", "tag-group-delta"]. 
    Per prima cosa selezionerei i tag da aggiornare:

    ![Select findings for bulk edit tag update](images/tags-select-findings-for-bulk-edit.png)

    Una volta selezionato un riscontro, appare un nuovo pulsante con il nome "Modifica in blocco". Facendo clic su questo pulsante
    si apre un menu a tendina con molte opzioni, ma per ora l'attenzione è solo sui tag. Aggiorna il
    campo con l'elenco di tag desiderato come segue, e fai clic su invia

    ![Apply changes for bulk edit tag update](images/tags-bulk-edit-submit.png)

    I tag sui Riscontri selezionati verranno aggiornati con quanto specificato nel campo tag
    all'interno del menu di modifica in blocco

    ![Completed bulk edit tag update](images/tags-bulk-edit-complete.png)

## Ereditarietà dei Tag

Quando l'Ereditarietà dei Tag è abilitata, i tag applicati a un dato Asset verranno automaticamente applicati a tutti gli oggetti sotto gli Asset nella [Gerarchia degli Asset](/asset_modelling/os_hierarchy/os__asset_hierarchy/).

### Configurazione

L'Ereditarietà dei Tag può essere abilitata ai seguenti livelli di ambito:
- Ambito globale
  - Ogni Asset a livello di sistema inizierà ad applicare i tag a tutti gli oggetti figli (Engagement, Test e Riscontri)
  - Questo si imposta nelle Impostazioni di Sistema
- Ambito Asset
  - Solo l'Asset selezionato inizierà ad applicare i tag a tutti gli oggetti figli (Engagement, Test e Riscontri)
  - Questo si imposta nella pagina di creazione/modifica dell'Asset

### Comportamenti

Quando l'Ereditarietà dei Tag è abilitata, i Tag standard possono essere aggiunti e rimossi dagli oggetti nel modo consueto.
Tuttavia i tag ereditati non possono essere rimossi da un oggetto figlio senza rimuoverli dall'oggetto genitore
Vedi il seguente esempio di aggiunta di un tag "test_only_tag" all'oggetto Test e di un tag "engagement_only_tag" all'Engagement.

![Example of inherited tags](images/tags-inherit-exmaple.png)

Quando vengono apportati aggiornamenti all'elenco dei tag su un Asset, le stesse modifiche vengono applicate in modo asincrono a tutti gli oggetti all'interno dell'Asset. La durata di questa attività è direttamente correlata al numero di oggetti contenuti in un riscontro.

**Open-Source:** Se le modifiche ai Tag non vengono osservate entro un periodo di tempo ragionevole, consulta i log del worker celery per identificare dove potrebbero essersi verificati eventuali problemi.


### Filtrare per Tag (interfaccia classica)

I tag possono essere filtrati in molti modi sia tramite l'interfaccia utente sia tramite l'API. Ad esempio, ecco un estratto
dei filtri dei Riscontri:

![Snippet of the finding filters](images/tags-finding-filter-snippet.png)

Ci sono dieci campi relativi ai tag:

 - Tag: filtra su qualsiasi tag associato a un dato Riscontro
   - Esempi:
     - Il Riscontro verrà restituito
       - Tag del Riscontro: ["A", "B", "C"]
       - Query di filtro: "B"
     - Il Riscontro *non* verrà restituito
       - Tag del Riscontro: ["A", "B", "C"]
       - Query di filtro: "F"
 - Non Tag: filtra su qualsiasi tag *non* associato a un dato Riscontro
   - Esempi:
     - Il Riscontro verrà restituito
       - Tag del Riscontro: ["A", "B", "C"]
       - Query di filtro: "F"
     - Il Riscontro *non* verrà restituito
       - Tag del Riscontro: ["A", "B", "C"]
       - Query di filtro: "B"
 - Il Nome del Tag Contiene: filtra su qualsiasi tag che contenga parte o tutta la query nel dato Riscontro
   - Esempi:
     - Il Riscontro verrà restituito
       - Tag del Riscontro: ["Alpha", "Beta", "Charlie"]
       - Query di filtro: "et" (parte di "Beta")
     - Il Riscontro *non* verrà restituito
       - Tag del Riscontro: ["Alpha", "Beta", "Charlie"]
       - Query di filtro: "meg" (parte di "Omega")
 - Non Tag: filtra su qualsiasi tag che *non* contenga parte o tutta la query nel dato Riscontro
   - Esempi:
     - Il Riscontro verrà restituito
       - Tag del Riscontro: ["Alpha", "Beta", "Charlie"]
       - Query di filtro: "meg" (parte di "Omega")
     - Il Riscontro *non* verrà restituito
       - Tag del Riscontro: ["Alpha", "Beta", "Charlie"]
       - Query di filtro: "et" (parte di "Beta")

Per gli altri sei filtri sui tag, valgono le stesse regole di "Tag" e "Non Tag" descritte sopra,
ma a livelli diversi del modello dei dati:

 - Tag (Test): filtra su qualsiasi tag associato al Test di un dato Riscontro
 - Non Tag (Test): filtra su qualsiasi tag *non* associato al Test di un dato Riscontro
 - Tag (Engagement): filtra su qualsiasi tag associato all'Engagement di un dato Riscontro
 - Non Tag (Engagement): filtra su qualsiasi tag *non* associato all'Engagement di un dato Riscontro
 - Tag (Asset): filtra su qualsiasi tag associato all'Asset di un dato Riscontro
 - Non Tag (Asset): filtra su qualsiasi tag *non* associato all'Asset di un dato Riscontro
