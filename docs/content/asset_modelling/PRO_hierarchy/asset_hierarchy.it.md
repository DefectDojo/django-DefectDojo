---
title: Gerarchia degli Asset
description: DefectDojo Pro - Revisione della Gerarchia dei Prodotti
audience: pro
weight: 1
aliases:
- /it/en/working_with_findings/organizing_engagements_tests/pro_assets_organizations
- /it/asset_modelling/pro_hierarchy/assets_organizations
---

DefectDojo Pro sta estendendo le classi di oggetti Prodotto/Product Type per fornire maggiore flessibilità al modello dei dati.

## Abilitare la funzionalità di gerarchia

I due elementi seguenti sono separati e sono controllati con mezzi diversi.

### Gerarchia degli Asset

**Gerarchia degli Asset** abilita le relazioni padre/figlio tra gli Asset. La gerarchia viene visualizzata e gestita dalla scheda **Prodotto** nella navigazione.

La Gerarchia degli Asset è disponibile in generale ed è attiva per ogni istanza, sia Cloud che On-Premise. Non c'è nulla da abilitare, e non è più elencata nella pagina Feature Flags.

### Modifiche alle etichette (opzionale)

**Modifiche alle etichette** rinomina "Product Type" in "Organization" e "Product" in "Asset" in tutta la UI. Questo è un passaggio separato dall'abilitazione della gerarchia e può essere eseguito contemporaneamente o in un secondo momento.

Le modifiche alle etichette sono attive per impostazione predefinita a partire dalla versione 3.0. Ci sono due controlli, che coprono parti diverse dell'applicazione:

* **UI Pro** (la UI predefinita): un superuser attiva "Organization / Asset Relabeling" in **Settings > Feature Flags**, sia sulle istanze Cloud che On-Premise. Le nuove etichette appaiono al caricamento della pagina successiva. Vedi [Feature Flags](/admin/feature_flags/pro__feature_flags/).
* **Pagine della UI classica e report generati**: le loro etichette e URL provengono dall'impostazione di deployment `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`, che viene letta all'avvio di DefectDojo. On-premise, impostala e riavvia DefectDojo. Su [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), invia un'email a [support@defectdojo.com](mailto:support@defectdojo.com) con l'URL della tua istanza.

Entrambe sono attive per impostazione predefinita, e il valore in Feature Flags è stato inizializzato a partire dall'impostazione di deployment, quindi i due valori coincidono a meno che tu non ne modifichi uno. Mantienili sincronizzati se utilizzi sia la UI classica che la UI Pro.

Nota che le modifiche alle etichette sono solo estetiche: gli endpoint API e i nomi dei campi rimangono invariati, quindi l'automazione esistente continuerà a funzionare.

## Modifiche significative

* I **Product Type** sono stati rinominati in "Organizations", e i **Products** sono stati rinominati in "Assets". A partire dalla versione 3.0 questa modifica del nome è attiva per impostazione predefinita. Vedi [Modifiche alle etichette](#label-changes-optional) per i controlli che la disattivano.
* Gli **Asset** possono ora avere relazioni padre/figlio tra loro per suddividere ulteriormente in sotto-categorie i componenti organizzativi.

### Organizations

Come per i Product Type, le **Organizations** dovrebbero essere intese come una categoria di primo livello. Puoi usarle per separare le applicazioni software principali, i reparti o le funzioni aziendali della tua azienda.

Ad esempio, potresti creare un'Organization per molti raggruppamenti di repository: "Core Application", "Infrastructure", "DevOps", "Analytics", "SDK" potrebbero contenere tutti più repository di codice.

Tieni presente che, ai fini della reportistica, è più facile combinare più Organizations in un unico documento che suddividere una singola Organization in documenti separati. Pertanto, raccomandiamo di impostare le Organizations al livello di granularità che ha più senso per i report del tuo team. Ad esempio, non c'è bisogno di rappresentare una grande divisione aziendale come un'Organization se prevedi principalmente di produrre report sui singoli reparti all'interno di quella divisione.

### Assets

Gli Asset hanno lo scopo di rappresentare le suddivisioni delle tue Organizations. Tuttavia, a differenza dei Products, gli Asset possono essere annidati e avere relazioni padre-figlio tra loro.

## Esempi di annidamento degli Asset

### Rappresentazione dei branch a livello di Asset

I branch di sviluppo e delle funzionalità possono essere rappresentati in vari modi; Engagement o Test separati sono modi già esistenti per rappresentare la differenza tra i tuoi branch di Produzione, Sviluppo e altri branch di funzionalità.

Puoi anche rappresentarli utilizzando Asset annidati. Considera il seguente albero di Asset:

```
Core Application [Organization]
└── webapp-frontend
    ├── webapp-frontend/prod
    └── webapp-frontend/dev
        ├── webapp-frontend/dev/feature-a
        └── webapp-frontend/dev/feature-b
```

In questo ambiente, ogni branch (`prod`, `dev`, `feature a`, `feature b`) potrebbe avere i propri Engagement e Test isolati dagli altri Asset, in modo che non si deduplichino tra loro. Questa configurazione può anche facilitare la navigazione, poiché i nomi degli Asset possono corrispondere direttamente al percorso su Git.

### Mono-Repo: componenti separati

Se utilizzi un unico repository per tutto il tuo codice, ma hai team diversi che contribuiscono a directory all'interno di quel repository, puoi impostare l'annidamento dei tuoi Asset per rappresentare quella struttura.

```
Core Application [Organization]
├── webapp-frontend [Parent Asset]
│   ├── mobile-ios
│   ├── mobile-android
│   └── mobile-sdk
├── webapp-backend [Parent Asset]
│   ├── database
│   └── api
└── infra [Parent Asset]
    ├── docker
    ├── kubernetes
    └── nginx
```

In questo diagramma, ogni elemento sotto "Core Application" potrebbe essere registrato come un Asset separato, con una propria criticità aziendale (vedi: [Priorità e Rischio](/asset_modelling/pro_hierarchy/priority_sla/#prioritization-engines)), RBAC, ed Engagement e Test corrispondenti. Potresti continuare a testare e archiviare i risultati sull'Asset padre (ad esempio, `webapp-backend`), ma potresti anche eseguire test isolati su un particolare Asset figlio (ad esempio, `database`).

### Pen Test: RBAC isolato

Se vuoi archiviare i risultati dei pen test all'interno di un singolo asset, ma non vuoi che i tester possano visualizzare i dati dell'asset, puoi creare asset figli per ogni gruppo di test in cui caricare i propri risultati.

```
Core Application [Organization]
└── webapp-frontend [Parent Asset]
    ├── Pen Test Group A
    └── Pen Test Group B
```

Cosa fondamentale, concedere a un utente l'accesso RBAC a un singolo Asset figlio (ad es. `Pen Test Group A`) qui non gli consente di vedere alcun Riscontro degli altri Asset figli (ad es. `Pen Test Group B`), né gli consente di vedere i Riscontri nell'Asset padre (`webapp-frontend`).

L'Asset padre potrebbe contenere Engagement che rappresentano risultati CI/CD, test interni, dati storici o altri dati sui Riscontri che non vuoi che terze parti possano scoprire. Creare un Asset figlio per risultati di Test specifici consente al tuo team interno di produrre report su quei risultati in combinazione con lo stato dell'Asset padre.

## Visualizzare gli Asset - Gerarchia

Puoi visualizzare la struttura degli Asset in DefectDojo e modificare le relazioni utilizzando l'opzione Asset Hierarchy nel menu.

![image](images/asset_hierarchy.png)

Aprendo Asset Hierarchy verrà visualizzata una tabella di tutti i tuoi Asset che può essere filtrata. Selezionando uno o più Asset da questa tabella verrà visualizzato un diagramma della gerarchia.

![image](images/asset_hierarchy_diagram.png)

### Navigazione del diagramma

Le icone in alto a sinistra del diagramma della gerarchia consentono di ingrandire e rimpicciolire la vista. Cliccando e trascinando in questo diagramma è possibile scorrerlo.

Ogni Asset viene rappresentato come un singolo nodo in questo diagramma, che può essere spostato per motivi di visualizzazione.

Gli Asset sono collegati tra loro tramite percorsi etichettati, che rappresentano il tipo di relazione che ogni nodo ha con l'altro. Attualmente, `parent` è l'unica etichetta supportata.

### Esplorare i nodi Asset

Ogni nodo Asset può essere utilizzato cliccando sui pulsanti blu. Questi pulsanti appaiono solo quando un nodo Asset è selezionato (cliccando sul nodo).

![image](images/asset_hierarchy_node.png)

* 👁️ (icona occhio) ti porterà direttamente alla vista Asset corrispondente (precedentemente nota come vista Prodotto).
* ✏️ (icona matita) aprirà una finestra modale con il modulo Modifica Asset (precedentemente noto come modulo Modifica Prodotto)
* ➕ (icona più) ti permetterà di aggiungere un nuovo Asset figlio a questo Asset. L'Asset non deve essere necessariamente visibile nel diagramma, ma deve far parte della stessa Organization.
* ✥ (icona quattro frecce) consente di modificare l'Asset padre dell'Asset attualmente selezionato.
* 🗑️ (icona cestino) consente di rimuovere la relazione padre di un Asset. Questa icona appare solo se un Asset ha già un padre.

Se il tuo diagramma mostra un Asset con Asset padre non selezionati, puoi cliccare sul pulsante Load More per popolare il diagramma con l'Asset padre (così come i figli di quell'Asset padre).

![image](images/assets_loadmore.png)

## Note

* Nota che gli ambiti di deduplicazione non sono cambiati; gli Asset deduplicano i Riscontri solo al proprio interno, e non considerano i Riscontri in altri Asset, indipendentemente dalle relazioni Padre/Figlio.
* Gli ambiti RBAC non sono cambiati in questo sistema; ogni Asset è ancora considerato un oggetto individuale ai fini dell'assegnazione dei permessi. Non è stata creata alcuna nuova ereditarietà RBAC.
  * Concedere a un utente l'accesso a un'intera Organization gli darà comunque accesso a tutti gli Asset contenuti in quella Organization (come per i Product Type).
  * Concedere a un utente l'accesso a un singolo Asset non gli dà accesso ad alcun Asset padre o figlio correlato, né accesso all'Organization.
* Non c'è alcun limite al numero di relazioni Padre/Figlio che possono essere create. Teoricamente, potresti rappresentare l'intera struttura di directory di un repository con Asset separati, se lo desiderassi.
* Le relazioni cicliche non sono consentite: gli Asset padre non possono essere figli dei loro Asset figli.
