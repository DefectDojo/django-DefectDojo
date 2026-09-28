---
title: Organizzazioni
description: Comprendere le Organizzazioni in DefectDojo OS
audience: opensource
weight: 1
aliases:
- /it/asset_modelling/engagements_tests/os_producttype/
- /it/en/asset_modelling/engagements_tests/os_producttype/
---

**ORGANIZZAZIONI** → Asset → Engagement → Test → Riscontri

## Panoramica

Le **Organizzazioni** si trovano al vertice della gerarchia degli oggetti di DefectDojo. Le Organizzazioni si distinguono dagli oggetti discendenti della gerarchia—Asset, Engagement, Test e Riscontri—perché non sono obiettivi tecnici di scansione, ma servono principalmente come astrazioni organizzative che suddividono i vostri sforzi di sicurezza in base a:
- Ambito aziendale
- Team di sviluppo
- Team di sicurezza
- Applicazioni software
- Famiglia di prodotto generale
- Cliente o filiale
- Struttura di reporting
- ecc.

Il filo conduttore degli esempi precedenti illustra l'utilità essenziale delle Organizzazioni: in genere dovrebbero rappresentare confini stabili e di lunga durata all'interno del vostro programma di sicurezza.

## Dati e struttura dell'Organizzazione

Poiché le Organizzazioni non vengono scansionate direttamente, l'unico campo obbligatorio per crearle è il nome. Al di là di questo, fungono da contenitori per gli Asset e per gli Engagement, i Test e i Riscontri che ne discendono.

Quando create un'Organizzazione, considerate come la sua struttura influenzerà il vostro reporting. Avete principalmente bisogno che le Organizzazioni rappresentino i team che lavorano sui progetti (Asset) che le Organizzazioni conterranno? Oppure le Organizzazioni rappresenterebbero meglio progetti generali che contengono al loro interno diverse iterazioni dei progetti (Asset)?

Se avete un'unica Organizzazione che contiene tutte le informazioni rilevanti per un dato ambito aziendale o team di sviluppo, rappresentarla come un'Organizzazione faciliterà un reporting più fluido, invece di dover assemblare un report a partire da vari Asset e Organizzazioni.

Se un particolare progetto software presenta molte distribuzioni o versioni distinte, può valere la pena creare un'unica Organizzazione che copra l'ambito dell'intero progetto e far sì che ogni versione esista come Asset individuali. In alcuni flussi di lavoro, le Organizzazioni possono anche essere usate per separare le fasi del ciclo di vita del software: un'Organizzazione per “In sviluppo”, un'Organizzazione per “In produzione”, ecc.

Le Organizzazioni possono essere usate per determinare l'accesso a filiali, società acquisite o altre unità aziendali regolamentate ai fini RBAC. Nelle aziende complesse, dove esistono molti progetti unici con regole di accesso diverse, le Organizzazioni sono particolarmente rilevanti.

In definitiva, la decisione su come usare Organizzazioni e Asset dipende da come preferite riflettere la vostra struttura organizzativa unica e le esigenze del vostro team di sicurezza.

Di seguito alcuni esempi di struttura per orientarvi su come designare i vostri oggetti come Organizzazioni o Asset.

- **Organizzazione**: Divisione Pagamenti
    - Asset: Payments API - Produzione
    - Asset: Payments API - Staging
    - Asset: Billing Worker

- **Organizzazione**: Prodotto Software A
    - Asset: Portale Web
    - Asset: Backend Mobile

Inoltre, la seguente è una guida illustrativa per capire se qualcosa è meglio rappresentato da un'Organizzazione o da un Asset:

| Organizzazioni | Asset |
|--------------|--------|
| Unità aziendali | Applicazioni individuali |
| Dipartimenti | Distribuzioni/ambienti |
| Domini di responsabilità della sicurezza | Componenti infrastrutturali |
| Famiglie di prodotto | Microservizi specifici |
| Reporting a livello di portafoglio | Obiettivi di scansione |
| Clienti | Versioni software specifiche |

Come indicato, la vostra struttura potrebbe differire a seconda delle vostre esigenze di sicurezza specifiche.

## Accesso alle Organizzazioni

Le Organizzazioni sono accessibili tramite la barra laterale. Il sottomenu offre anche l'opzione per creare nuove Organizzazioni.

![image](images/organization_ss1.png)

### Vista Organizzazione

La vista di un'Organizzazione contiene diverse tabelle e grafici per interpretarne lo stato a colpo d'occhio. Questi includono:
- **Descrizione**
- **Casella Key/Critical**
    - Selezionare Critical o Key serve esclusivamente a scopi di filtraggio
- **Elenco degli Asset all'interno dell'Organizzazione**
- **Utenti autorizzati** (Utenti DefectDojo)

## Lavorare con le Organizzazioni

### Creare Organizzazioni

Esistono due modi per creare Organizzazioni:

- Dall'opzione **Add Organization** nel menu laterale
- Dal pulsante **Add Organization** in cima all'elenco All Organizations

### Modificare le Organizzazioni

Le Organizzazioni possono essere modificate facendo clic su **Edit** dal menu a discesa in alto a destra della tabella Description nella vista dell'Organizzazione. Lo stesso menu è accessibile anche facendo clic sul menu kebab ⋮ a sinistra dell'Organizzazione nell'elenco All Organizations.

Tutti i campi modificabili di seguito sono disponibili anche durante la creazione dell'Organizzazione.

### Eliminare le Organizzazioni

È possibile eliminare un'Organizzazione selezionando **Delete Organization** dalle impostazioni dell'Organizzazione.

Poiché le Organizzazioni si trovano al vertice della gerarchia, la loro eliminazione rimuove tutta la cronologia di sicurezza, le relazioni e gli oggetti figli a valle, tra cui:
- Qualsiasi Asset, Engagement e Test contenuto nell'Organizzazione
- Tutta la cronologia di sicurezza associata, inclusi Riscontri e integrazioni
- Eventuali Epic Jira collegate
- Tutte le note e i file caricati associati agli Asset, agli Engagement e ai Test all'interno di quell'Organizzazione

L'eliminazione di un'Organizzazione non può essere annullata. Se desiderate “dismettere” un'Organizzazione senza eliminare i dati sottostanti (ad esempio, per conservare i registri di test software legacy a fini di audit), potete cambiare il nome dell'Organizzazione o aggiungere un Tag per indicare che si trova in uno stato deprecato.

## Organizzazioni vs. Metadati

Le Organizzazioni hanno lo scopo di rappresentare la responsabilità strutturale o i confini di reporting, non classificazioni leggere. Attributi come lo stato di distribuzione, le etichette interne o gli stati di workflow temporanei potrebbero essere meglio rappresentati tramite tag o metadati piuttosto che da Organizzazioni separate.

## Confini delle Organizzazioni

Le Organizzazioni stabiliscono sia i confini di reporting sia quelli di accesso all'interno di DefectDojo. Poiché integrazioni, permessi RBAC, proprietà, metriche e modelli di deduplicazione ereditano spesso la struttura delle Organizzazioni, progettare confini chiari fin dall'inizio aiuta a evitare una proliferazione della gerarchia e una frammentazione del reporting in seguito.

### Riscontri e automazione

Sebbene le integrazioni siano tipicamente configurate su oggetti di livello inferiore come Asset, Engagement o Riscontri, le Organizzazioni definiscono comunque i confini di proprietà, reporting e accesso entro cui tali integrazioni operano.

I permessi si propagano verso il basso, il che significa che l'accesso a un'Organizzazione concede automaticamente l'accesso a tutti gli oggetti al suo interno (ad es. Asset, Engagement, Test e Riscontri).

Il modello RBAC di DefectDojo può essere usato per limitare l'accesso degli utenti umani, ma può anche limitare l'accesso dei token API a particolari Organizzazioni.

Per maggiori informazioni sui ruoli utente, consultate il nostro articolo [Permessi](/admin/user_management/os__authorized_users/).

### Proprietà

In quanto oggetti di primo livello, le Organizzazioni implicano anche la proprietà sugli oggetti figli al loro interno. Il monitoraggio degli SLA, i workflow di remediation, l'instradamento dei ticket e la governance generale funzionano in modo più fluido quando le Organizzazioni sono state configurate per riflettere accuratamente le persone responsabili di esse.

### Metriche/Reporting

Le dashboard delle metriche, i riquadri e le viste possono essere filtrati per Organizzazione, il che le rende una componente critica del modo in cui i vostri dati di sicurezza vengono calcolati, visualizzati e infine esportati.

Ai fini del reporting, in genere è più semplice combinare più Organizzazioni in un unico documento che suddividere una singola Organizzazione in documenti separati. Pertanto, consigliamo di impostare le Organizzazioni al livello di granularità più adatto ai report del vostro team. Ad esempio, non è necessario rappresentare una grande divisione aziendale come un'Organizzazione se farete principalmente report verso i singoli dipartimenti al suo interno.

Strutturare efficacemente le vostre Organizzazioni in modo da riflettere le vostre esigenze di reporting è fondamentale per valutare accuratamente la vostra postura di sicurezza. Per maggiori informazioni sulle Metriche, fate clic [qui](/metrics_reports/dashboards/introduction_dashboard/).

### Deduplicazione

La deduplicazione in DefectDojo avviene a livello di Asset e non è influenzata dall'Organizzazione principale.
