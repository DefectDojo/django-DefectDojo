---
title: Dashboard personalizzabili
description: Crea dashboard personalizzate in DefectDojo Pro a partire da widget disposti
  su una griglia drag-and-drop
draft: false
audience: pro
weight: 10
slug: custom-dashboards
aliases:
- /it/en/customize_dojo/dashboards/about_custom_dashboard_tiles
- /it/metrics_reports/dashboards/about_custom_dashboard_tiles
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: le Dashboard personalizzabili (layout, widget e catalogo widget) sono una funzionalità di DefectDojo Pro. Sono disattivate per impostazione predefinita — un Superuser può attivarle da **Impostazioni > Feature Flags** sia su Cloud che su istanze On-Premise.</span>

Le Dashboard personalizzabili di DefectDojo Pro consentono a ogni utente di comporre la propria home page a partire da **widget** — conteggi, grafici, classifiche, feed e note — disposti su una griglia drag-and-drop. Invece di un'unica dashboard fissa per tutti, costruisci i **layout** che contano per te: una panoramica esecutiva, una coda di triage, una board sulla velocità di remediation, una vista sull'efficacia degli scanner. Puoi mantenere i layout privati, pubblicarli per l'intero team, impostarne uno come pagina di destinazione predefinita e clonare qualsiasi layout (tuo o un template condiviso) come punto di partenza.

![Una dashboard personalizzabile di DefectDojo Pro — il layout Default Dashboard.](images/pro_dashboard_v2_default.png)

## Confronto con la versione open source

DefectDojo open source dispone di un'unica [Dashboard principale](../introduction_dashboard/) integrata, con un insieme fisso di schede di riepilogo e grafici che un superuser può mostrare o nascondere. È identica per ogni utente.

DefectDojo Pro sostituisce quella pagina fissa con **dashboard personalizzabili per singolo utente**. Scegli quali widget compaiono, come vengono filtrati e dove sono posizionati sulla griglia. Puoi creare un numero qualsiasi di layout con nome, passare dall'uno all'altro, condividerli con il tuo team e gestire l'intero sistema tramite la [REST API](../custom-dashboards-api/) o un [LLM](../custom-dashboards-llm/).

> **💡 Tip:** In DefectDojo Pro, gli **Asset** erano precedentemente chiamati **Prodotti** e le **Organizzazioni** erano precedentemente **Tipi di prodotto**. L'interfaccia utilizza la nuova terminologia, ma alcune impostazioni sottostanti dei widget usano ancora i nomi legacy — ad esempio, la maggior parte dei widget accetta un `model` pari a `finding`, `product`, `engagement`, o `test`. Dove ciò è rilevante, viene indicato di seguito.

## Attivare le Dashboard personalizzabili

Le Dashboard personalizzabili sono disattivate per impostazione predefinita. Un superuser può attivarle da **Impostazioni > Feature Flags**, sia su Cloud che su istanze On-Premise. Consulta [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Una volta attivata, la pagina **🏠 Home** mostra la tua dashboard personalizzabile e la [REST API delle Dashboard](../custom-dashboards-api/) diventa disponibile.

> **🔑 Important:** Finché la funzionalità è disattivata, la home page mantiene la dashboard precedente e ogni endpoint `/api/v2/dashboards/` restituisce `403 Dashboards 2.0 is not enabled.` L'attivazione **non** modifica in alcun modo l'accesso ai dati di nessuno — ogni widget continua a rispettare il controllo degli accessi basato sui ruoli di DefectDojo, quindi ogni utente vede sempre e solo i Riscontri, gli Asset e gli altri record che è autorizzato a visualizzare.

## Concetti fondamentali

Una dashboard personalizzabile è costruita a partire da alcuni elementi semplici.

### Layout

Un **layout** è una dashboard con un nome: un insieme di widget e delle relative posizioni sulla griglia. Ogni layout ti appartiene e puoi averne quanti ne vuoi — ad esempio una board "Triage giornaliero" e una separata "Panoramica esecutiva". Un layout memorizza tre elementi:

- **widgets** — l'elenco ordinato dei widget contenuti, ciascuno con il proprio tipo, titolo e configurazione.
- **layout** — la posizione e le dimensioni di ciascun widget sulla griglia.
- **settings** — opzioni di visualizzazione a livello di layout.

La prima volta che apri le Dashboard personalizzabili, DefectDojo ti fornisce una copia personale del template di partenza **Default Dashboard**, così non ti trovi mai davanti a una pagina vuota.

### Widget

Un **widget** è un singolo pannello sulla dashboard. Ogni widget è un'istanza di un **tipo** presente nel catalogo (un Count, un Graph, una Top-N Leaderboard e così via), e possiede una propria **configurazione**: quale **model** di dati legge (`finding`, `product`, `engagement`, o `test`), quali **filtri** lo delimitano, e opzioni di visualizzazione specifiche per tipo, come il tipo di grafico, i colori o il raggruppamento. Due widget dello stesso tipo con filtri diversi sono completamente indipendenti.

Ogni widget dispone inoltre di un **intervallo di aggiornamento automatico** opzionale (disattivato, 30 secondi, 1 minuto, 5 minuti o 15 minuti) e di un **titolo** modificabile.

### Il catalogo widget

Il **catalogo** è il menu fisso dei tipi di widget supportati dalla piattaforma, raggruppati in quattro categorie — **Numeri**, **Grafici**, **Elenchi e feed** e **Statici e utilità**. Quando aggiungi un widget, ne scegli il tipo dal catalogo. Il catalogo è disponibile anche tramite [API](../custom-dashboards-api/), così script e LLM possono scoprire i tipi di widget disponibili e una configurazione di partenza valida per ciascuno. Consulta [Il catalogo widget](#the-widget-catalog-1) più avanti per l'elenco completo.

### La griglia

I widget vengono posizionati su una **griglia a 12 colonne**. In modalità di modifica puoi trascinare i widget per spostarli e trascinare l'angolo in basso a destra per ridimensionarli; la griglia si compatta verso l'alto per colmare gli spazi vuoti. Ogni tipo di widget ha dimensioni minime e massime sensate, in modo che grafici e tabelle restino leggibili.

### Condivisione, clonazione e impostazioni predefinite

- **Predefinito** — uno dei tuoi layout è il tuo layout **predefinito**: quello che viene caricato quando apri la home page. Puoi cambiare in qualsiasi momento quale layout è il tuo predefinito.
- **Clona** — copia qualsiasi layout (uno dei tuoi o un template condiviso) nel tuo spazio personale come nuovo punto di partenza indipendente. La clonazione assegna alla copia i propri widget, quindi modificare il clone non tocca mai l'originale.
- **Condividi** — pubblica uno dei tuoi layout per l'intero team come **layout condiviso**. Gli altri utenti possono vederlo e clonarlo, ma solo un **Maintainer** del team può pubblicare, modificare o annullare la condivisione di un layout condiviso. Condividere un layout ne condivide solo il *design* — ogni utente continua a vedere solo i dati che le proprie autorizzazioni consentono.
- **Template di partenza e condivisi** — DefectDojo fornisce un insieme selezionato di **template condivisi** che puoi clonare per partire avvantaggiato (vedi [Template condivisi](#shared-templates) più avanti). Il **Default Dashboard** è il template speciale "di partenza" assegnato automaticamente ai nuovi utenti.

## Creare una dashboard nell'interfaccia

### La barra degli strumenti della dashboard

La barra degli strumenti nella parte superiore della home page è il punto in cui puoi cambiare layout e gestirli. Include un **selettore di layout** (con badge che indicano il tuo layout predefinito ed eventuali layout/template condivisi), oltre a pulsanti per creare un **Nuovo layout**, aprire **Gestisci layout**, **Aggiornare** tutti i widget e attivare la modalità **Modifica**.

![La barra degli strumenti della dashboard (evidenziata): il selettore di layout, oltre a Nuovo layout, Gestisci layout, Aggiorna e Modifica](images/pro_dashboard_v2_home.png)

### Passaggio 1: attivare la modalità di modifica

Fai clic su **Modifica** per sbloccare la dashboard. La griglia diventa trascinabile e ridimensionabile e appare un pulsante **Aggiungi widget**. Fai clic su **Fatto** al termine — la modalità di modifica si disattiva automaticamente anche quando cambi layout.

![Una dashboard in modalità di modifica, con le maniglie di trascinamento e ridimensionamento](images/pro_dashboard_v2_edit_grid.png)

### Passaggio 2: aggiungere un widget

In modalità di modifica, fai clic su **Aggiungi widget** per aprire il selettore. Sono presenti due schede:

- **Per tipo** — sfoglia il catalogo per categoria (Numeri, Grafici, Elenchi e feed, Statici e utilità). Ogni scheda mostra il nome del widget e una breve descrizione. Selezionandone uno lo aggiungi alla griglia e ne apri la finestra di configurazione.
- **Dal catalogo** — parti da un widget preconfigurato ripreso da uno dei template condivisi (ad esempio, il grafico "Riscontri per gravità" del Default Dashboard). Questi arrivano già configurati, quindi si posizionano direttamente sulla griglia.

![La finestra di dialogo Aggiungi widget, scheda Per tipo](images/pro_dashboard_v2_add_widget.png)

### Passaggio 3: configurare il widget

Ogni widget apre una finestra di configurazione adattata al proprio tipo. Le impostazioni comuni includono:

- **Titolo** — l'intestazione mostrata sul widget.
- **Model** — quali record legge il widget (Riscontro, Asset, Engagement o Test), ove applicabile.
- **Filtri** — un'interfaccia di filtro integrata, simile a quella delle viste a elenco, che delimita il widget esattamente ai record desiderati (ad esempio, i Riscontri attivi con gravità Critica). I filtri scelti qui sono gli stessi che useresti nella pagina a elenco di quell'oggetto.
- **Intervallo di aggiornamento** — con quale frequenza il widget si ricarica automaticamente.
- **Opzioni specifiche per tipo** — ad esempio il tipo di grafico e la dimensione di raggruppamento per un Graph, le soglie per un Gauge, o la metrica per una Top-N Leaderboard.

![Configurazione di un widget Graph](images/pro_dashboard_v2_widget_config.png)

> **💡 Tip:** I dati di un widget rispettano sempre le tue autorizzazioni. Se un layout condiviso include un widget "My Work", ogni utente vede *i propri* incarichi e menzioni — non quelli dell'autore del layout.

### Passaggio 4: disporre e salvare

Trascina i widget per riorganizzarli e trascina un angolo per ridimensionarli. Usa l'icona a forma di ingranaggio su un widget per riconfigurarlo e l'icona del cestino per rimuoverlo. Le modifiche di posizione e dimensione vengono salvate automaticamente man mano che procedi. Fai clic su **Fatto** per uscire dalla modalità di modifica.

### Gestione dei layout

La finestra di dialogo **Gestisci layout** (il pulsante a forma di ingranaggio sulla barra degli strumenti) è il punto centrale per tutto ciò che riguarda i layout:

- **I tuoi layout** — rinomina, imposta come predefinito, condividi/annulla la condivisione, clona o elimina ciascun layout di tua proprietà.
- **Crea nuovo** — avvia un layout nuovo e vuoto da costruire da zero.
- **Template condivisi** — sfoglia i layout curati e pubblicati dal team, raggruppati per categoria, e fai clic su **Usa layout** per clonarne uno nel tuo spazio personale.

![La finestra di dialogo Gestisci layout](images/pro_dashboard_v2_manage_layouts.png)

### Template condivisi

DefectDojo fornisce quattro template condivisi pronti all'uso che puoi clonare come punto di partenza:

| Template | Scopo |
|----------|---------|
| **Default Dashboard** | La vista home classica — 12 conteggi a colpo d'occhio, grafici di gravità e Asset con valutazione più alta/più bassa. È il template di partenza assegnato automaticamente a ogni nuovo utente. |
| **Priority Layout** | Una board orientata al triage, costruita attorno a priorità e rischio dei Riscontri. |
| **Mitigation Layout** | Una board sulla velocità di remediation (tendenze di chiusura, MTTR/MTTD, invecchiamento). |
| **Tool Layout** | Una board sull'efficacia degli scanner, costruita attorno ai tipi di test e all'attività di scansione recente. |

> **💡 Tip:** Clonare un template crea una copia indipendente. Personalizza liberamente il clone — non influirai sul template né su chiunque altro lo clonerà.

### Lo stato vuoto

Un layout appena creato senza widget mostra un messaggio **"Crea la tua prima dashboard"**. Fai clic su **Aggiungi il tuo primo widget** per passare direttamente alla modalità di modifica e iniziare a scegliere i widget.

![Lo stato di layout vuoto](images/pro_dashboard_v2_empty_state.png)

## Il catalogo widget

Le Dashboard personalizzabili includono i seguenti tipi di widget, organizzati in quattro categorie. La maggior parte dei widget legge uno di quattro model — `finding`, `product` (Asset), `engagement`, o `test` — e viene delimitata dai filtri che scegli. Le opzioni di configurazione complete per ciascun widget sono documentate nella [guida API](../custom-dashboards-api/).

### Numeri

Metriche a colpo d'occhio — conteggi, KPI e indicatori.

| Widget | Cosa mostra |
|--------|---------------|
| **Count** | Un singolo numero ricavato da una query filtrata — ad es. "Riscontri Critici aperti" o "Engagement attivi". Funziona con finding / asset / engagement / test. |
| **KPI / Trend** | Un numero principale insieme alla sua variazione rispetto al periodo precedente, con uno sparkline opzionale. |
| **Gauge** | Un rapporto rappresentato come indicatore ad arco — un filtro "universo" come denominatore e un filtro "superato" come numeratore. Utile per la conformità agli SLA, il tasso di mitigazione o la copertura delle scansioni, con soglie di avviso/OK configurabili. |
| **License Usage** | Lo stato di utilizzo della licenza del tuo account, con una suddivisione per segnale (dimensione del database, volume settimanale di Riscontri e così via). *Richiede il ruolo Maintainer.* |
| **Scan Coverage** | Quale frazione degli asset è stata sottoposta a scansione negli ultimi 30 / 90 / 180 / 365 giorni, come riepilogo su più finestre temporali. |

### Grafici

Visualizzazioni di serie temporali e distribuzioni.

| Widget | Cosa mostra |
|--------|---------------|
| **Graph** | Un grafico generico su qualsiasi model e dimensione di raggruppamento — a barre, a linee, ad area, a torta o a ciambella. Ad es. Riscontri per gravità, Riscontri per mese. |
| **Sankey** | Un diagramma di flusso da una dimensione di origine a una dimensione di destinazione — ad es. Gravità → Stato. |
| **Sunburst** | Una suddivisione radiale a uno o due livelli — ad es. Gravità, poi Tipo di test all'interno di ciascuna gravità. |
| **Risk Matrix** | Una heatmap dei riscontri basata su probabilità EPSS × rischio — sicuro in basso a sinistra, pericoloso in alto a destra. |
| **Priority Histogram** | La distribuzione dei punteggi di **priorità** dei riscontri calcolati dal motore di prioritizzazione, suddivisa automaticamente in intervalli. |
| **Rate by Category** | Un rapporto per categoria (numeratore / denominatore) — ad es. Tasso di falsi positivi per strumento o Tasso di mitigazione per asset. |
| **Finding Velocity** | Riscontri creati rispetto a quelli chiusi nel tempo, per mostrare se l'arretrato sta crescendo o diminuendo. |
| **MTTR / MTTD** | Tempo medio di remediation e tempo medio di rilevamento, come serie temporali abbinate. |
| **Vulnerability Aging** | Riscontri aperti suddivisi per fascia di età (0–30 gg / 30–90 gg / 90–180 gg / oltre 180 gg), impilati per gravità. |
| **Activity Heatmap** | Un calendario in stile GitHub dell'attività giornaliera su una finestra temporale mobile. |
| **Portfolio Treemap** | Rettangoli annidati per un riepilogo del portfolio (Organizzazione → Asset), dimensionati in base al conteggio e colorati in base alla gravità. |

### Elenchi e feed

Elenchi classificati, feed e tabelle integrate.

| Widget | Cosa mostra |
|--------|---------------|
| **Top-N Leaderboard** | Un elenco classificato in una di due modalità: *aggregata* (i principali raggruppamenti per dimensione in base al conteggio, ad es. le prime 10 CWE) oppure *record* (i principali record singoli in base a una metrica, ad es. i primi 10 Asset per valutazione). |
| **Embedded Table** | Una vista a elenco completa (Riscontri, Asset, Engagement, Test, Accettazioni del rischio, Organizzazioni o Tipi di test) con filtri e ordinamento preimpostati — paginazione, ordinamento ed esportazione CSV inclusi. |
| **Recent Activity** | Un feed scorrevole dei record aggiornati più di recente, con collegamento diretto alle pagine di dettaglio. |
| **SLA Burndown** | Riscontri prossimi al superamento dello SLA, classificati per giorni rimanenti, con badge di conto alla rovescia. |
| **My Work** | La tua coda personale — incarichi, menzioni e revisioni di accettazione del rischio in sospeso. Sempre delimitata all'utente che la visualizza. |
| **Saved Reports** | Accesso con un clic ai tuoi Template di report salvati. *Richiede la funzionalità Reporting.* |

### Statici e utilità

Note, scorciatoie e struttura.

| Widget | Cosa mostra |
|--------|---------------|
| **Favorites** | Collegamenti rapidi curati dall'utente verso pagine specifiche dell'app. |
| **Section Break** | Un separatore etichettato per raggruppare widget correlati sotto un'intestazione. |
| **Markdown / Notes** | Un pannello di testo formattato inline per intestazioni, note di contesto o link di riferimento. |
| **Quick Actions** | Pulsanti di azione con un clic che portano a una pagina scelta. |

## Prossimi passi

- **[Automatizzare le dashboard con l'API](../custom-dashboards-api/)** — scopri il catalogo widget, crea e aggiorna i layout e visualizza i dati dei widget tramite la REST API, con uno script completo.
- **[Creare dashboard con un LLM](../custom-dashboards-llm/)** — lascia che un LLM progetti e costruisca le dashboard al posto tuo (l'API delle dashboard è stata realizzata pensando agli agenti AI).
