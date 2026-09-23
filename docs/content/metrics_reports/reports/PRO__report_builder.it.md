---
title: Generatore di report
description: Creare report personalizzati e riutilizzabili in DefectDojo Pro con Temi,
  Blocchi e Template
draft: false
audience: pro
weight: 20
slug: report-builder
aliases:
- /it/en/share_your_findings/pro_reports/using_the_report_builder
- /it/metrics_reports/reports/using_the_report_builder
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: il Generatore di report riutilizzabile (Temi, Blocchi, Template e Report generati salvati) è una funzionalità di DefectDojo Pro, attualmente in beta.</span>

Il Generatore di report di DefectDojo Pro consente di comporre report curati a partire da parti riutilizzabili, in modo da creare gli elementi una sola volta e riutilizzarli ovunque, invece di ricostruire un report da zero ogni volta. Vi si accede dall'area **📄 Reporting** nella barra laterale.

## Confronto con la versione open source

DefectDojo open source consente di creare un report, eseguirlo e recuperarne l'output, ma **non** salva i template dei report né mantiene persistenti i report generati. Ogni report è un'attività da svolgere una tantum.

DefectDojo Pro trasforma il reporting in blocchi riutilizzabili. È possibile salvare **Temi**, **Blocchi** e **Template** che possono essere combinati, abbinati e riutilizzati, e ogni report eseguito viene mantenuto come **Report generato** che può essere scaricato o rieseguito in seguito. Pro espone inoltre l'intero flusso di lavoro tramite una API REST completa e supporta la creazione assistita da LLM, così i report possono essere creati ed eseguiti in modo programmatico.

> **💡 Suggerimento:** se si utilizza DefectDojo open source, vedere invece il [generatore di report open source](../using-the-report-builder/).

## Concetti fondamentali

Il Generatore di report è composto da quattro elementi, ciascuno disponibile come risorsa REST sotto `/api/v2/`: `report_themes`, `report_blocks`, `report_templates` e `generated_reports`. Comprendere come si combinano tra loro è la chiave per creare report in modo efficiente.

### Temi

Un **Tema** controlla lo stile visivo e il branding di un report: i colori, le immagini di intestazione e piè di pagina e il testo del piè di pagina. Definendo un Tema una sola volta, è possibile applicare un branding aziendale coerente a ogni report prodotto.

Un Tema dispone delle seguenti impostazioni:

| Impostazione | Scopo | Predefinito |
|---------|---------|---------|
| Name | Un'etichetta per il Tema | — |
| Primary color | Colore principale del brand | `#1e3a5f` |
| Secondary color | Colore secondario di supporto | `#4a90a4` |
| Accent color | Colore di evidenziazione | `#e67e22` |
| Text color | Colore del testo del corpo | `#333333` |
| Background color | Colore di sfondo della pagina | `#ffffff` |
| Footer text | Testo visualizzato nel piè di pagina | — |
| Show page numbers | Se stampare o meno i numeri di pagina | Attivo |
| Header image | Immagine visualizzata nell'intestazione | — |
| Footer image | Immagine visualizzata nel piè di pagina | — |

> **💡 Tip:** tutti e cinque i colori sono espressi come valori esadecimali a 7 caratteri (ad esempio `#1e3a5f`), in modo da poter corrispondere esattamente alla palette del brand della propria organizzazione.

È possibile crearlo tramite l'interfaccia utente (di seguito) oppure automatizzarlo con l'[API](../report-builder-api/).

### Blocchi

Un **Blocco** è un'unità di contenuto riutilizzabile. Si crea un Blocco una sola volta, si configura cosa deve mostrare e poi lo si inserisce in tutti i Template desiderati. Esistono quattro tipi di blocco:

| Tipo di blocco | Cosa produce |
|------------|------------------|
| **Stock** | Contenuto non basato sui dati, come una copertina, un sommario, un'interruzione di pagina, un'immagine o un blocco di testo. |
| **Tabular** | Una tabella di record tratti da una singola entità. |
| **Detail** | Un layout per singolo record, ideale per campi lunghi che vengono visualizzati in formato markdown (ad esempio descrizione, impatto, mitigazione e riferimenti). |
| **Chart** | Grafici visivi. *Prossimamente* — questo tipo di blocco è definito nel modello dati ma non è ancora disponibile nell'API o nell'interfaccia utente. |

Un blocco **Stock** viene configurato scegliendo uno dei cinque tipi stock, insieme a un titolo, un sottotitolo, un contenuto testuale o un'immagine, a seconda dei casi:

- **Cover page**
- **Table of contents**
- **Page break**
- **Image**
- **Text block**

I blocchi **Tabular** e **Detail** recuperano entrambi record live da una singola entità. Si sceglie l'entità tramite una selezione del modello, quindi si selezionano i campi da includere e l'ordine dei record. La scelta del modello corrisponde esattamente a una di queste sette entità:

- **Organization**
- **Asset**
- **Engagement**
- **Test**
- **Finding**
- **Test type**
- **Risk acceptance**

> **💡 Tip:** in DefectDojo Pro, gli **Asset** erano precedentemente chiamati **Prodotti** e le **Organizzazioni** erano precedentemente **Tipi di prodotto**. È possibile imbattersi ancora nella terminologia precedente in alcuni nomi di campo e filtro sottostanti.

La differenza sta nella presentazione: un blocco **Tabular** dispone i record in una tabella di colonne, ideale per riepiloghi e inventari, mentre un blocco **Detail** visualizza un record alla volta in un layout esteso, più adatto a campi ricchi di markdown come descrizione, impatto, mitigazione e riferimenti.

> **💡 Tip:** i filtri risiedono nel Blocco, non nel Template. Un Blocco porta con sé i propri filtri, quindi riutilizzare un Blocco ne riutilizza i filtri in modo identico ovunque compaia. Se è necessario lo stesso contenuto ma con un filtro diverso, duplicare il Blocco e modificare la copia.

È possibile crearlo tramite l'interfaccia utente (di seguito) oppure automatizzarlo con l'[API](../report-builder-api/).

### Template

Un **Template** è un elenco ordinato di Blocchi associato a un singolo Tema. Il Template definisce cosa appare nel report e in quale ordine, mentre il Tema a cui è associato ne controlla l'aspetto.

Poiché un Template fa riferimento ai Blocchi per inclusione, lo stesso Blocco può comparire più volte in un Template. Un Blocco di interruzione di pagina riutilizzabile, ad esempio, può essere inserito tra diverse sezioni dello stesso report.

È possibile crearlo tramite l'interfaccia utente (di seguito) oppure automatizzarlo con l'[API](../report-builder-api/).

### Report generati

L'esecuzione di un Template produce un **Report generato**: un file PDF o HTML persistente che è possibile scaricare e rieseguire su richiesta. Ogni Report generato è **cristallizzato nel tempo** — cattura i dati di DefectDojo nel momento in cui è stato generato e **non** si aggiorna automaticamente quando i dati sottostanti cambiano in seguito. Per ottenere un'istantanea aggiornata, rieseguire il Template.

Durante la creazione, un Report generato attraversa i seguenti stati:

| Stato | Significato |
|--------|---------|
| Pending | Il report è stato richiesto ed è in coda. |
| Processing | Il report è in fase di assemblaggio. |
| Completed | Il report è pronto per il download. |
| Failed | Non è stato possibile generare il report. |

> **🔑 Important:** il Reporting è attivo per impostazione predefinita. Un superuser può attivarlo o disattivarlo da **Settings > Feature Flags** (vedere [Feature Flags](/admin/feature_flags/pro__feature_flags/)). La visualizzazione rispetta il controllo degli accessi basato sui ruoli (RBAC) di DefectDojo — gli utenti vedono sempre e solo i dati che sono autorizzati a visualizzare, anche all'interno di un report.

È possibile crearlo tramite l'interfaccia utente (di seguito) oppure automatizzarlo con l'[API](../report-builder-api/).

## Creare un report tramite l'interfaccia utente

I passaggi seguenti illustrano l'intero processo di creazione di un report: creare un Tema, creare i Blocchi che contengono il contenuto, assemblarli in un Template e generare il report finale.

### Passaggio 1: creare un Tema

Iniziare dall'area Themes. L'elenco Themes mostra tutti i Temi definiti e consente di crearne uno nuovo.

![Elenco dei Temi](images/pro_report_themes_list.png)

Aprire un nuovo Tema per impostarne il branding. Il modulo del Tema espone i cinque colori, un'immagine facoltativa di intestazione e piè di pagina, il testo del piè di pagina e l'interruttore per i numeri di pagina. Scegliere colori coerenti con il brand della propria organizzazione, in modo che ogni report prodotto risulti visivamente coerente.

![Modulo di modifica del Tema](images/pro_report_theme_new.png)

### Passaggio 2: creare i Blocchi

Successivamente, creare i Blocchi di contenuto. L'elenco Blocks mostra tutti i Blocchi, di ogni tipo.

![Elenco dei Blocchi](images/pro_report_blocks_list.png)

Per creare un Blocco basato sui dati, sceglierne il tipo e configurarlo. L'esempio seguente è un Blocco **Tabular** denominato per i riscontri aperti: il Block Type è impostato su Tabular, viene fornita un'intestazione, il Model è **Finding**, i campi selezionati sono Severity, Title, Product, Age (Days) e SLA Days Remaining, e i record sono ordinati per Numerical Severity in ordine decrescente. Poiché i filtri risiedono nel Blocco, le **Filter Entries** qui definiscono esattamente quali record questo Blocco recupererà ovunque venga utilizzato.

![Configurazione del blocco Tabular](images/pro_report_block_new_tabular.png)

È possibile visualizzare in **Preview** un Blocco per vedere come verrà visualizzato con un Tema applicato prima di inserirlo in un Template. L'anteprima seguente mostra una copertina stilizzata ("DefectDojo Security Report") che riprende i colori e il branding del Tema.

![Anteprima del blocco renderizzato](images/pro_report_block_preview.png)

> **💡 Tip:** utilizzare **Duplicate** per copiare un Blocco esistente quando serve lo stesso layout con un filtro diverso. Poiché i filtri viaggiano insieme al Blocco, la duplicazione è il modo corretto per produrre, ad esempio, una tabella "Critical findings" e una tabella "High findings" a partire dallo stesso layout di colonne.

### Passaggio 3: assemblare un Template

Con i Blocchi pronti, creare un Template. L'elenco Templates mostra i Template salvati.

![Elenco dei Template](images/pro_report_templates_list.png)

Nell'editor del Template si seleziona un Tema e si dispongono i Blocchi nell'ordine in cui devono comparire. L'esempio seguente sequenzia Cover Page → Executive Intro → Open Findings → KEV → Page Break → Asset Inventory. Utilizzare **Add Existing Block** per riutilizzare un Blocco già creato, oppure **Add New Block** per crearne uno al momento, e utilizzare le maniglie di trascinamento per riordinare. Ricordare che lo stesso Blocco può comparire più di una volta — un singolo Blocco di interruzione di pagina può essere inserito tra diverse sezioni.

![Editor del Template](images/pro_report_template_new.png)

### Passaggio 4: generare e scaricare

Quando il Template è pronto, generare il report. La finestra di dialogo di generazione conferma il Template e consente di scegliere il formato di output — **HTML** o **PDF**.

![Finestra di dialogo di generazione del report](images/pro_generate_report_dialog.png)

I report generati vengono raccolti nell'elenco Generated Reports, che mostra lo stato di ciascun report, il formato del file, l'ora di richiesta e completamento e un collegamento per il download.

![Elenco dei report generati](images/pro_generated_reports_list.png)

È possibile rieseguire un Template in qualsiasi momento per produrre un report aggiornato. Tenere presente che ogni Report generato è cristallizzato nel tempo — riflette i dati al momento della generazione e non cambierà al variare dei dati di DefectDojo, quindi rieseguire il Template ogni volta che serve un'istantanea aggiornata.

## Abbandonare il motore di report classico

Il motore di report classico — le pagine **Report Builder**, **Report Templates** e **Generated
Reports** elencate sotto *Classic Report Engine* nella barra laterale — viene rimosso nella versione
**3.3.0 (8 settembre 2026)**. Fino ad allora, tali pagine mostrano un banner che ricorda la
data, ed entrambe, insieme a questo Generatore di report, offrono una migrazione con un clic.

### Migrazione dei template salvati

Utilizzare **Migrate to the new engine** su qualsiasi pagina classica, oppure **Import from Classic Engine**
su *All Report Templates* qui. Entrambe eseguono la stessa conversione, quindi non importa da quale
si parta, ed entrambe possono essere eseguite più di una volta in sicurezza: un template classico il cui nome
esiste già qui viene segnalato come *già migrato* anziché duplicato.

Ogni widget classico diventa un Blocco:

| Widget classico | Diventa |
|----------------|---------|
| Cover Page | Blocco stock Cover Page |
| Table Of Contents | Blocco stock Table of Contents |
| Page Break | Blocco stock Page Break |
| Custom Content / WYSIWYG | Text Block |
| Findings | Blocco Tabular sui Findings, mantenendo i filtri del widget |
| Vulnerable Endpoints | Blocco Tabular sugli URL |
| Severities | Blocco grafico Active Findings by Severity |

Due non vengono trasferiti, e la migrazione lo segnala per ciascun template anziché convertirli
in qualcosa di approssimativo:

- **Executive Summary** — il motore classico lo derivava dai widget Findings
  presenti nello stesso report. Non esiste un Blocco aggregato equivalente; ricrearlo come Text
  Block, se necessario.
- **Report Options** — non è un Blocco. Il suo *Report name* diventa il nome del nuovo Template.
  Le note sui riscontri, le immagini dei riscontri e le interruzioni di pagina per widget sono impostazioni a livello di Tema
  nel nuovo motore.

### Cosa succede ai report già eseguiti

Niente. I Report generati prodotti dal motore classico sono file già completati, quindi non c'è
nulla da convertire. Restano elencati e scaricabili fino alla rimozione del motore — salvare
tutto ciò che si desidera conservare oltre la versione 3.3.0.

### Se il Generatore di report è disattivato

La migrazione funziona comunque con il feature flag **Reporting** disattivato. I Template
convertiti semplicemente non vengono visualizzati finché il flag non viene riattivato, quindi è possibile trasferire i propri
template secondo i propri tempi.

## Passaggi successivi

- **[API del Generatore di report](../report-builder-api/)** — scrivere script per l'intero flusso di lavoro (Temi, Blocchi, Template e Report generati) per un reporting ripetibile e automatizzato.
- **[Generatore di report con un LLM](../report-builder-llm/)** — utilizzare la creazione assistita da LLM per progettare e creare report in modo conversazionale.
