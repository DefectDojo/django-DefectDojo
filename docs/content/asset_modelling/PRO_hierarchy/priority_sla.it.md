---
title: Assegnare Priorità, Rischio e SLA
description: Come DefectDojo classifica i tuoi Riscontri
weight: 1
audience: pro
aliases:
- /it/en/working_with_findings/finding_priority
- /it/en/working_with_findings/priority_adjustments
---

![image](images/pro_finding_priority.png)

Un approccio efficace alla gestione del rischio basata sulle vulnerabilità richiede di considerare sia il contesto di business sia la sfruttabilità tecnica. Utilizzando la funzionalità Priorità e Rischio di DefectDojo Pro, gli utenti possono ordinare automaticamente i Riscontri in un contesto significativo, garantendo che le vulnerabilità ad alto impatto possano essere affrontate per prime.

**Priorità** è un rango numerico calcolato applicato a tutti i Riscontri nella tua istanza
DefectDojo. Consente di comprendere rapidamente le vulnerabilità nel loro contesto, specialmente all’interno di grandi organizzazioni che gestiscono le esigenze di sicurezza per molti Riscontri e/o
Prodotti.

**Rischio** è un sistema di classificazione a 4 livelli che tiene conto in misura maggiore della sfruttabilità di un Riscontro. È pensato come una versione meno granulare e più ‘a livello esecutivo’ della Priorità.

![image](images/pro_risk_example.png)

I valori di Priorità e Rischio possono essere utilizzati insieme ad altri filtri per confrontare i Riscontri in qualsiasi contesto, ad esempio:

* all’interno di un singolo Prodotto, Engagement o Test
* a livello globale in tutti i Prodotti DefectDojo
* tra alcuni Prodotti specifici

Applicare la Priorità e il Rischio dei Riscontri aiuta il tuo team a rispondere alle
vulnerabilità più rilevanti nella tua organizzazione, e fornisce inoltre un framework utile per la
conformità agli standard normativi.


Scopri di più su Priorità e Rischio con l'Office Hours di maggio 2025 di DefectDojo, Inc.:
<iframe width="560" height="315" src="https://www.youtube.com/embed/4SN0BWWsVm4?si=VYUzEGNeijjhoD22" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>


## Come vengono calcolati Priorità e Rischio
L’intervallo dei valori di Priorità va da 0 a 1150. Più alto è il numero, maggiore è
l’urgenza di triage o correzione del Riscontro.

In modo simile alla Gravità, il Rischio è classificato da Bassa -> Media -> Richiede intervento -> Urgente.  Il **Rischio** tiene conto dei campi di Priorità e può quindi differire dalla Gravità segnalata da uno strumento.

![image](images/priority-overview.png)

## Campi di Priorità: a livello di Prodotto

Ogni Prodotto in DefectDojo dispone di metadati che tracciano la criticità di business e i fattori
di rischio. Questi metadati vengono utilizzati per calcolare la Priorità e il Rischio dei
Riscontri associati.

Tutti questi campi di metadati possono essere impostati nel modulo **Modifica Prodotto** per un dato Prodotto.

![image](images/priority_edit_product.png)

* **Criticità** può essere impostata su uno dei seguenti valori: Nessuna, Molto bassa, Bassa, Media, Alta o Molto
Alta. La Criticità è un campo soggettivo, quindi nell’assegnare questo campo considera come il
Prodotto si confronta con gli altri Prodotti della tua organizzazione.
* **Record utente** è una stima numerica dei record utente presenti in un database (o in un sistema
che può accedere a quel database).
* **Ricavi** è una stima numerica dei ricavi annuali del Prodotto. Per calcolare la Priorità, DefectDojo calcolerà una percentuale confrontando i ricavi di questo Prodotto con la somma dei ricavi di tutti i Prodotti all’interno del Tipo di Prodotto.

Non è possibile impostare un tipo di valuta in DefectDojo, quindi assicurati che tutte le tue stime di Ricavi
usino la stessa denominazione di valuta. (“50000” potrebbe significare $50.000
Dollari USA oppure ¥50.000 Yen giapponesi - la denominazione non ha importanza, purché
tutti i tuoi Prodotti abbiano i ricavi calcolati nella stessa valuta).
* **Pubblico esterno** è un valore vero/falso - impostalo su Vero se questo Prodotto può
essere raggiunto da un pubblico esterno. Ad esempio, clienti, utenti o chiunque
al di fuori della tua organizzazione.
* **Accessibile da Internet** è un valore vero/falso. Se questo Prodotto può connettersi alla rete
internet pubblica, dovresti impostare questo valore su Vero.

La Priorità è un calcolo ‘relativo’, pensato per confrontare diversi Prodotti all’interno della
tua istanza DefectDojo. Sta in definitiva alla tua organizzazione decidere come questi
filtri vengono impostati. Questi valori dovrebbero essere il più accurati possibile, ma l’obiettivo principale è
mettere in evidenza i tuoi Prodotti chiave in modo da poter dare priorità alle vulnerabilità secondo la
politica della tua organizzazione, quindi questi campi non devono necessariamente essere impostati alla perfezione.

## Campi di Priorità: a livello di Riscontro

I Riscontri all’interno di un Prodotto possono avere metadati aggiuntivi che possono ulteriormente modificare il livello di Priorità e Rischio del Riscontro:

* Se il Riscontro ha un **Punteggio EPSS**, questo viene aggiunto automaticamente ai Riscontri e mantenuto aggiornato per gli utenti Pro.  Il **Punteggio EPSS** è il campo che contribuisce al Punteggio di Priorità — il **Percentile EPSS** viene tracciato sul Riscontro come riferimento ma non alimenta direttamente il calcolo.
* Quanti Endpoint del Prodotto sono interessati da questo Riscontro
* Se il Riscontro è In revisione oppure no
* Se il Riscontro è presente nel database KEV (Known Exploited Vulnerabilities), che viene verificato regolarmente da DefectDojo
* La Gravità segnalata dallo strumento per un Riscontro (Info, Bassa, Media, Alta, Critica)

#### Punteggio EPSS vs Percentile EPSS

Due Riscontri che appaiono identici sui fattori visibili (Gravità, Criticità di business, Accessibile da Internet, Exploit disponibile) possono comunque ottenere Punteggi di Priorità diversi se i loro **Punteggi EPSS** differiscono.  Questo è normale: il Punteggio EPSS è un input contestuale per il calcolo.

Il Percentile EPSS viene mostrato sul Riscontro a scopo di contesto, ma non viene utilizzato nel calcolo del Punteggio di Priorità.  Se hai bisogno di confrontare due Riscontri per capire una differenza nel Punteggio di Priorità, guarda i valori del Punteggio EPSS, non quelli del Percentile.

Il peso esatto che il Punteggio EPSS (e gli altri fattori) ha nel calcolo del Punteggio di Priorità non viene volutamente pubblicato.  Se hai bisogno di influenzare quanto il Punteggio EPSS incide sul punteggio nel tuo ambiente, regola il cursore **Sfruttabilità** nel tuo [Motore di Prioritizzazione](#prioritization-engines).


## Calcolo del Rischio del Riscontro

![image](images/risk_table.png)

La colonna Rischio in una tabella dei Riscontri è un altro modo per dare rapidamente priorità ai Riscontri.  Il Rischio viene calcolato utilizzando il livello di Priorità di un Riscontro, ma tiene conto in misura maggiore anche della sfruttabilità del Riscontro.  È pensato come una versione meno granulare e più ‘a livello esecutivo’ della Priorità.

I quattro livelli di Rischio assegnabili sono:

![image](images/pro_risk_levels.png)

L’EPSS / la sfruttabilità di un Riscontro ha un peso molto maggiore nel calcolo del Rischio.  Di conseguenza, un Riscontro può avere sia una priorità alta sia un valore di rischio basso.

Il calcolo del Rischio in sé non può attualmente essere regolato direttamente. Tuttavia, se la [Threat Intelligence](/asset_modelling/pro_hierarchy/threat_intelligence/) è abilitata, la **Soglia minima di Rischio per elementi attivamente sfruttati** ti permette di controllare l’esito per il caso più importante: un Riscontro confermato come sfruttato attivamente viene portato almeno a una fascia di Rischio a tua scelta, invece di rimanere in una fascia bassa solo perché la sua gravità di base è Bassa. Viene fornita impostata su **Richiede intervento**, e ogni Motore di Prioritizzazione può alzarla, abbassarla o azzerarla per disattivare la soglia. Vedi [la Soglia minima di Rischio per elementi attivamente sfruttati](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor).

## Dashboard Priority Insights

Gli utenti possono avere una visione a livello esecutivo di Priorità e Rischio nel proprio ambiente utilizzando
la Dashboard Priority Insights (Metriche > Priority Insights nella barra laterale)

![image](images/priority_dashboard.png)

Questa dashboard può essere filtrata per includere Prodotti specifici o intervalli di date. Come le
altre dashboard Pro, questa dashboard può essere esportata da DefectDojo come PDF per
produrre rapidamente un report.

## Impostare Priorità e Rischio per la conformità normativa

Questo è un elenco non esaustivo di standard normativi che richiedono specificamente
metodi di prioritizzazione delle vulnerabilità:

* La conformità a [SOX (Sarbanes-Oxley Act)](https://www.sarbanes-oxley-act.com/) richiede una prioritizzazione basata sui ricavi per i
sistemi che hanno un impatto sui dati finanziari. In DefectDojo, i ricavi di un sistema possono essere inseriti
a livello di Prodotto.
* La conformità a [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/) richiede una prioritizzazione basata su valutazioni di rischio e criticità per gli
ambienti dei dati dei titolari di carta. La Criticità di business e il Pubblico esterno possono essere
impostati a livello di Prodotto, mentre la sincronizzazione EPSS a livello di Riscontro di DefectDojo supporta l’approccio
basato sul rischio richiesto da PCI.
* [NIST SP 800-40](https://csrc.nist.gov/pubs/sp/800/40/r4/final) è una guida alla manutenzione preventiva che richiede specificamente la
prioritizzazione delle vulnerabilità basata su impatto di business, criticità del prodotto e
fattori di accessibilità da Internet. Tutti questi possono essere impostati a livello di Prodotto di DefectDojo.
* La conformità al Controllo A.12.6.1 di [ISO 27001/27002](https://www.iso.org/standard/27001) richiede la gestione delle vulnerabilità
tecniche con una Priorità basata sulla valutazione del rischio.
* [L'articolo 32 del GDPR](https://gdpr-info.eu/art-32-gdpr/) richiede misure di sicurezza basate sul rischio - i flag di record utente e pubblico
esterno a livello di Prodotto possono aiutare a dare priorità ai sistemi della tua organizzazione
che trattano dati personali.
* La conformità a [FISMA/FedRAMP](https://help.fedramp.gov/hc/en-us) richiede il monitoraggio continuo e la correzione delle vulnerabilità basata sul rischio.

I calcoli di Priorità e Rischio di DefectDojo Pro possono essere regolati, permettendoti di adattare DefectDojo Pro per farlo corrispondere agli standard interni della tua organizzazione per la Priorità e il Rischio dei Riscontri.

## Motori di Prioritizzazione

In modo simile alle configurazioni SLA, i Motori di Prioritizzazione ti permettono di impostare le regole che governano il calcolo di Priorità e Rischio.

![image](images/priority_default.png)

DefectDojo include un Motore di Prioritizzazione predefinito, applicato a tutti i Prodotti.  Tuttavia, puoi modificare questo Motore di Prioritizzazione per cambiare la ponderazione dei moltiplicatori di **Riscontro** e **Prodotto**, il che modificherà il modo in cui vengono assegnati Priorità e Rischio dei Riscontri.

### Moltiplicatori del Riscontro

Otto fattori contestuali influenzano il punteggio di Priorità di un Riscontro.  Tre di questi sono specifici del Riscontro, mentre gli altri cinque vengono assegnati in base al Prodotto che contiene il Riscontro.

Puoi regolare il tuo Motore di Prioritizzazione modificando il modo in cui questi fattori vengono applicati al calcolo finale.

![image](images/priority_sliders.png)

Seleziona un fattore facendo clic sul pulsante, e regolando questo cursore puoi controllare la percentuale con cui un determinato fattore viene applicato.  Man mano che regoli il cursore, vedrai cambiare di conseguenza le soglie di Rischio.

#### Moltiplicatori a livello di Riscontro

* **Gravità** - il livello di Gravità di un Riscontro
* **Sfruttabilità** - il KEV e/o il punteggio EPSS di un Riscontro
* **Endpoint** - il numero di Endpoint associati a un Riscontro

#### Moltiplicatori a livello di Prodotto

* **Criticità di business** - la Criticità di business del Prodotto correlato (Nessuna, Molto bassa, Bassa, Media, Alta o Molto
Alta)
* **Record utente** - il conteggio dei Record utente del Prodotto correlato
* **Ricavi** - i ricavi del Prodotto correlato, relativi ai ricavi totali del Tipo di Prodotto
* **Pubblico esterno** - se il Prodotto correlato ha o meno un pubblico esterno
* **Accessibile da Internet** - se il Prodotto correlato è o meno accessibile da Internet

### Soglie di Rischio

In base alla regolazione del Motore di Priorità, DefectDojo consiglierà automaticamente delle Soglie di Rischio.  Tuttavia, anche queste soglie possono essere regolate e impostate sui valori che ritieni più appropriati.

![image](images/risk_threshold.png)

## Creare nuovi Motori di Prioritizzazione

Puoi utilizzare più Motori di Prioritizzazione, ciascuno assegnabile a Prodotti diversi.

![image](images/priority_engine_new.png)

Creando un nuovo Motore di Prioritizzazione si aprirà il modulo del Motore di Prioritizzazione.  Una volta inviato questo modulo, un nuovo Motore di Prioritizzazione verrà aggiunto alla tabella.

## Assegnare i Motori di Prioritizzazione ai Prodotti

Ogni Prodotto può avere un Motore di Prioritizzazione attualmente in uso tramite il modulo **Modifica Prodotto** per un dato Prodotto.

![image](images/priority_chooseengine.png)

Nota che quando il Motore di Prioritizzazione di un Prodotto viene modificato, o un Motore di Prioritizzazione viene aggiornato, il Motore di Prioritizzazione del Prodotto o il Motore di Prioritizzazione stesso verrà “Bloccato” finché il calcolo di prioritizzazione non sarà completato.

Ogni Prodotto in DefectDojo può avere la propria configurazione di Service Level Agreement (SLA), che rappresenta i giorni a disposizione della tua organizzazione per correggere o comunque gestire un Riscontro.

Lo SLA può essere impostato in base alla **[Gravità del Riscontro](/asset_modelling/os_hierarchy/product_hierarchy/#findings)** oppure al **[Rischio del Riscontro](/asset_modelling/pro_hierarchy/priority_sla/)** (in DefectDojo Pro).

![image](images/sla_multiple.png)

Gli SLA applicano un conto alla rovescia di giorni a un Riscontro in base al giorno in cui il Riscontro è stato creato in DefectDojo.  Se un Riscontro non viene Chiuso entro il conto alla rovescia, il Riscontro verrà etichettato come in violazione dello SLA.

## Lavorare con gli SLA

Puoi utilizzare gli SLA come modo per rappresentare le politiche di correzione della tua organizzazione.  Puoi anche usarli come modo per dare priorità ai Riscontri più critici e attivi da più tempo nella tua istanza DefectDojo.  

* Puoi ordinare o filtrare le tabelle dei Riscontri in base ai giorni di SLA.
* Le violazioni SLA possono essere configurate per attivare [Notifiche](/admin/notifications/about_notifications/) agli utenti DefectDojo assegnati al Prodotto correlato.
* In **DefectDojo Pro**, le prestazioni SLA vengono tracciate anche nelle Dashboard delle Metriche [Executive Insights and Remediation](/metrics_reports/pro_metrics/pro__overview/).
* La conformità SLA può anche essere mostrata in una [dashboard](/metrics_reports/dashboards/custom-dashboards/) personalizzata in **DefectDojo Pro** — ad esempio con un widget SLA Burndown o un widget Count filtrato.

### Stato Mitigato entro lo SLA

Se un Riscontro viene Mitigato con successo entro la scadenza dello SLA, il Riscontro registrerà un segno di spunta verde ✅ nella colonna Mitigato entro lo SLA.

![image](images/sla_mitigated_within.png)

Se un Riscontro è stato Mitigato, ma non prima che lo SLA venisse violato, il Riscontro registrerà una X rossa ❌ nella colonna Mitigato entro lo SLA.

### Violazione degli SLA

Quando lo SLA di un dato Riscontro viene violato (il Riscontro non viene Chiuso entro la scadenza dello SLA) il segno di spunta verde ✅ passerà a una X rossa ❌.  Lo SLA continuerà a essere tracciato con un numero negativo, per rappresentare da quanti giorni lo SLA è stato violato.

![image](images/sla_breached.png)

## Gestire le configurazioni SLA (Pro)

In DefectDojo Pro, una o più configurazioni SLA vengono gestite nella sezione **Configurazione > Service Level Agreement** della barra laterale.  Puoi creare un **Nuovo Service Level Agreement** oppure lavorare con le configurazioni SLA esistenti dalla pagina **Tutti i Service Level Agreement**.

![image](images/pro_sla_risk.png)

Le configurazioni SLA possono essere modificate solo dai Superuser o da un utente con il [Permesso di Configurazione](/admin/user_management/user_permission_chart/#configuration-permission-chart) corrispondente.

### Configurare lo SLA

Le configurazioni SLA contengono i giorni assegnati a ciascun valore di **Gravità** o **Rischio** di DefectDojo.

![image](images/pro_new_sla.png)

Ogni Service Level Agreement può avere un nome univoco, oltre a una descrizione facoltativa.

**Riavvia SLA alla riattivazione del Riscontro**: se abilitata, questa opzione farà ripartire da zero uno SLA quando un Riscontro viene Riaperto.  Altrimenti, lo SLA si baserà sul momento in cui il Riscontro è stato creato.

Quando modifichi uno SLA, puoi scegliere se quello SLA utilizzerà **Gravità** o **Rischio** come parametro di riferimento per assegnare i Giorni per la Correzione.  Questo si fa selezionando l’opzione corrispondente nella sezione **Tipo di configurazione del Service Level** del modulo.

Da qui, puoi impostare il numero di giorni consentiti per ciascun livello di **Gravità** o **Rischio**.  Puoi anche applicare gli SLA in modo selettivo; deselezionando **Applica i giorni per i Riscontri di livello ___** puoi ignorare il calcolo SLA per quei livelli di Gravità o Rischio.

## Applicare una configurazione SLA a un Prodotto (Pro)

I Prodotti appena creati in DefectDojo applicheranno sempre la **Configurazione SLA predefinita**, che può essere impostata su valori diversi se lo desideri.

Se hai delle configurazioni SLA, puoi scegliere quale di queste applicare al tuo Prodotto dal modulo **Modifica Prodotto**.  

![image](images/pro_sla_product.png)

### Ricalcolo SLA

Una volta selezionato un nuovo SLA per un Prodotto, tutti gli SLA dei Riscontri associati dovranno essere ricalcolati da DefectDojo.  Mentre questo processo è in esecuzione, lo SLA di un Prodotto non può essere modificato.

## Note sugli SLA

* Gli SLA possono essere facoltativamente riavviati quando un Riscontro con [Rischio accettato](/triage_findings/findings_workflows/pro__risk_acceptance/) viene riattivato.  Questo viene impostato durante la creazione dell’Accettazione del rischio, impostando il campo **Riavvia SLA Scaduto**.
* Il reimport di un Riscontro non riavvia lo SLA - gli SLA vengono sempre calcolati a partire dal momento in cui un Riscontro è stato rilevato per la prima volta, a meno che **Riavvia SLA alla riattivazione del Riscontro** non sia abilitato.
* La scadenza dell’Accettazione del rischio o la riattivazione di un Riscontro Chiuso sono gli unici modi per reimpostare o ricalcolare uno SLA per un Riscontro dopo la sua creazione (senza modificare la configurazione SLA del Prodotto).
