---
title: EPSS / KEV
description: Come DefectDojo Pro arricchisce i Riscontri con i dati EPSS e CISA KEV,
  quando esegue la sincronizzazione e come influisce sulla priorità
audience: pro
weight: 2
aliases:
- /it/triage_findings/epss_kev/
---

DefectDojo Pro arricchisce automaticamente i tuoi Riscontri con due fonti esterne di threat intelligence — **EPSS** e **CISA KEV** — in modo che la definizione delle priorità rifletta quanto sia probabile che una vulnerabilità venga sfruttata, non solo la sua gravità CVSS. Entrambe le fonti vengono associate ai Riscontri tramite **CVE**, si aggiornano con una **pianificazione giornaliera** e alimentano direttamente il punteggio di **priorità** calcolato per ogni Riscontro.

I dati di arricchimento vengono memorizzati **una sola volta per vulnerabilità**, e poi applicati a ogni Riscontro che la referenzia. Questo significa che un CVE presente su diecimila Riscontri viene consultato una sola volta, e puoi esaminare i suoi valori EPSS e KEV direttamente nel **Vulnerability Explorer** — non solo Riscontro per Riscontro.

Su DefectDojo Cloud, l'arricchimento è completamente gestito: DefectDojo mantiene i dati di threat intelligence sottostanti e li distribuisce alla tua istanza. Non c'è nulla da installare, nessun URL di feed da configurare e nessun job giornaliero da pianificare — viene eseguito automaticamente per te.

## Le due fonti

### EPSS — Exploit Prediction Scoring System

[EPSS](https://www.first.org/epss/) è un modello basato sui dati pubblicato da FIRST che stima la probabilità che un determinato CVE venga sfruttato in natura (in the wild) nei prossimi 30 giorni. DefectDojo Pro memorizza due valori EPSS per ogni Riscontro corrispondente:

| Field | Meaning |
| --- | --- |
| **EPSS Score** | Probabilità di sfruttamento nei prossimi 30 giorni, da `0.0` a `1.0` (ad es. `0.94` = 94%). |
| **EPSS Percentile** | La posizione di questo CVE rispetto a tutti i CVE valutati, da `0.0` a `1.0` (ad es. `0.99` = tra l'1% più probabile di essere sfruttato). |

Quando un singolo Riscontro contiene **più CVE**, DefectDojo conserva il **punteggio EPSS più alto** tra essi e lo abbina al percentile di quel CVE. Il percentile appartiene sempre allo stesso CVE del punteggio — i due valori non vengono mai combinati da CVE diversi, perché un percentile ha senso solo insieme al proprio punteggio.

### KEV — CISA Known Exploited Vulnerabilities

Il [catalogo CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) è l'elenco ufficiale del governo statunitense delle vulnerabilità confermate come sfruttate in natura. A differenza di EPSS (una previsione), KEV è una dichiarazione di sfruttamento osservato nel mondo reale. DefectDojo Pro memorizza tre valori KEV per ogni Riscontro corrispondente:

| Field | Meaning |
| --- | --- |
| **Known Exploited** | `True` quando il CVE è presente nel catalogo CISA KEV. |
| **Ransomware Used** | `True` quando CISA segnala che il CVE è stato sfruttato in campagne ransomware. |
| **KEV Date** | La data in cui la vulnerabilità è stata aggiunta al catalogo KEV. |

Quando un Riscontro contiene **più CVE**, viene contrassegnato come **Known Exploited** se **almeno uno** dei suoi CVE è presente nel catalogo, come **Ransomware Used** se almeno uno soddisfa questo criterio, e la **KEV Date** corrisponde alla data di aggiunta al catalogo più antica tra essi.

Un segnale KEV non viene mai soppresso da un CVE correlato con un EPSS più alto. Se un Riscontro contiene un CVE con un punteggio EPSS alto che *non* è presente in KEV, e un altro con un punteggio EPSS basso che *lo è*, il Riscontro assume il punteggio EPSS alto **e** viene contrassegnato come Known Exploited — ogni campo riflette in modo indipendente il caso peggiore tra i CVE del Riscontro.

> **I Riscontri privi di CVE non vengono arricchiti.** Entrambe le fonti effettuano la corrispondenza rigorosamente sugli identificatori CVE (`CVE-YYYY-NNNNN`). Un Riscontro senza CVE — o con solo un identificatore specifico del vendor o in stile GHSA — non riceve alcun dato EPSS o KEV.

## Quando avviene la sincronizzazione

L'arricchimento viene eseguito **una volta al giorno, automaticamente**. Ogni esecuzione avviene in due fasi:

1. **Aggiornamento dei dati sulla vulnerabilità.** Ogni CVE conosciuto da DefectDojo viene riverificato rispetto ai dati EPSS e KEV più recenti, e il record per vulnerabilità viene aggiornato.
2. **Applicazione delle modifiche ai Riscontri.** Solo le vulnerabilità i cui valori sono effettivamente *cambiati* vengono propagate ai Riscontri che le referenziano, e solo quei Riscontri vengono ripunteggiati.

Poiché la seconda fase è guidata da ciò che è cambiato, una giornata tranquilla ha un costo minimo: se nessuna delle due fonti ha pubblicato novità, l'esecuzione si conclude senza riscrivere i tuoi Riscontri. Quando qualcosa cambia — un punteggio EPSS varia, oppure un CVE viene aggiunto al catalogo KEV — ogni Riscontro interessato lo recepisce alla successiva esecuzione.

Alcune conseguenze utili da comprendere:

- **I Riscontri vengono solitamente arricchiti già in fase di importazione.** A partire dalla **v3.2.0**, l'arricchimento EPSS/KEV viene applicato al momento dell'importazione, quindi un Riscontro con un CVE appena importato normalmente non deve attendere il ciclo giornaliero successivo per mostrare i valori. Quanto sia immediato dipende dal fatto che DefectDojo abbia già consultato quel CVE — vedi [Cosa copre "arricchito al momento dell'importazione"](#what-enriched-at-import-time-covers) più sotto. L'esecuzione giornaliera continua comunque a operare, mantenendo questi valori aggiornati man mano che i punteggi EPSS cambiano e il catalogo KEV si evolve. Se un Riscontro che ti aspetti sia arricchito non lo è, puoi [eseguire una sincronizzazione su richiesta](#running-a-sync-on-demand).
- **I valori vengono mantenuti aggiornati, non congelati.** Un CVE che viene aggiunto al catalogo KEV farà passare un Riscontro esistente a **Known Exploited** alla successiva esecuzione — senza bisogno di una nuova importazione.
- **Le rimozioni da KEV vengono rispettate.** Se i CVE di un Riscontro non sono più presenti in KEV, l'esecuzione cancella i valori obsoleti di **Known Exploited** / **Ransomware Used** / **KEV Date** invece di lasciarli impostati.

### Cosa copre "arricchito al momento dell'importazione"

Poiché i dati di arricchimento vengono memorizzati una sola volta per vulnerabilità, un'importazione può applicare istantaneamente solo ciò che DefectDojo ha già consultato in precedenza. Esistono tre casi:

| At import, the CVE is… | When the Finding shows EPSS/KEV |
| --- | --- |
| **Già arricchito** — DefectDojo ha già consultato questo CVE in precedenza, per qualsiasi Riscontro in qualsiasi Prodotto | **Immediatamente**, come parte dell'importazione. Questo è il caso comune: i CVE ricorrono tra le scansioni e tra i team, quindi la maggior parte dei CVE in una tipica importazione è già nota. |
| **Nuovo per DefectDojo**, e l'importazione introduce solo un numero modesto di nuovi CVE | **Poco dopo l'importazione**, in background. Non c'è ancora nulla di memorizzato da applicare, quindi l'importazione richiede una consultazione solo per quei CVE e applica i risultati non appena vengono restituiti. |
| **Nuovo per DefectDojo**, e l'importazione introduce un numero molto elevato di nuovi CVE — una prima importazione, o un backfill massivo | **Alla successiva esecuzione giornaliera**, oppure alla successiva [sincronizzazione su richiesta](#running-a-sync-on-demand). Consultare migliaia di CVE del tutto nuovi mentre l'importazione è ancora in corso duplicherebbe il lavoro dell'esecuzione giornaliera, quindi viene deliberatamente lasciato a quest'ultima. |

In ogni caso i valori arrivano senza bisogno di una nuova importazione, e l'esecuzione giornaliera resta la rete di sicurezza — nulla viene saltato in modo permanente.

> **Le sincronizzazioni dei connettori vengono arricchite allo stesso modo**, con un'eccezione: una **sincronizzazione di connettore molto grande viene importata a blocchi (chunk)**, e le sincronizzazioni a blocchi non vengono arricchite al momento dell'importazione. Quei Riscontri ricevono i propri valori EPSS/KEV dalla successiva esecuzione giornaliera, oppure da una sincronizzazione su richiesta.

## Visualizzare KEV/EPSS nel Vulnerability Explorer

Il **Vulnerability Explorer** elenca una riga per ogni ID di vulnerabilità, con le stesse cinque colonne KEV/EPSS presenti nella tabella dei Riscontri — **EPSS Score**, **EPSS Percentile**, **Known Exploited**, **Ransomware Used** e **KEV Date**:

![image](images/Pro_EPSS_KEV_Explorer_Columns.png)

Questi valori descrivono la vulnerabilità stessa, quindi sono identici indipendentemente da quanti Riscontri la referenzino. EPSS Score, EPSS Percentile, Known Exploited e KEV Date sono tutti ordinabili, il che rende questo il modo più rapido per rispondere alla domanda "quali vulnerabilità nel mio ambiente vengono effettivamente sfruttate?" — ordina per **EPSS Score** in ordine decrescente, oppure ordina per **Known Exploited** per portare in cima i CVE presenti nel catalogo.

Il conteggio **Total Findings** di ogni riga rimanda all'elenco dei Riscontri filtrato per quella vulnerabilità, così puoi passare da "questo CVE è presente in KEV" a "ecco tutto ciò che riguarda" con un solo clic.

## Distinguere "nessun dato" da "non sfruttata"

Una colonna KEV/EPSS vuota e una ✗ rossa hanno significati diversi:

- **✗ rossa / un punteggio** — questa vulnerabilità *è stata* verificata. Una ✗ sotto Known Exploited significa che CISA non la elenca.
- **Vuoto** — questa vulnerabilità **non è mai stata arricchita**, quindi il suo stato di sfruttamento è semplicemente sconosciuto.

Qui lo stesso Explorer non è mai stato sincronizzato, quindi ogni colonna KEV/EPSS è vuota anziché mostrare zeri o simboli ✗:

![image](images/Pro_EPSS_KEV_Explorer_Unenriched.png)

La stessa distinzione compare sul Riscontro stesso. Un Riscontro i cui CVE non sono ancora stati arricchiti lo indica chiaramente, e rimanda all'Explorer da cui puoi avviare una sincronizzazione:

![image](images/Pro_EPSS_KEV_Not_Enriched.png)

Una volta eseguito l'arricchimento, lo stesso pannello riporta ciò che è stato effettivamente trovato:

![image](images/Pro_EPSS_KEV_Finding_Panel.png)

Questo è importante perché "non abbiamo ancora verificato" e "abbiamo verificato e non è sfruttata" sarebbero altrimenti indistinguibili, e solo una delle due situazioni è un motivo per abbassare la guardia.

## Eseguire una sincronizzazione su richiesta

Non è necessario attendere il ciclo giornaliero. Il pulsante **Sync KEV/EPSS data** nella parte superiore del Vulnerability Explorer avvia immediatamente una sincronizzazione:

![image](images/Pro_EPSS_KEV_Sync_Started.png)

Mentre una sincronizzazione è in corso, il pulsante è disabilitato e al suo posto compare una barra di avanzamento, insieme a una stima del tempo rimanente non appena è stato completato abbastanza lavoro da poterla proiettare. La riga di stato sopra di essa riporta cosa sta succedendo — prima che DefectDojo sta verificando quali vulnerabilità sono cambiate, poi quanti Riscontri sono stati aggiornati finora. Al termine dell'esecuzione, la riga riporta l'esito: quanti Riscontri sono cambiati, che tutto era già aggiornato, oppure — se non è configurata alcuna fonte — che la sincronizzazione non è stata eseguita.

Può essere in esecuzione una sola sincronizzazione alla volta. Premere il pulsante mentre una sincronizzazione è già in corso si limita ad agganciarsi all'esecuzione già avviata invece di avviarne una seconda, quindi è sicuro premerlo se non sei certo che una sincronizzazione sia già in corso. È anche sicuro ripetere una sincronizzazione: se nulla è cambiato dall'ultima esecuzione, non riscrive nulla.

Questo è il modo più rapido per recepire le modifiche EPSS e KEV pubblicate dopo l'ultimo ciclo giornaliero, e per completare eventuali Riscontri che ancora non mostrano dati di arricchimento.

## Come influisce su priorità e rischio

EPSS e KEV non sono semplici badge informativi — sono input diretti del **motore di definizione delle priorità** di DefectDojo Pro. Il punteggio `priority` di ogni Riscontro combina diverse componenti (gravità, esposizione, contesto dell'asset e altro); EPSS e KEV determinano la componente **external score**, che premia le vulnerabilità che è probabile vengano sfruttate — o che è noto vengano sfruttate.

L'external score deriva dal più **forte** tra i seguenti segnali:

- **EPSS** contribuisce in proporzione al proprio punteggio — una probabilità di sfruttamento più alta contribuisce maggiormente.
- **La presenza in KEV** contribuisce con un peso fisso: essere **Known Exploited** *oppure* utilizzato in **ransomware** applica un incremento significativo, e un CVE che è **sia** Known Exploited **che** utilizzato in ransomware applica l'incremento massimo.

Prevale il segnale più grande tra i due, quindi un Riscontro ottiene pieno credito sia per un punteggio EPSS alto sia per la presenza in KEV, senza essere penalizzato per la mancanza dell'altro. Questo external score viene poi combinato nella priorità complessiva del Riscontro insieme alla sua gravità ed esposizione. L'effetto netto: **un Riscontro presente in KEV o con EPSS alto sale sopra un Riscontro altrimenti comparabile che non ha nessuno dei due**, concentrando la remediation su ciò che è realmente più probabile venga attaccato.

> **EPSS e KEV rappresentano la base — [Threat Intelligence](/asset_modelling/pro_hierarchy/threat_intelligence/) la estende.** Con Threat Intelligence Enrichment abilitato, lo stesso external score riconosce anche exploit pubblici armati (weaponized), template di rilevamento Nuclei, codice proof-of-concept e sfruttamento attivo confermato, ciascuno dei quali agisce come *soglia minima* (floor) sulla scala EPSS. Aggiunge inoltre l'[Actively-Exploited Risk Floor](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor), che impedisce a un Riscontro sfruttato in natura di rimanere in una fascia di Rischio bassa solo perché la sua gravità di base è Bassa. Come EPSS e KEV, questi segnali possono solo aumentare un punteggio, mai diminuirlo.

Questo processo avviene automaticamente — la priorità viene ricalcolata esattamente per i Riscontri aggiornati da ogni esecuzione di arricchimento, così la definizione delle priorità resta allineata alla threat intelligence più recente.

> **Nota:** EPSS e KEV influenzano il punteggio di **priority**. Non modificano il campo **Severity** di un Riscontro. Possono tuttavia influire sul timer dello **SLA**: se la configurazione SLA ha **Cap by KEV due date** abilitato, la scadenza SLA di un Riscontro presente in KEV viene anticipata alla data di remediation prevista da CISA per quel CVE. Quando un Riscontro contiene più CVE presenti in KEV, si applica la data più vicina.

## Filtrare e visualizzare i Riscontri arricchiti

Una volta che i Riscontri sono arricchiti, i valori EPSS e KEV sono disponibili in tutta l'interfaccia Pro:

- **Sul Riscontro** — EPSS score, EPSS percentile, Known Exploited, Ransomware Used e KEV Date vengono tutti mostrati nel dettaglio del Riscontro.
- **Ordinamento** — le tabelle dei Riscontri possono essere ordinate per EPSS score / percentile per portare in cima i Riscontri più probabili da sfruttare.
- **Filtraggio** — l'elenco dei Riscontri offre i filtri **Known Exploited** e **Ransomware Used**, così puoi creare viste o report limitati alle vulnerabilità con sfruttamento reale confermato.

Un workflow comune consiste nel filtrare per **Known Exploited = true**, quindi ordinare per priorità, per produrre una coda "correggi prima questi" basata su uno sfruttamento confermato.

## Configurazione

Su **DefectDojo Cloud**, l'arricchimento EPSS e KEV è abilitato e mantenuto per te — non ci sono interruttori per le fonti, URL di feed o soglie da impostare, e la sincronizzazione giornaliera è gestita da DefectDojo. I pesi che traducono EPSS e KEV in priorità sono integrati nel motore di definizione delle priorità.

Se i dati EPSS o KEV non compaiono sui Riscontri in cui ti aspetti di vederli (e quei Riscontri contengono effettivamente dei CVE), inizia controllando la riga di stato nel Vulnerability Explorer — riporta l'esito della sincronizzazione più recente, incluso il caso in cui non sia configurata alcuna fonte. Se tutto sembra a posto ma i dati continuano a mancare, contatta il supporto DefectDojo, che può confermare se la sincronizzazione giornaliera sta distribuendo dati alla tua istanza.

> *Le installazioni on-premise* configurano l'arricchimento in modo diverso — ogni fonte può essere abilitata o disabilitata e puntata verso un URL di feed personalizzato nelle impostazioni di arricchimento dei riscontri del Tuner. Questa configurazione non si applica a Cloud, dove i dati vengono forniti da DefectDojo.
