---
title: Raggiungibilità
description: Come DefectDojo Pro registra se il codice vulnerabile di un Riscontro
  sia effettivamente raggiungibile, e come questo verdetto modifica la priorità
audience: pro
weight: 3
---

Un CVE critico in un codice che la tua applicazione non richiama mai non rappresenta lo stesso rischio dello stesso CVE su un percorso di richiesta attivo. La **Raggiungibilità** (Reachability) coglie questa differenza: DefectDojo Pro registra se il codice vulnerabile di ogni Riscontro possa effettivamente essere raggiunto, ti mostra da dove proviene questa conclusione, e la utilizza nel calcolo della **priority** del Riscontro.

La raggiungibilità è una funzionalità **beta** ed è **disattivata per impostazione predefinita**. Un superuser la abilita in **Settings > Feature Flags**. Finché è disattivata, non viene registrato alcun verdetto, la priorità non ne risente e non compare alcuna interfaccia relativa alla raggiungibilità.

## Verdetti

Ogni verdetto viene normalizzato negli stessi cinque valori, indipendentemente da cosa lo abbia prodotto:

| Verdict | Meaning |
|---|---|
| **Raggiungibile (runtime)** | Il codice vulnerabile è stato osservato in esecuzione. |
| **Raggiungibile (statico)** | Esiste un percorso di chiamata verso il codice vulnerabile a partire da un punto di ingresso dell'applicazione. |
| **Potenzialmente raggiungibile** | Evidenza parziale — ad esempio il pacchetto vulnerabile viene utilizzato, ma non è stato possibile confermare la funzione specifica. |
| **Non raggiungibile** | L'analisi non ha trovato alcun percorso verso il codice vulnerabile. |
| **Sconosciuto** | Nessuna analisi di raggiungibilità copre ancora questo Riscontro. |

La normalizzazione è importante perché gli strumenti non concordano sulla terminologia: la dicitura "no path found" di uno scanner e "not in use" di un altro hanno significati diversi, e DefectDojo registra entrambi come verdetti confrontabili invece di appiattirli in un semplice sì/no.

## Le regole che la raggiungibilità segue

Questi comportamenti sono intenzionali e non cambiano da uno strumento all'altro:

- **Sconosciuto non penalizza mai un Riscontro.** La maggior parte delle istanze parte con una copertura di raggiungibilità scarsa o nulla. Un Riscontro che nessuno strumento ha analizzato viene punteggiato esattamente come se la funzionalità fosse disattivata.
- **Non raggiungibile abbassa la priorità. Non chiude mai un Riscontro.** Un verdetto "non raggiungibile" attenua il punteggio in modo che i problemi realmente attivi si posizionino sopra di esso, ma il Riscontro resta aperto e visibile. L'analisi di raggiungibilità non è perfetta, e un "non raggiungibile" errato che nascondesse silenziosamente un Critical attivo sarebbe il peggior fallimento possibile.
- **Ogni verdetto mostra la propria fonte.** Nessun verdetto compare senza lo strumento che lo ha prodotto, il suo livello di confidenza, e il commit analizzato, quando è noto.
- **I verdetti seguono la deduplicazione.** Quando più scanner segnalano la stessa vulnerabilità e solo uno di essi riporta la raggiungibilità, il verdetto si applica all'intero cluster di duplicati, così non perdi il segnale importando un altro strumento.

## Da dove provengono i verdetti

Non è necessario adottare un nuovo scanner per trarne valore — DefectDojo legge la raggiungibilità che gli strumenti che già utilizzi stanno già producendo:

- **Scanner che la riportano nel loro output.** Diversi parser supportati includono la raggiungibilità, sia come dati strutturati sia nel testo del report. Non è richiesta alcuna configurazione oltre alla normale importazione del report.
- **Connettori.** Un connettore che supporta la raggiungibilità invia i verdetti per i prodotti che sincronizza, aggiornati secondo la sua pianificazione abituale.

La copertura è normalmente parziale, ed è previsto che lo sia. Gli strumenti che non riportano la raggiungibilità lasciano semplicemente i propri Riscontri su **Sconosciuto**.

## Come la raggiungibilità modifica la priorità

La raggiungibilità è un ulteriore input per il punteggio di priorità descritto in
[Scoring & Prioritization](../). I verdetti raggiungibili aumentano la priorità di un Riscontro, quelli non raggiungibili la abbassano in proporzione alla confidenza della fonte, e quelli sconosciuti la lasciano invariata.

L'intensità di questo aggiustamento è regolabile per ogni motore di definizione delle priorità, come ogni altro fattore: imposta lo scalare di raggiungibilità a `0` per registrare i verdetti senza che influiscano affatto sui punteggi, oppure aumentalo per dare più peso alla raggiungibilità. Puoi visualizzare in anteprima l'effetto con il simulatore di definizione delle priorità prima di applicarlo.

Poiché l'attivazione della raggiungibilità sposta i punteggi, rivedi le soglie di rischio del tuo motore dopo averla attivata, in modo che i Riscontri finiscano nelle fasce previste.

### Regole di rischio della raggiungibilità

Questo aggiustamento è proporzionale alla gravità di un Riscontro, il che significa che non può esprimere due cose che potresti desiderare. Un Riscontro di gravità Bassa il cui codice è confermato raggiungibile riceve comunque solo un piccolo incremento e resta in una fascia bassa; un Critical segnalato come non raggiungibile può comunque rimanere in cima alla coda. Due regole opzionali sul motore di definizione delle priorità impostano invece direttamente una fascia:

- **Reachable risk floor** — la fascia di Rischio minima per i Riscontri il cui codice vulnerabile è confermato raggiungibile. Può solo alzare una fascia, mai abbassarla.
- **Unreachable risk ceiling** — la fascia di Rischio massima per i Riscontri segnalati come non raggiungibili. Può solo abbassare una fascia, mai alzarla, e non chiude né nasconde mai un Riscontro; si limita a limitare dove viene ordinato.

Entrambe sono vuote per impostazione predefinita, quindi non cambia nulla finché non le imposti. Il ceiling ha anche una **confidenza minima**: si applica solo quando il verdetto di non raggiungibilità ha almeno quel livello di confidenza, perché limitare una fascia sulla base di un verdetto a bassa confidenza è il modo in cui un Critical attivo finisce sepolto.

Un Riscontro il cui CVE è segnalato come attivamente sfruttato in natura non viene mai limitato dal ceiling — l'evidenza di sfruttamento ha la precedenza su un'affermazione di assenza di percorso.

## Cosa vedi

**Su un Riscontro** — un badge di raggiungibilità, e un pannello **Reachability Sources** che elenca ogni fonte che ha riportato informazioni su di esso, il verdetto e la confidenza di ciascuna fonte, e quale sia attualmente applicata. Quando uno strumento fornisce un percorso di chiamata, l'evidenza a supporto viene mostrata insieme ad esso.

**Nell'elenco dei Riscontri** — una colonna e un filtro Reachability, così puoi creare viste come "Critical e raggiungibile" e salvarle.

**Su un asset** — un pannello **Reachability Coverage** che mostra la ripartizione dei verdetti per quell'asset, quanti dei suoi Riscontri hanno un verdetto di qualsiasi tipo, e quanti Critical la raggiungibilità ha declassato o confermato. Ogni cifra rimanda ai Riscontri corrispondenti. La quota ancora su Unknown viene mostrata insieme al resto: indica quanta parte dell'asset la raggiungibilità è attualmente in grado di valutare.
