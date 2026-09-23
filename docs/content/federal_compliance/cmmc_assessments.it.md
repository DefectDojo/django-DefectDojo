---
title: Valutazioni CMMC Level 2
description: Valuta un'autovalutazione rispetto a NIST 800-171 Rev 2
weight: 5
audience: pro
---

La scheda Compliance può valutare un'autovalutazione CMMC Level 2 rispetto a NIST 800-171 Rev 2, utilizzando
i pesi di punteggio della DoD Assessment Methodology.

![Una scorecard di valutazione CMMC Level 2](images/05-cmmc-scorecard.png)

**Beta: considera il punteggio come una stima.** Finché questa funzionalità è in beta, i pesi di punteggio
inclusi e il punteggio SPRS risultante hanno valore puramente indicativo e sono in attesa di validazione.
Verifica qualsiasi punteggio rispetto alla DoD NIST SP 800-171 Assessment Methodology ufficiale prima di
farvi affidamento per l'invio di una valutazione o per una finalità contrattuale.

## Registrare i risultati

Registra un risultato per ciascuno dei 110 requisiti:

* **Met**
* **Not met**
* **Not applicable**
* **Planned** (su POA&M)

![Il flusso di lavoro dei requisiti](images/06-cmmc-requirements.png)

### Credito parziale

Alcuni requisiti hanno una condizione parziale documentata che la metodologia valuta con una deduzione
ridotta anziché il peso completo. Dove esiste, la colonna **Partial Credit** permette di registrarla, e
il requisito deduce i punti ridotti anziché il totale. `3.13.11` è l'esempio: cifratura impiegata ma non
validata FIPS, deduce 3 punti invece di 5.

I requisiti senza una condizione parziale documentata deducono sempre il loro peso completo.

## Cosa calcola la valutazione

### Punteggio SPRS

110 meno la deduzione per ogni requisito non soddisfatto o semplicemente pianificato. I pesi sono di 1,
3 o 5 punti, quindi i punteggi vanno da 110 fino a -203.

Il requisito 3.12.4 (il requisito relativo al System Security Plan) viene valutato come non applicabile,
secondo la metodologia.

### Se è possibile uno stato condizionale

CMMC consente una certificazione condizionale con un punteggio di almeno **88** (80 percento), a
condizione che ogni lacuna aperta sia idonea per un POA&M.

La metodologia esclude del tutto alcuni requisiti dai POA&M. Tra i requisiti con peso superiore a un
punto, solo **3.13.11** (crittografia validata FIPS) può essere rinviato.

### Il termine di chiusura

Una valutazione condizionale ha **180 giorni** per chiudere i propri elementi POA&M. La valutazione
passa allo stato scaduta se il termine viene superato.

## Stati

Gli stati passano da **in progress** a **conditional** o **final**. Le valutazioni condizionali mostrano
i giorni rimanenti sul proprio termine di chiusura.

Le valutazioni sono soggette a cronologia delle modifiche: ogni modifica registra chi, cosa e quando.
