---
title: Configurazione
description: Impostazioni a livello di deployment per Rules Engine 2.0
weight: 7
audience: pro
aliases:
- /it/automation/rules_engine_v2/configuration/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 è una funzionalità disponibile solo in DefectDojo Pro.</span>

Rules Engine 2.0 funziona subito, senza configurazione. Le impostazioni di questa pagina servono ai deployment che devono ottimizzare il throughput, la conservazione o la politica di rete in uscita. Tutte vengono applicate allo stesso modo di qualsiasi altra impostazione di DefectDojo (vedere [Configuration](/get_started/open_source/configuration/)).

Rules Engine 2.0 viene configurato separatamente dal Rules Engine originale. I due motori non condividono alcuna impostazione: un'impostazione `DD_RULES_ENGINE_*` non influisce su Rules Engine 2.0 e un'impostazione `DD_RULES_V2_*` non influisce sul motore originale.

```python
DD_RULES_V2_EVENT_BATCH=(int, 500),
DD_RULES_V2_CHUNK_SIZE=(int, 1000),
DD_RULES_V2_STALLED_AFTER_MINUTES=(int, 30),
DD_RULES_V2_RUN_TIME_LIMIT_MINUTES=(int, 360),
DD_RULES_V2_ALLOW_PRIVATE_EGRESS=(bool, False),
DD_RULES_V2_DELIVERY_RETENTION_DAYS=(int, 180),
DD_RULES_V2_RUN_RETENTION_DAYS=(int, 180),
DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS=(int, 8000),
DD_RULES_V2_MAX_PER_ITEM_SENDS=(int, 1000),
```

## Throughput

### Riscontri per evento (`DD_RULES_V2_EVENT_BATCH`)

**Predefinito: 500.**

Quanti id di Riscontro porta un singolo evento. Gli eventi attraversano un confine asincrono, quindi vengono mantenuti abbastanza piccoli da restare un messaggio economico. Una scrittura più grande si suddivide in più eventi, ciascuno dei quali diventa un run a sé.

Aumentare questo valore produce run più grandi e meno numerosi. Abbassarlo ne produce di più piccoli e più numerosi.

### Riscontri per blocco (`DD_RULES_V2_CHUNK_SIZE`)

**Predefinito: 1000.**

Quanti Riscontri un run mantiene in memoria alla volta. Un run viene elaborato a blocchi, quindi questo è un parametro di memoria e **non** un tetto a ciò che una regola gestisce: una regola elabora sempre tutto ciò che il suo scope include.

Un envelope pesa circa 2,7KB per Riscontro, quindi il valore predefinito mantiene in memoria pochi megabyte alla volta. Aumentarlo scambia memoria per un minor numero di andirivieni. Abbassarlo fa il contrario.

### Limite di testo dell'envelope (`DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS`)

**Predefinito: 8000. Impostare a 0 per disattivarlo.**

Quanti caratteri di `description`, `mitigation` e `impact` porta un elemento.

Quei tre campi rappresentano la maggior parte delle dimensioni di un envelope. Il limite esiste per il caso insolito di un Riscontro con una descrizione molto grande, dove un blocco pieno di questi sarebbe molto più grande di quanto suggerisca la dimensione del blocco. È abbastanza generoso da non farsi mai notare in un'istanza ordinaria.

Si noti che questo influisce su ciò che condizioni e template possono vedere. Una condizione che confronta la coda di una descrizione molto lunga non vedrà il testo oltre il limite.

## Durata del run

### Finestra di stallo (`DD_RULES_V2_STALLED_AFTER_MINUTES`)

**Predefinito: 30.**

Per quanto tempo un run può restare senza heartbeat prima di essere considerato abbandonato, contrassegnato come in errore, con il rilascio del suo lock per-regola.

Un run genera un heartbeat dopo ogni blocco, quindi questo si misura dall'ultimo heartbeat e non dall'inizio. Una scansione lunga che sta ancora facendo progressi non viene mai scambiata per un worker bloccato, ed è questo che permette alla finestra di restare breve.

### Limite di tempo del run (`DD_RULES_V2_RUN_TIME_LIMIT_MINUTES`)

**Predefinito: 360, ovvero sei ore.**

Il tempo massimo che un singolo run può impiegare prima che il worker lo interrompa.

È una protezione contro una regola che non finirebbe mai, tenendo occupati uno slot del worker e il lock di esecuzione della sua regola. È deliberatamente generoso, perché una scansione a blocchi su uno scope molto ampio è esattamente il carico di lavoro per cui questo motore è stato costruito.

## Conservazione

Due job limitano le tre tabelle che questa funzionalità fa crescere. Entrambi hanno come predefinito **180 giorni**, ed entrambi accettano `0` per disattivare completamente l'eliminazione.

La conservazione è resa visibile nel prodotto invece di restare implicita: l'API restituisce sia la finestra sia la data in cui un dato record verrà eliminato, e le pagine che mostrano un run o una delivery lo indicano in una frase. La data viene calcolata in lettura, quindi modificare la finestra ha effetto immediato invece di applicarsi solo ai nuovi record.

### `DD_RULES_V2_DELIVERY_RETENTION_DAYS`

**Predefinito: 180.**

Per quanti giorni viene conservata una delivery conclusa.

Questa è la tabella che cresce più rapidamente in questa funzionalità. Un nodo egress per-Riscontro scrive fino a un blocco intero di righe per run, anche in modalità Simulate. Aumentarlo se serve una traccia di controllo in uscita più lunga, abbassarlo se il volume è un problema.

### `DD_RULES_V2_RUN_RETENTION_DAYS`

**Predefinito: 180.**

Per quanti giorni viene conservato un run concluso, insieme alle sue righe per nodo e alla provenienza dei Riscontri.

Il lato run cresce più rapidamente delle delivery, perché la provenienza è una riga per Riscontro per nodo di modifica per run. Una regola oraria su uno scope ampio ne genera molte.

Un run che detiene ancora delle delivery viene conservato finché queste non vengono eliminate, quindi impostare una finestra del run più corta di quella delle delivery non lascia nulla orfano.

## Validazione della destinazione in uscita

Due impostazioni dei nodi accettano una destinazione come testo libero invece che da un oggetto configurato: l'**URL** su Call a Webhook, e il campo **To** su Send an Email. Entrambe vengono validate al salvataggio della regola.

Per gli URL dei webhook:

* Sono accettati solo `http` e `https`. Altri schemi vengono rifiutati direttamente.
* L'URL deve avere un host.
* Per impostazione predefinita, un host che si risolve in un indirizzo loopback, link-local, privato, riservato o multicast viene rifiutato.

Per gli indirizzi email, un indirizzo vuoto viene rifiutato, così come uno che contiene un a-capo, che costituisce un'iniezione di intestazione.

Il motivo del controllo di rete è che il worker che invia la richiesta di solito si trova all'interno del cluster e può raggiungere una parte molto più ampia della rete interna rispetto a chi scrive la regola. Senza il controllo, un URL in testo libero è un primitivo di request forgery: puntarlo verso un servizio di metadati o una porta di amministrazione interna, e la risposta torna indietro attraverso il registro delle delivery.

Questo è un livello di difesa in profondità, non l'unico controllo. Rule Edit è comunque vicino a un permesso amministrativo. Vale la pena averlo affinché il raggio d'azione di un ruolo concesso in modo troppo ampio non sia "leggere qualsiasi endpoint HTTP interno", e affinché un errore di battitura fallisca al salvataggio con un messaggio chiaro invece che all'invio con un errore di connessione.

### Consentire indirizzi privati (`DD_RULES_V2_ALLOW_PRIVATE_EGRESS`)

**Predefinito: disattivato.**

Disattiva il controllo dell'indirizzo di rete, così i webhook possono pubblicare verso indirizzi loopback, link-local e privati. La validazione di schema e formato continua ad applicarsi.

Attivarlo se effettivamente si invia un webhook verso qualcosa su un indirizzo privato, che è normalmente il caso di una chat o di un ricevitore di webhook self-hosted.

## Tetto di invii per Riscontro

### `DD_RULES_V2_MAX_PER_ITEM_SENDS`

**Predefinito: 1000. Impostare a 0 per rimuovere il tetto.**

Il numero massimo di invii per Riscontro che un singolo nodo egress registrerà in un run.

Un nodo con **One Message per Finding** attivato produce una riga di delivery e un task in coda per ogni Riscontro. Poiché un run non ha un limite di elementi, una regola con uno scope molto ampio e l'invio per-Riscontro attivo produrrebbe altrimenti un numero illimitato di entrambi.

Oltre questo tetto il nodo registra un'**omissione visibile** che indica quanti Riscontri non ha inviato. Non fa fallire il run, e non si ferma silenziosamente.

## Impostazioni correlate

Alcuni nodi di Rules Engine 2.0 usano la configurazione di integrazione a livello di sistema invece della propria:

* **Send a Slack Message** usa il token Slack di sistema, e ricade sul canale Slack di sistema quando il nodo non ne indica uno.
* **Send a Microsoft Teams Message** usa il webhook Microsoft Teams dalle impostazioni di sistema.
* **Create a JIRA Issue** usa la configurazione JIRA del prodotto per il riepilogo, la descrizione e la priorità.
* **Raise an In-App Alert** rispetta l'impostazione di notifica **Rules Engine Match** di ciascun destinatario.
