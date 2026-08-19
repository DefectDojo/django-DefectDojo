---
title: Costruire regole
description: L'editor a grafo, i trigger, lo scope, le condizioni e i template dei
  messaggi
weight: 2
audience: pro
aliases:
- /it/automation/rules_engine_v2/building_rules/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 è una funzionalità disponibile solo in DefectDojo Pro.</span>

Una regola si costruisce su una canvas. Si trascinano nodi da una palette, si collegano tra loro e si configura ciascuno in un pannello laterale. Questa pagina tratta le parti di questo processo che sono le stesse indipendentemente dai nodi usati. I nodi stessi sono descritti in [Node Reference](../node_reference/).

## L'editor

Aprire **Rules Engine 2.0 > All Rules** e scegliere **New Rule**, oppure aprire una regola esistente per modificarla.

La palette è raggruppata in quattro categorie, che rappresentano anche l'ordine in cui gli elementi attraversano un grafo tipico:

| Categoria | Cosa fanno i nodi |
|----------|-------------------|
| **Triggers** | Decidono quando la regola si attiva e quali Riscontri vi entrano. Esattamente uno per grafo. |
| **Logic** | Instradano, limitano e deduplicano gli elementi che vi passano attraverso. |
| **Findings** | Modificano i Riscontri. |
| **Egress** | Inviano qualcosa verso l'esterno: un ticket, un messaggio, un report. |

La palette viene generata dal motore stesso, quindi ciò che si vede nell'editor è sempre esattamente ciò che il motore può eseguire.

### Regole del grafo

Un grafo viene verificato al salvataggio, e di nuovo prima di ogni run. Deve soddisfare tutte le condizioni seguenti:

* Ha almeno un nodo.
* Ha **esattamente un** nodo trigger.
* Ogni nodo ha un id univoco e non vuoto di 100 caratteri o meno.
* Ogni nodo è di un tipo che il motore conosce.
* Ogni arco collega due nodi esistenti.
* Non contiene cicli.

Un nodo senza nulla collegato in ingresso è ammesso. Viene eseguito con un elenco di input vuoto, il che di norma significa che non fa nulla.

Un nodo con più archi in ingresso riceve tutti i loro output concatenati.

### Anteprima prima di salvare

**Preview** esegue a secco il grafo attualmente presente sulla canvas e mostra la traccia per nodo che produrrebbe: quanti elementi sono entrati in ciascun nodo, quanti sono usciti da ciascuna uscita e cosa ciascun nodo avrebbe modificato.

Preview esegue il motore reale, non una sua simulazione, e poi annulla tutto. Non viene scritto nulla, non viene registrato alcun run, e l'egress è forzato a simulare qualunque cosa dica la modalità della regola. È il modo più rapido per verificare che le condizioni corrispondano a quanto ci si aspettava.

Preview è l'unica esecuzione che limita quanti Riscontri esamina, in modo da restare veloce. Quando tronca, lo segnala nella traccia. Un run reale non ha un limite del genere.

## Trigger e scope

Ogni grafo inizia con uno dei tre trigger.

* **On Finding Event** attiva la regola quando i Riscontri vengono creati, aggiornati, chiusi o riaperti. Scegliere quale di questi nell'impostazione **Event** del nodo, oppure `any` per tutti e quattro.
* **On a Schedule** esamina i Riscontri secondo una pianificazione ricorrente.
* **Manual Run** esamina i Riscontri quando si preme **Run** sulla regola.

### Scope

Tutti e tre i trigger accettano uno **Scope**, ed è tramite lo scope che si restringe ciò che la regola considera. È lo stesso vocabolario di filtri usato dal Rules Engine originale, circa sessanta filtri che coprono i Riscontri e gli oggetti che li circondano, quindi un filtro che si sa già scrivere lì significa la stessa cosa qui.

Due cose sullo scope vale la pena capire:

* **Lo scope si applica sopra l'autorizzazione, mai al suo posto.** La regola viene eseguita come il suo proprietario, quindi lo scope restringe un insieme di Riscontri già autorizzato. Lasciare lo scope vuoto non significa "tutti i Riscontri dell'istanza", significa "tutti i Riscontri che il proprietario della regola può vedere".
* **Uno scope non valido fa fallire il run invece di ampliarlo.** Se una chiave di filtro non esiste, o un valore è tale che il filtro lo scarterebbe silenziosamente, il run termina con un errore. Una regola che non fa nulla è recuperabile. Una regola che modifica silenziosamente ogni Riscontro dell'istanza non lo è.

Per un trigger a evento, lo scope funge da secondo cancello: i Riscontri indicati nell'evento vengono confrontati con esso, e solo quelli che passano entrano nel grafo.

### Pianificazione

Una regola il cui trigger è **On a Schedule** viene pianificata dalla regola stessa. Impostare la pianificazione richiede Rule Edit, lo stesso permesso richiesto per modificare la regola, perché una regola attivata da pianificazione non fa nulla finché non ne ha una.

Le pianificazioni sono limitate a intervalli di un quarto d'ora. Il campo dei minuti di un'espressione cron deve essere `0`, `15`, `30` o `45`.

Esempi validi:

```
0 * * * *     every hour, on the hour
15 9 * * *    every day at 09:15
0 15 * * 1    every Monday at 15:00
30 2 * * *    every day at 02:30
```

## Fare riferimento ai dati di un Riscontro

Due punti di una regola leggono valori dall'elemento che vi passa attraverso: le **condizioni** e i **template**. Entrambi usano gli stessi percorsi puntati.

```
finding.severity
finding.title
finding.vulnerability_ids.0
product.name
product_type.name
test.scan_type
ctx.rule_name
```

Un percorso che non si risolve produce l'assenza di valore, non un errore.

### Campi disponibili

Ogni elemento porta con sé un insieme fisso di campi del Riscontro. Questo elenco è un contratto, quindi cambia solo in modo deliberato.

| Gruppo | Campi |
|-------|--------|
| Identità | `id`, `title`, `hash_code`, `unique_id_from_tool` |
| Gravità e punteggio | `severity`, `numerical_severity`, `cvssv3`, `cvssv3_score`, `epss_score`, `epss_percentile`, `priority`, `risk`, `risk_score` |
| Testo | `description`, `mitigation`, `impact` |
| Stato | `active`, `verified`, `false_p`, `duplicate`, `is_mitigated`, `out_of_scope`, `risk_accepted`, `under_review` |
| Date | `date`, `mitigated`, `last_status_update`, `sla_expiration_date` |
| Posizione | `file_path`, `line`, `component_name`, `component_version`, `service` |
| Classificazione | `cwe`, `vulnerability_ids`, `tags` |

Oltre a `finding`, ogni elemento porta con sé `test` (`id`, `title`, `scan_type`), `engagement` (`id`, `name`), `product` (`id`, `name`), `product_type` (`id`, `name`) e `ctx`.

Le date sono stringhe ISO-8601. Ciò è deliberato: significa che `gt` e `lt` le ordinano correttamente come testo, quindi `2026-07-28` è correttamente maggiore di `2026-01-01`.

`priority`, `risk` e `risk_score` provengono dalla prioritizzazione di Pro. Un Riscontro non ancora valutato non porta alcun valore per essi.

### Condizioni

Un nodo **If / Filter** contiene un elenco di righe di condizione. Ogni riga è un percorso, un operatore e un valore. **Match** decide se ogni riga deve essere vera (`all`) oppure basta che lo sia una sola (`any`).

| Operatore | Significato |
|----------|---------|
| `eq` | è uguale a |
| `neq` | non è uguale a |
| `contains` | contiene |
| `not_contains` | non contiene |
| `in` | è uno tra |
| `not_in` | non è uno tra |
| `gt` | è maggiore di |
| `gte` | è maggiore o uguale a |
| `lt` | è minore di |
| `lte` | è minore o uguale a |
| `startswith` | inizia con |
| `endswith` | finisce con |
| `exists` | è impostato |
| `not_exists` | non è impostato |

I confronti sono **permissivi**. Si prova prima come numero, e se fallisce i valori vengono confrontati come testo con spazi rimossi e senza distinzione tra maiuscole e minuscole. Quindi una condizione scritta come `finding.severity eq high` corrisponde a un Riscontro la cui gravità è `High`, che è quasi sempre ciò che l'autore intendeva.

#### Trasformazioni

Una riga di condizione può post-elaborare il valore letto prima di confrontarlo.

| Trasformazione | Effetto |
|-----------|--------|
| `int` | numero intero |
| `float` | numero decimale |
| `str` | testo |
| `first` | primo elemento di una lista |
| `list` | come lista |
| `join` | unito con virgole |
| `upper` | MAIUSCOLO |
| `lower` | minuscolo |
| `strip` | con spazi rimossi |
| `cwe_int` | numero CWE |
| `severity` | gravità normalizzata, così valori in stile `critical`, `error` e `warning` provenienti da scanner diversi vengono mappati sui cinque livelli di DefectDojo |
| `numerical_severity` | codice di gravità ordinabile, per i confronti di ordinamento |

### Template

Qualsiasi impostazione etichettata come messaggio, nota, titolo o valore accetta segnaposto `{{ percorso }}`, risolti per ciascun elemento:

```
{{finding.severity}}: {{finding.title}} ({{product.name}})
```

Un percorso senza valore viene reso come stringa vuota. Una lista viene resa unita da virgole.

I template vedono anche un blocco `ctx` che porta dettagli sul run stesso. Le chiavi disponibili dipendono dal nodo, ma quelle comuni sono:

| Segnaposto | Significato |
|-------------|---------|
| `{{ctx.rule_name}}` | Il nome della regola |
| `{{ctx.count}}` | Quanti Riscontri copre il messaggio |
| `{{ctx.trigger}}` | L'evento che ha avviato il run |
| `{{ctx.findings_html}}` | L'elenco dei Riscontri renderizzato, nel nodo email |
| `{{ctx.report_url}}` | Il link di download, nel nodo report |
| `{{ctx.template_name}}` | Il nome del template di report, nel nodo report |

I template sono pura sostituzione. Non c'è valutazione di espressioni, non c'è esecuzione di codice, e non c'è accesso ad attributi di oggetti in nessun punto della configurazione di una regola.

## Testare una regola in sicurezza

L'ordine consigliato per una regola che invia qualcosa:

1. Costruire il grafo e usare **Preview** finché i conteggi degli elementi non sembrano corretti.
2. Salvarla. Le nuove regole vengono create disabilitate.
3. Lasciare la modalità su **Simulate** e abilitare la regola.
4. Farla eseguire, poi leggere **Deliveries** e verificare che i payload registrati siano quelli previsti.
5. Passare la modalità a **Live**.

Simulate non è un'esecuzione parziale. Ogni modifica a un Riscontro nel grafo avviene realmente in modalità simulate. Vengono trattenuti solo gli invii in uscita.
