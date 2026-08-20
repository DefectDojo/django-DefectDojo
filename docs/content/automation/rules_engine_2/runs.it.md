---
title: Esecuzioni
description: Come viene eseguita una regola, cosa registra un'esecuzione e come viene
  limitata la propagazione a cascata
weight: 4
audience: pro
aliases:
- /it/automation/rules_engine_v2/runs/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 è una funzionalità disponibile solo in DefectDojo Pro.</span>

Un **run** è una singola esecuzione di una regola. Ogni run viene registrato, sia che abbia avuto esito positivo sia che sia fallito, e ogni nodo al suo interno lascia una traccia. **Rules Engine 2.0 > Runs** li elenca.

## Cosa registra un run

| Campo | Significato |
|-------|---------|
| **Rule** | La regola che è stata eseguita. |
| **Trigger** | L'evento che lo ha avviato, ad esempio `finding.created`, `schedule` o `manual`. |
| **Triggered by** | La persona che lo ha avviato, quando una persona lo ha fatto: chi ha premuto Run, oppure chi ha salvato il Finding che lo ha attivato. Vuoto per una pianificazione, e per una modifica alla quale nessuno era presente, come un'importazione o una chiamata API senza utente. Questo campo è distinto dal proprietario della regola, che è l'identità con cui il run viene eseguito. |
| **Status** | `Running`, `Success` o `Error`. |
| **Started** e **Finished** | Quando è stato eseguito. Finished è vuoto solo mentre è ancora in esecuzione. |
| **Error** | L'errore che lo ha terminato, in caso di fallimento. |
| **Stats** | Totali per nodo, eventi a cascata e lavoro differito. |
| **Depth** | Quanti passaggi a cascata separano questo run dall'evento che lo ha originato. |
| **Source run** | Il run il cui evento emesso ha attivato questo, nel caso di un run a cascata. |

### La traccia dei nodi

All'interno di un run, ogni nodo registra una propria riga:

| Campo | Significato |
|-------|---------|
| **Order** | La posizione del nodo nell'ordine di esecuzione. |
| **Node** | Il suo id, il suo tipo e la sua etichetta, se ne è stata assegnata una. |
| **Status** | Se il nodo è stato completato o ha generato un errore. |
| **Items in** | Quanti elementi sono entrati. |
| **Items out** | Quanti ne sono usciti, suddivisi per handle di output, in modo che un nodo If / Filter mostri separatamente i conteggi true e false. |
| **Summary** | I contatori riportati dal nodo, ad esempio quanti Finding ha modificato. |
| **Error** | L'errore generato, in caso di fallimento. |

La traccia è ciò che si consulta quando una regola non ha fatto ciò che ci si aspettava. Un nodo If / Filter che riporta 400 elementi in ingresso e 0 sul ramo true indica che le condizioni sono sbagliate, senza dover indovinare.

## Modello di esecuzione

I nodi vengono eseguiti in ordine topologico: un nodo viene eseguito solo dopo che tutto ciò che lo alimenta è stato eseguito. Un nodo con più archi in ingresso riceve tutti i relativi output concatenati. Un nodo privo di input viene comunque eseguito, con un elenco di input vuoto.

### Un run fallito non cambia nulla

Un run è atomico. Se un nodo genera un errore, ogni modifica ai Finding effettuata dal run viene annullata (rollback).

La traccia non viene annullata insieme al resto. Le righe dei nodi e lo stato `Error` vengono scritti in seguito, quindi un run fallito indica esattamente quale nodo si è rotto senza lasciare modifiche parzialmente applicate. Questa è la garanzia più importante da tenere presente leggendo la pagina Runs: un run in errore è un run che non ha fatto nulla.

L'egress segue la stessa regola. Le consegne (deliveries) vengono registrate all'interno della transazione del run e vengono inviate solo dopo il commit, quindi un run che viene annullato non invia nulla.

### Un solo run per regola alla volta

Una regola può avere un solo run in corso. Un secondo trigger per la stessa regola mentre è ancora in esecuzione non entra in competizione con essa: attende e riprova.

Regole diverse vengono eseguite in modo completamente concorrente, quindi una regola lenta non blocca mai le altre.

Se un run viene in qualche modo abbandonato, ad esempio perché il worker che lo eseguiva è stato terminato, il suo lock viene rilasciato dopo una finestra di stallo (30 minuti per impostazione predefinita), in modo che la regola non resti bloccata per sempre. Un run che si avvicina a questa soglia si interrompe da solo per primo, annullandosi in modo pulito, così un run semplicemente lento non può mai finire per essere eseguito insieme alla propria sostituzione.

## Cascata

Una regola che modifica un Finding produce esattamente il tipo di evento su cui un'altra regola può attivarsi. Rules Engine 2.0 lo consente, quindi catene del tipo `A -> B -> C` funzionano, e le limita in due modi indipendenti:

* **Profondità.** Un evento può percorrere al massimo **3** passaggi a cascata dalla modifica che lo ha originato.
* **Appartenenza alla catena.** Ogni evento porta con sé l'elenco delle regole già attraversate nella sua catena, e una regola non viene mai eseguita due volte nella stessa catena. Quindi una regola non può riattivare se stessa, e due regole non possono rimbalzare tra loro.

I campi **Depth** e **Source run** di un run permettono di risalire una catena fino alla modifica che l'ha avviata. **Triggered by** viene trasmesso lungo tutta la catena, quindi una cascata avviata da una persona resta attribuibile a quella persona a ogni passaggio.

Le modifiche effettuate *da* una regola in esecuzione vengono attribuite alla cascata di quella regola, invece di apparire come nuova attività dell'utente, così una regola che delega lavoro internamente non gonfia la catena.

## Scala e limiti

**Un run non ha un limite massimo.** Una regola elabora tutto ciò che corrisponde al suo ambito, per quanto grande sia. Una regola che si fermasse silenziosamente ai primi N Finding sarebbe una regola di cui non ci si potrebbe fidare.

Un run viene invece elaborato in **blocchi (chunk)**, 1.000 Finding alla volta per impostazione predefinita. Solo il blocco corrente viene mantenuto in memoria, quindi una scansione su un ambito molto ampio è limitata in memoria, non in copertura. L'unica eccezione è **Preview**, che applica un limite e lo segnala nella propria traccia quando tronca i risultati.

Altri due numeri determinano come viene suddiviso il lavoro:

* **Finding per evento**, 500 per impostazione predefinita. Una modifica in blocco viene suddivisa su più eventi, ciascuno dei quali diventa un proprio run. L'effetto pratico per un'importazione di grandi dimensioni è un numero gestibile di run, invece di un run per ogni Finding.
* **Limite di invio per Finding**, 1.000 per impostazione predefinita. Un nodo di egress impostato per inviare un messaggio per ogni Finding si ferma a questo numero all'interno di un singolo run e registra uno skip visibile che indica per quanti Finding non ha inviato nulla. Questo limita le righe di consegna e le attività in coda, che un run suddiviso in blocchi non limita più da solo.

Tutti e tre sono impostazioni di deployment, documentate in [Configuration](../configuration/).

### Quanto può durare un run

Un run registra un **heartbeat** dopo ogni blocco. Il rilevamento dello stallo legge questo heartbeat anziché l'orario di avvio, quindi una scansione lunga che sta ancora facendo progressi non viene mai scambiata per un worker bloccato.

Si applicano due finestre temporali, entrambe configurabili:

* Un run che rimane 30 minuti senza heartbeat viene considerato abbandonato, segnato come errore, e il suo lock viene rilasciato.
* Un run viene terminato forzatamente dopo sei ore, come protezione contro un run che non finirebbe mai.

## Conservazione

I run vengono conservati per **180 giorni** per impostazione predefinita, insieme alle relative righe per nodo e alla provenienza dei Finding. Le consegne (deliveries) vengono conservate per 180 giorni separatamente.

Il prodotto lo comunica esplicitamente, invece di lasciarlo implicito: il dettaglio di un run mostra la finestra di conservazione e la data in cui quel run verrà eliminato. Un run che detiene ancora consegne viene mantenuto finché queste non vengono rimosse.

Entrambe le finestre sono configurabili, ed è possibile impostarne una qualsiasi per conservare i record a tempo indeterminato. Vedere [Configuration](../configuration/#retention).

## Eseguire una regola manualmente

Una regola il cui trigger è **Manual Run** viene eseguita con l'azione **Run** nell'elenco delle regole. Le regole con altri trigger vengono eseguite quando il rispettivo trigger scatta.

**Preview**, nell'editor, è l'altro modo per eseguire un grafo. Esegue il motore reale e poi annulla tutto, non registra alcun run, e forza l'egress a simulare. Usa preview mentre costruisci, e i run per vedere cosa è realmente successo.

## Provenienza su un Finding

I run rispondono alla domanda "cosa ha fatto questa regola?". La provenienza risponde alla domanda opposta: "perché questo Finding è cambiato?".

Ogni modifica effettuata da una regola viene registrata a fronte del Finding con la regola, il run e il nodo responsabili, e appare come una timeline sul Finding stesso. Le azioni registrate sono:

| Azione | Significato |
|--------|---------|
| `created`, `updated`, `closed`, `reopened` | Il ciclo di vita del Finding è cambiato. |
| `duplicate`, `status_change` | I suoi flag di duplicato o di stato sono cambiati. |
| `notified` | È stata inviata una notifica a riguardo. |
| `delivered` | Una consegna in uscita lo ha riguardato. |

Le modifiche ai campi registrano cosa è cambiato, incluso il valore precedente e successivo di ogni campo. I valori molto lunghi vengono troncati nel record, in modo che la timeline resti una registrazione della modifica e non una seconda copia del Finding.

Anche le notifiche e le consegne vengono registrate qui. È una scelta deliberata: una regola che ha inviato un messaggio ma non ha modificato alcun campo altrimenti non lascerebbe alcuna traccia sul Finding.

La provenienza sopravvive alla regola. Eliminare una regola o un run mantiene le voci della timeline e si limita a scollegarle, così la cronologia non scompare quando qualcuno fa pulizia.

## Eliminare regole con cronologia

Una regola che ha prodotto delle consegne non può essere eliminata lasciandole orfane. Elimina prima le consegne, oppure mantieni la regola e disattivala. Questo è intenzionale: le consegne conservano il record di ciò che è stato effettivamente inviato ai sistemi esterni, e un'eliminazione a cascata trascinerebbe con sé gli invii in corso.
