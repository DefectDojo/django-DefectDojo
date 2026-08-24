---
title: Consegne
description: Il registro di tutto ciò che le regole inviano verso l'esterno, e come
  funzionano i nuovi tentativi e i reinvii
weight: 5
audience: pro
aliases:
- /it/automation/rules_engine_v2/deliveries/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 è una funzionalità disponibile solo in DefectDojo Pro.</span>

Ogni effetto collaterale in uscita prodotto da una regola corrisponde a una riga nel registro delle consegne. **Rules Engine 2.0 > Consegne** le elenca.

La riga viene scritta **prima** che avvenga qualsiasi chiamata di rete e contiene esattamente ciò che verrà, o è stato, inviato. Questo è ciò che rende l'uscita dei dati verificabile, invece di essere una riga di log che si spera qualcuno abbia conservato, ed è il motivo per cui **Simulazione** non è un percorso di codice separato: un invio simulato è la stessa riga con il passaggio di dispatch saltato.

## Cosa registra una consegna

| Campo | Significato |
|-------|---------|
| **Esecuzione** e **Nodo** | L'esecuzione e il nodo di uscita che l'hanno prodotta. |
| **Riscontro** | Il Riscontro a cui si riferisce, per un invio per singolo Riscontro. Gli invii in batch registrano invece il gruppo. |
| **Canale** | Il tipo di invio. |
| **Destinazione** | La destinazione risolta: una chiave di progetto JIRA, un canale, un URL, un indirizzo. |
| **Titolo** | Una descrizione dell'invio su una riga. |
| **Payload** | Esattamente ciò che verrà, o è stato, inviato. |
| **Modalità** | `simulate` o `live`. |
| **Stato** | A che punto è arrivata la consegna. |
| **Tentativi** | Quanti invii sono stati tentati, rispetto al massimo consentito. |
| **Ultimo errore** | Il motivo per cui l'ultimo tentativo non è riuscito, o per cui la consegna è stata saltata. |
| **Risposta** | Cosa ha risposto la destinazione. |
| **Riferimento esterno** e **URL** | La chiave del ticket, l'ID del messaggio o il percorso del file restituiti dalla destinazione, e un link ad esso quando disponibile. |

## Canali

| Canale | Prodotto da |
|---------|-------------|
| **JIRA** | Crea un problema JIRA |
| **Connettore downstream** | Crea un ticket downstream |
| **Slack** | Invia un messaggio Slack e annunci di report inviati a Slack |
| **Microsoft Teams** | Invia un messaggio Microsoft Teams |
| **Email** | Invia un'email e annunci di report inviati via email |
| **Webhook** | Chiama un webhook |
| **Report** | Genera un report |
| **Avviso in-app** | Genera un avviso in-app |

## Stati

| Stato | Significato |
|--------|---------|
| `simulated` | La regola era in modalità Simulazione. Non è stato inviato nulla, e nulla verrà mai inviato. |
| `skipped` | Qualcos'altro copriva già questo invio, oppure il gating lo ha rifiutato. Il motivo si trova nel campo dell'ultimo errore. |
| `pending` | Registrata in modalità Live, in attesa del task di consegna. |
| `dispatched` | Passata al servizio di integrazione, in attesa di conferma. |
| `sent` | Consegna confermata. |
| `failed` | Rifiutata in modo permanente, ad esempio un errore 4xx o un errore del vendor. Può essere reinviata. |
| `dead` | Tentativi esauriti, oppure non è mai arrivata alcuna conferma. Può essere reinviata. |

Vale la pena soffermarsi su `skipped`. I salti vengono registrati invece di passare inosservati, perché "la regola non ha fatto nulla" e "la regola non ha fatto nulla perché questo Riscontro aveva già un ticket" sono risposte diverse, e solo una delle due è un problema.

Ci sono tre motivi comuni per un salto, e il campo dell'ultimo errore indica sempre quale:

* **Idempotenza.** Qualcos'altro copriva già questo invio.
* **Il canale è disattivato.** Una regola con un nodo Slack su un'istanza in cui Slack è disabilitato registra un salto che lo spiega, invece di fallire. Una regola salvata mentre un canale era attivo non dovrebbe iniziare a generare errori quando qualcuno lo disattiva. Vedere [disponibilità dei nodi](../node_reference/#when-a-channel-is-unavailable).
* **È stato raggiunto il limite di invio per singolo Riscontro.** Un nodo che invia un messaggio per ogni Riscontro si ferma per impostazione predefinita dopo 1.000 invii in una singola esecuzione, e registra per quanti Riscontri non ha inviato nulla.

### Fedeltà del payload

Il registro è trasparente su quanto il payload registrato sia vicino al corpo effettivamente trasmesso, perché questo varia in base al canale.

| Fedeltà | Significato |
|----------|---------|
| `exact` | Byte-equivalente a ciò che è stato inviato. |
| `rendered` | Renderizzato dagli helper reali, ma il gating al momento dell'invio può comunque ridurlo. |
| `dojo request` | La richiesta esatta passata al servizio di integrazione. Il payload specifico del vendor viene composto a valle. |
| `summary` | Una descrizione dell'invio piuttosto che una sua riproduzione. Un report generato ne è l'esempio: il file viene costruito con dati live al momento dell'invio, quindi una copia salvata sarebbe errata non appena qualcosa cambiasse. |

## La protezione contro i doppi invii

Può esistere una sola consegna **attiva** per chiave di idempotenza, imposto a livello di database piuttosto che per convenzione. Attiva significa `pending`, `dispatched` o `sent`.

Un secondo invio che entrerebbe in collisione con uno attivo diventa una riga `skipped` con il motivo registrato. Non è mai un'operazione nulla silenziosa, e non è mai un ticket duplicato.

Poiché le righe `simulated`, `skipped`, `failed` e `dead` non mantengono una prenotazione, una consegna non riuscita può essere reinviata al suo posto senza che una seconda riga la contenda per la stessa chiave.

## Nuovi tentativi

Una consegna live viene ritentata automaticamente. Ogni riga porta con sé il proprio conteggio dei tentativi e il proprio limite massimo, sei tentativi per impostazione predefinita, in modo che una destinazione che fallisce non possa trascinare con sé le altre. I nuovi tentativi vengono distanziati progressivamente tra un tentativo e l'altro.

Quando l'ultimo tentativo è stato consumato, la riga viene contrassegnata come `dead` invece di rimanere ferma su `pending`. L'esaurimento dei tentativi è visibile, non silenzioso.

Se un worker viene interrotto a metà dell'invio, il messaggio viene riconsegnato. La riga viene bloccata e il suo stato viene ricontrollato prima che venga inviato nuovamente qualcosa, in modo che una riconsegna non possa trasformarsi in un doppio invio.

Le consegne passate al servizio di integrazione passano a `dispatched` e attendono un callback di conferma. Se non arriva alcun callback entro sei ore, la riga viene contrassegnata come `dead` in modo che possa essere reinviata. Questa finestra temporale è deliberatamente ampia: un accumulo nella coda a valle per un'ora è normale, e archiviare una riga con troppa fretta trasformerebbe un reinvio in un ticket duplicato.

## Reinviare una consegna

Una consegna `failed` o `dead` può essere reinviata dalla pagina Consegne. Il registro riporta quando è stata reinviata e da chi.

Il reinvio richiede il permesso **Modifica regola**.

Il reinvio invia nuovamente il payload registrato. Per un report, questo rigenera il report a partire dai dati correnti, perché il payload è una descrizione di cosa generare piuttosto che il file stesso.

## Simulazione

In modalità Simulazione, ogni nodo di uscita scrive la propria riga di consegna con stato `simulated`, payload completo e destinazione risolta, quindi si ferma. Non viene registrato alcun dispatch, quindi nulla può essere inviato in seguito, indipendentemente da come si conclude l'esecuzione. L'anteprima si comporta allo stesso modo, e non inserisce nemmeno le righe.

Questo è il modo previsto per rivedere una regola prima di renderla operativa: abilitarla in modalità Simulazione, lasciarla eseguire su Riscontri reali, quindi leggere i payload che ha registrato.

Da tenere presente che la Simulazione blocca **solo** gli invii in uscita. I nodi sui Riscontri continuano comunque a modificare i Riscontri.

## Conservazione

Le consegne vengono conservate per **180 giorni** per impostazione predefinita, dopodiché un job di conservazione le elimina.

Questa è la tabella che cresce più velocemente in questa funzionalità, perché un nodo che invia un messaggio per ogni Riscontro scrive una riga per ogni Riscontro, sia in modalità Simulazione sia in Live. Il valore predefinito è una finestra reale anziché "conserva tutto", in modo che la crescita non diventi silenziosamente un problema per l'utente.

L'utente ne viene informato invece di doverlo scoprire da solo. Il dettaglio di una consegna mostra la finestra di conservazione e la data in cui quella riga verrà eliminata, e la data viene ricalcolata a ogni lettura, quindi modificare la finestra ha effetto immediatamente.

Impostare una finestra più lunga se è necessaria una traccia di controllo delle uscite più estesa, oppure `0` per conservare tutto. Vedere [Configurazione](../configuration/#retention).
