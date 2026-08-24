---
title: Riferimento dei nodi
description: Tutti i nodi inclusi in Rules Engine 2.0, e cosa fa ciascuno
weight: 3
audience: pro
aliases:
- /it/automation/rules_engine_v2/node_reference/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 è una funzionalità disponibile solo in DefectDojo Pro.</span>

Rules Engine 2.0 include 25 nodi suddivisi in quattro categorie. Questa pagina li documenta tutti.

Salvo diversa indicazione, un nodo accetta un input, produce un output chiamato `out` e passa a quell'output ogni elemento ricevuto. Questo è rilevante quando si concatenano i nodi: un nodo sui Riscontri modifica il Riscontro e poi passa l'elemento avanti, quindi più nodi in sequenza vengono applicati tutti.

## Trigger

Ogni grafo ha esattamente un trigger, e solo un trigger può avviare un'esecuzione. Tutti e tre producono elementi Riscontro e tutti e tre accettano un **Ambito** che restringe quali Riscontri producono. Vedere [Creazione delle regole](../building_rules/) per il funzionamento dell'ambito.

### Al verificarsi di un evento sul Riscontro

`trigger.finding`

Viene eseguito quando i Riscontri vengono creati, aggiornati, chiusi o riaperti.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Evento** | `created` | Quale modifica al Riscontro attiva questa regola: `created`, `updated`, `closed`, `reopened`, oppure `any` per tutte e quattro. |
| **Ambito** | vuoto | Quali Riscontri considera questa regola. Vuoto significa ogni Riscontro visibile al proprietario della regola. |

I Riscontri indicati dall'evento vengono confrontati con l'ambito prima di entrare nel grafo, quindi l'evento decide *quando* e l'ambito decide *quali*.

### Su pianificazione

`trigger.schedule`

Scansiona tutti i Riscontri nell'ambito secondo una pianificazione. La pianificazione viene configurata sulla regola ed è limitata a intervalli di un quarto d'ora.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Ambito** | vuoto | Quali Riscontri considera questa regola. |

### Esecuzione manuale

`trigger.manual`

Scansiona tutti i Riscontri nell'ambito quando si preme **Esegui** sulla regola.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Ambito** | vuoto | Quali Riscontri considera questa regola. |

## Logica

### Se / Filtro

`filter.if`

Instrada ogni elemento lungo il ramo **true** o **false**, in base a delle condizioni. È l'unico nodo con due output, ed è il modo in cui un grafo si dirama.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Condizioni** | vuoto | Ogni riga è un percorso, un operatore e un valore. Vedere [Condizioni](../building_rules/#conditions). |
| **Corrispondenza** | `all` | Se tutte le condizioni devono essere vere (`all`), oppure solo una di esse (`any`). |

Un elenco di condizioni vuoto fa passare tutto lungo il ramo true. Entrambi i rami sono opzionali: lasciare il ramo false non collegato scarta semplicemente gli elementi che non hanno soddisfatto la condizione.

### Limite

`flow.limit`

Fa passare i primi N elementi e scarta il resto. Utile come valvola di sicurezza durante il test di una regola, e per limitare quanti ticket o messaggi può produrre una singola esecuzione.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Mantieni i primi** | `100` | Quanti elementi far passare. |

### Deduplica all'interno dell'esecuzione

`flow.dedupe_batch`

Mantiene il primo elemento per ogni chiave e scarta quelli successivi con la stessa chiave. Limitato all'esecuzione corrente, quindi deduplica all'interno di una singola esecuzione e non tra esecuzioni diverse.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Percorso chiave** | `finding.hash_code` | Il percorso dell'elemento il cui valore identifica un duplicato. |

Un uso comune è `finding.component_name`, per notificare una volta per ogni componente interessato invece che una volta per Riscontro.

## Riscontri

Questi nodi modificano i Riscontri. Ogni modifica viene attribuita alla regola, all'esecuzione e al nodo che l'ha effettuata, e compare nella cronologia di provenienza del Riscontro.

### Imposta gravità

`finding.set_severity`

Imposta la gravità e ricalcola di conseguenza la data SLA e la priorità.

| Impostazione | Opzioni |
|---------|---------|
| **Gravità** | `Critical`, `High`, `Medium`, `Low`, `Info` |

### Imposta un campo

`finding.set_field`

Imposta, aggiunge in coda, oppure antepone il testo a un campo testuale.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Campo** | nessuno | Uno tra `component_name`, `component_version`, `cvssv3`, `cwe`, `description`, `file_path`, `impact`, `mitigation`, `service`, `title`. |
| **Modalità** | `set` | `set`, `append` o `prepend`. Un vettore CVSSv3 può essere solo sostituito. |
| **Valore** | nessuno | Il testo da scrivere. Supporta segnaposto in stile `{{finding.title}}`. |

### Imposta stato

`finding.set_status`

Sposta il Riscontro in uno stato.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Stato** | nessuno | `active`, `inactive`, `verified`, `unverified`, `false_positive`, `mitigated`, `reopen`. |
| **Nota** | vuoto | Una nota facoltativa registrata insieme alla modifica dello stato. |

### Aggiungi tag

`finding.add_tags`

Aggiunge tag al Riscontro. I tag esistenti vengono mantenuti.

| Impostazione | Note |
|---------|-------|
| **Tag** | Separati da virgola. Supporta segnaposto in stile `{{product.name}}`, per taggare con dati provenienti dal Riscontro. |

### Aggiungi una nota

`finding.add_note`

Aggiunge una nota al Riscontro.

| Impostazione | Note |
|---------|-------|
| **Nota** | Il testo della nota. Supporta i segnaposto. |

### Imposta proprietari

`finding.set_owners`

Rende un gruppo responsabile del Riscontro.

| Impostazione | Note |
|---------|-------|
| **Gruppo** | Il gruppo proprietario di questi Riscontri. |

### Imposta revisori

`finding.set_reviewers`

Sottopone il Riscontro alla revisione degli utenti selezionati.

| Impostazione | Note |
|---------|-------|
| **Revisori** | Uno o più utenti che devono revisionare questi Riscontri. |

### Accetta rischio

`finding.risk_accept`

Applica l'accettazione semplice del rischio al Riscontro, oppure lo aggiunge a un record di accettazione del rischio.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Come** | `simple` | `simple` imposta l'accettazione semplice del rischio sul Riscontro. `acceptance` lo aggiunge a un record di accettazione del rischio. |
| **Accettato** | attivo | Visibile per `simple`. Disattivare per annullare l'accettazione del rischio. |
| **Accettazione del rischio** | nessuno | Visibile per `acceptance`. A quale accettazione del rischio aggiungere questi Riscontri. |

### Imposta policy di mitigazione

`finding.set_mitigation_policy`

Imposta la policy di mitigazione in base alla quale il Riscontro viene risolto.

| Impostazione | Note |
|---------|-------|
| **Policy di mitigazione** | La policy da applicare. |

### Cambia priorità

`finding.set_priority`

Imposta la priorità, oppure la modifica aritmeticamente. Questo sovrascrive la priorità calcolata.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Operazione** | `set` | `set`, `add`, `subtract`, `multiply`, `divide`. |
| **Valore** | nessuno | La priorità da impostare, oppure la quantità di cui modificarla. |

### Imposta rischio

`finding.set_risk`

Imposta il rischio, sovrascrivendo quello calcolato.

| Impostazione | Opzioni |
|---------|---------|
| **Rischio** | `Low`, `Medium`, `Needs Action`, `Urgent` |

## Uscita

I nodi di uscita sono i nodi che escono da DefectDojo. Ognuno di essi registra una [Consegna](../deliveries/) prima che venga inviato qualsiasi cosa, ed ognuno rispetta la modalità **Simulazione** o **Live** della regola.

Diversi di essi offrono la stessa opzione **Un messaggio per Riscontro**. Se disattivata, il nodo invia un unico messaggio che descrive l'intero batch, con una ripartizione per gravità e un elenco limitato di Riscontri. Se attivata, invia un messaggio per ogni Riscontro.

Un nodo che invia un messaggio per ogni Riscontro si ferma per impostazione predefinita dopo 1.000 invii in una singola esecuzione, e registra un salto visibile che indica per quanti Riscontri non ha inviato nulla. Vedere [Configurazione](../configuration/#per-finding-send-ceiling).

### Quando un canale non è disponibile

Un nodo di uscita dipende da qualcosa esterno alla regola: un token Slack, un webhook Microsoft Teams, una configurazione JIRA, un connettore con licenza. Quando questo manca o è disattivato, il nodo non può funzionare, e Rules Engine 2.0 lo segnala in tre momenti diversi invece di fallire silenziosamente:

* **Nella tavolozza**, un nodo non disponibile viene contrassegnato come tale, con il motivo, prima che venga trascinato sul canvas.
* **Al salvataggio**, un grafo che contiene un nodo non disponibile viene rifiutato. È il momento in cui qualcuno è presente per sceglierne uno diverso.
* **In fase di esecuzione**, la consegna viene **saltata** con il motivo allegato, non fallita. Una regola salvata mentre Slack era attivo non dovrebbe iniziare a generare errori il giorno in cui qualcuno disattiva Slack. Il resoconto corretto è una consegna saltata che indica che Slack è disattivato.

### Crea un problema JIRA

`ticket.jira`

Crea o aggiorna il problema JIRA per il Riscontro.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Salta i Riscontri che hanno già un problema** | attivo | Lascia invariati i Riscontri che hanno già un problema JIRA. |
| **Aggiorna un problema esistente** | disattivo | Visibile quando l'opzione precedente è disattivata. Invia i Riscontri che hanno già un problema, in modo da aggiornare JIRA. |

Il riepilogo, la descrizione e la priorità provengono dalla configurazione JIRA del prodotto, non da questo nodo. Un ticket creato da una regola è quindi identico a uno creato tramite l'invio di tutti i problemi.

### Crea un ticket downstream

`ticket.downstream`

Crea o aggiorna un ticket tramite un [connettore downstream](/connectors/downstream/about/).

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Issue tracker** | `auto` | `auto` utilizza gli issue tracker assegnati all'Engagement o al Prodotto. `mapping` punta a una mappatura specifica. |
| **Mappatura issue tracker** | nessuno | Visibile per `mapping`. A quale mappatura inviare. |
| **Operazione** | `create` | `create` un ticket, oppure `update` quello esistente. Un `update` senza un ticket esistente lo crea. |
| **Salta i Riscontri che hanno già un ticket** | attivo | Lascia invariati i Riscontri che hanno già un ticket nella mappatura di destinazione. |

La regola sostituisce le impostazioni di invio automatico dell'assegnazione: i filtri per gravità e solo-attivi non vengono applicati una seconda volta qui. Un Riscontro il cui ticket esiste già viene saltato, indipendentemente da come quel ticket sia stato creato.

### Invia un messaggio Slack

`notify.slack`

Pubblica su un canale Slack tramite un connettore di messaggistica. La connessione contiene il token del bot; le impostazioni Slack a livello di istanza in **Impostazioni di sistema** non vengono utilizzate e non fungono da fallback.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Connessione** | nessuno | Un [connettore di messaggistica](/issue_tracking/pro_integration/messaging_connectors/) di questo tipo. Obbligatorio. |
| **Destinazione** | vuoto | Visibile una volta scelta una connessione. I campi dipendono dal vendor della connessione. |
| **Un messaggio per Riscontro** | disattivo | Se disattivata, invia un unico messaggio relativo al batch. |
| **Messaggio** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Renderizzato per ogni Riscontro. |
| **Riscontri elencati nel digest** | `10` | Visibile per i messaggi in batch. Quanti Riscontri elenca il messaggio prima di indicare quanti altri ce ne sono. |

### Invia un messaggio Microsoft Teams

`notify.msteams`

Pubblica una scheda tramite un connettore di messaggistica. La connessione contiene l'URL del flusso di lavoro Power Automate; il webhook Teams a livello di istanza in **Impostazioni di sistema** non viene utilizzato e non funge da fallback.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Connessione** | nessuno | Un [connettore di messaggistica](/issue_tracking/pro_integration/messaging_connectors/) di questo tipo. Obbligatorio. |
| **Destinazione** | vuoto | Visibile una volta scelta una connessione. I campi dipendono dal vendor della connessione. |
| **Un messaggio per Riscontro** | disattivo | Se disattivata, invia un'unica scheda relativa al batch. |
| **Messaggio** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Renderizzato per ogni Riscontro. |
| **Riscontri elencati nel digest** | `10` | Visibile per i messaggi in batch. |

### Invia un'email

`notify.email`

Invia un'email a un elenco fisso di indirizzi tramite un connettore di messaggistica. I destinatari corrispondono alla destinazione della connessione.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Connessione** | nessuno | Un [connettore di messaggistica](/issue_tracking/pro_integration/messaging_connectors/) di questo tipo. Obbligatorio. |
| **Destinazione** | vuoto | Visibile una volta scelta una connessione. I campi dipendono dal vendor della connessione. |

| **Oggetto** | `[DefectDojo] {{ctx.count}} finding(s) from rule {{ctx.rule_name}}` | Renderizzato una volta per messaggio. |
| **Corpo** | un corpo HTML contenente `{{ctx.findings_html}}` | HTML. `{{ctx.findings_html}}` visualizza l'elenco dei Riscontri. |
| **Un messaggio per Riscontro** | disattivo | Se disattivata, invia un'unica email relativa al batch. |
| **Riscontri elencati nel corpo** | `25` | Quanti Riscontri elenca `{{ctx.findings_html}}` prima di indicare quanti altri ce ne sono. |

### Chiama un webhook

`notify.webhook`

Invia una richiesta POST JSON a un endpoint webhook.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Endpoint webhook** | nessuno | Un [webhook di notifica](/automation/api/notification_webhooks/) configurato. La sua intestazione personalizzata viene inviata con la richiesta. |
| **URL** | vuoto | Visibile quando non è selezionato alcun endpoint. Dove inviare la richiesta POST. |
| | | È obbligatorio uno dei due precedenti. |
| **Segreto di firma** | vuoto | Firma il corpo come `X-DefectDojo-Signature: sha256=HMAC`. |
| **Un messaggio per Riscontro** | disattivo | Se disattivata, pubblica l'intero batch in un'unica richiesta. |

Due cose da sapere. Un segreto di firma digitato qui viene memorizzato con la regola, quindi per qualsiasi dato sensibile è preferibile utilizzare un endpoint configurato con la propria intestazione. Inoltre, un webhook chiamato da una regola non modifica mai lo stato di salute di quell'endpoint, quindi una regola non può disabilitare i webhook di notifica fallendo.

Gli URL in testo libero vengono convalidati al salvataggio. Vedere [Configurazione](../configuration/#outbound-destination-validation) per sapere cosa viene rifiutato e come consentire indirizzi privati.

### Genera un avviso in-app

`notify.alert`

Crea un avviso in-app relativo al batch.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Titolo** | `Rules Engine 2.0: {{ctx.rule_name}}` | Renderizzato una volta per l'intero batch. |
| **Descrizione** | `{{ctx.count}} finding(s) matched the rule {{ctx.rule_name}}.` | Renderizzato una volta per l'intero batch. |
| **Destinatari** | vuoto | Nomi utente separati da virgola. Se vuoto, avvisa gli amministratori. |

I destinatari mantengono comunque il controllo su questo tramite la propria impostazione di notifica **Corrispondenza Rules Engine**, quindi un avviso non può aggirare le preferenze di notifica di un utente.

### Genera un report

`report.generate`

Genera un report da un modello, limitato ai Riscontri che hanno raggiunto questo nodo, e può annunciare il link di download.

| Impostazione | Predefinito | Note |
|---------|---------|-------|
| **Modello di report** | nessuno | Da quale modello generare. Obbligatorio. |
| **Formato** | `pdf` | `pdf` o `html`. |
| **Riscontri inclusi** | `batch_findings` | `batch_findings` limita il report ai Riscontri che hanno raggiunto questo nodo. `template_default` consente al modello di usare i propri filtri. |
| **Annuncia tramite** | nessuno | Un [connettore di messaggistica](/issue_tracking/pro_integration/messaging_connectors/) su cui pubblicare il link di download una volta generato il report. Lasciare vuoto per non annunciare. |
| **Annuncia a** | vuoto | Visibile una volta scelta una connessione. Dove invia quella connessione: un ID canale Slack, indirizzi email, e così via. |
| **Annuncio** | `Report ready: {{ctx.report_url}}` | Visibile quando si annuncia. `{{ctx.report_url}}` è il link di download. |

`batch_findings` è ciò che una regola può fare e un report pianificato no: creare un report esattamente sui Riscontri appena corrisposti.

L'annuncio viene registrato come una consegna a sé stante, separata dalla generazione del report, in modo da poter vedere il report riuscire e l'annuncio fallire in modo indipendente.
