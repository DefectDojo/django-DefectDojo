---
title: Informazioni su Rules Engine 2.0
description: Cos'è Rules Engine 2.0, come attivarlo e i concetti su cui si basa
weight: 1
audience: pro
aliases:
- /it/automation/rules_engine_v2/about/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 è una funzionalità disponibile solo in DefectDojo Pro.</span>

Rules Engine 2.0 è un builder di automazione visuale. Invece di un filtro più un elenco piatto di azioni, una regola è un **grafo**: un nodo trigger che decide quando la regola si attiva, e un numero qualsiasi di nodi logici, Riscontro ed egress collegati tra loro per stabilire cosa succede dopo.

Rules Engine 2.0 è accessibile solo tramite la [UI Pro](/get_started/about/ui_pro_vs_os/).

## Cosa aggiunge rispetto a Rules Engine

Il [Rules Engine](/automation/rules_engine/about/) originale applica un elenco ordinato di azioni a ogni Riscontro che corrisponde a un filtro. Rules Engine 2.0 mantiene questa capacità e aggiunge quattro cose:

* **Ramificazione.** Un nodo **If / Filter** instrada gli elementi lungo un ramo vero e uno falso, così una regola può trattare i Riscontri Critica in modo diverso dal resto senza doverla dividere in due regole.
* **Egress.** Una regola può uscire da DefectDojo: aprire un ticket JIRA o un ticket a valle, pubblicare su Slack o Microsoft Teams, inviare un'email, chiamare un webhook, generare un avviso in-app o produrre un report.
* **Tracciabilità.** Ogni esecuzione viene registrata nodo per nodo come [Run](../runs/), e ogni invio in uscita viene registrato come [Delivery](../deliveries/) che indica esattamente cosa è stato inviato, dove è andato e come è terminato.
* **Una modalità di simulazione.** Una regola può registrare esattamente cosa avrebbe inviato senza inviare nulla, ed è così che la si testa in sicurezza prima che tocchi il mondo esterno.

I due motori funzionano fianco a fianco. Attivare Rules Engine 2.0 non disabilita né converte le regole esistenti, ed esiste un [convertitore](../converting_from_rules_engine/) per quando si vuole spostarle.

## Abilitare Rules Engine 2.0

Rules Engine 2.0 è in Beta ed è disattivato per impostazione predefinita. Un superuser lo attiva da **Settings > Feature Flags**, sia sulle istanze Cloud che On-Premise. Vedere [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Una volta attivato il flag, nella barra laterale compare una sezione **Rules Engine 2.0** con tre pagine:

| Pagina | A cosa serve |
|------|----------------|
| **All Rules** | L'elenco delle regole. Da qui si creano, modificano, abilitano, eseguono ed eliminano le regole. |
| **Runs** | Ogni esecuzione, con la sua traccia per nodo. |
| **Deliveries** | Il registro di tutto ciò che le regole hanno inviato verso l'esterno. |

### Permessi

L'accesso è governato da due permessi di ruolo globali, condivisi con il Rules Engine originale:

* **Rule View** è necessario per vedere la sezione nella barra laterale e tutto ciò che contiene.
* **Rule Edit** è necessario per creare, modificare, eseguire, eliminare, convertire, assumere la proprietà e rieseguire.

Rule Edit è vicino a un permesso amministrativo. Un autore di regole può raggiungere qualsiasi Riscontro che il proprietario della sua regola può vedere, e può indirizzare l'output verso sistemi esterni, quindi va concesso con attenzione.

## I concetti

### Regole e grafi

Una regola è un nome, una descrizione, un proprietario, una modalità, un interruttore di abilitazione e un grafo. Il grafo è un insieme di **nodi** e degli **archi** tra di essi. Deve contenere esattamente un nodo trigger e non deve contenere cicli. Tutto il resto è a discrezione dell'autore, incluso lasciare un nodo non collegato, il che significa semplicemente che viene eseguito senza nulla su cui lavorare.

Le nuove regole vengono sempre create **disabilitate**, quindi abilitarne una è un atto deliberato.

### Elementi

Ciò che viaggia lungo gli archi di un grafo è un **elemento**: uno snapshot JSON di un Riscontro più il contesto circostante.

```json
{
  "finding":      { "id": 1234, "title": "...", "severity": "High", "...": "..." },
  "test":         { "id": 12, "title": "...", "scan_type": "..." },
  "engagement":   { "id": 5,  "name": "..." },
  "product":      { "id": 3,  "name": "..." },
  "product_type": { "id": 1,  "name": "..." },
  "ctx":          { "trigger": "finding.created", "depth": 0, "source": "app" }
}
```

Le condizioni e i template dei messaggi vengono scritti sui percorsi presenti in questa struttura, ad esempio `finding.severity` o `product.name`. L'elenco completo dei campi si trova in [Building Rules](../building_rules/).

### Proprietario

Ogni regola viene eseguita **come il suo proprietario**. Vede esattamente i Riscontri che quell'utente può vedere, attraverso la stessa autorizzazione usata ovunque altrove nel prodotto. Due conseguenze vale la pena conoscere:

* Restringere l'accesso del proprietario di una regola restringe la regola.
* Una regola il cui account proprietario è stato eliminato non ha proprietario, quindi non corrisponde a nulla e non fa nulla. Assegnare un nuovo proprietario, oppure usare **Take Ownership** dall'elenco delle regole, per ripristinarla.

### Modalità: Simulate o Live

La modalità è impostata per regola, non per nodo.

* **Simulate** (predefinita) esegue l'intero grafo realmente, incluse tutte le modifiche ai Riscontri, ma i nodi egress registrano cosa *avrebbero* inviato e si fermano lì. Nulla lascia DefectDojo.
* **Live** esegue effettivamente gli invii.

Gli invii simulati compaiono comunque nel registro Deliveries, contrassegnati come `simulated`, con il loro payload completo. Questo è il modo previsto per rivedere una regola prima di renderla operativa.

La modalità si applica deliberatamente all'intera regola. Un grafo in cui alcuni invii sono reali e altri no è più difficile da comprendere rispetto a due regole separate.

### Run

Una singola esecuzione di una regola è un [Run](../runs/). Un run registra l'evento che lo ha attivato, il suo stato, la traccia per nodo e qualsiasi errore. Una regola può avere un solo run in corso alla volta, quindi una regola occupata si accoda invece di correre contro sé stessa.

### Deliveries

Ogni effetto collaterale in uscita è una riga nel registro [Deliveries](../deliveries/), scritta **prima** che avvenga qualsiasi chiamata di rete. La riga contiene il payload, la destinazione risolta, lo stato, il conteggio dei tentativi e qualsiasi risposta della destinazione. Anche le omissioni vengono registrate, così "la regola non ha fatto nulla" e "la regola non ha fatto nulla perché il Riscontro aveva già un ticket" sono distinguibili.

### Provenienza

Ogni modifica che una regola apporta a un Riscontro viene attribuita alla regola, al run e al nodo che l'ha effettuata. Questa cronologia è visibile sul Riscontro stesso, così si può rispondere a "perché questo Riscontro è cambiato?" senza dover leggere le definizioni delle regole.

### Scala

Una regola elabora tutto ciò che il suo scope include. Non c'è un limite al numero di Riscontri che un run può gestire: li elabora a blocchi in modo che sia la memoria a rimanere limitata, non la copertura. Solo Preview impone un limite, e lo segnala quando lo fa.

### Conservazione

Run e delivery vengono entrambi mantenuti per 180 giorni per impostazione predefinita, poi eliminati. Il prodotto mostra la finestra e la data in cui un dato record verrà eliminato invece di lasciarla implicita, ed entrambe le finestre sono configurabili. Vedere [Configuration](../configuration/#retention).

## Dove andare dopo

* [Building Rules](../building_rules/) tratta l'editor, i trigger, lo scope, le condizioni e i template.
* [Node Reference](../node_reference/) documenta tutti i 25 nodi.
* [Runs](../runs/) tratta l'esecuzione, le tracce, la propagazione a cascata e i limiti.
* [Deliveries](../deliveries/) tratta i canali, gli stati, i tentativi e la riesecuzione.
* [Converting from Rules Engine](../converting_from_rules_engine/) tratta lo spostamento delle regole esistenti.
* [Configuration](../configuration/) tratta le impostazioni a livello di deployment.
