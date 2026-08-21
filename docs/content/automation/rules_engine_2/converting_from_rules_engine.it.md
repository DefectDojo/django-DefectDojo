---
title: Conversione da Rules Engine
description: Spostare le regole esistenti di Rules Engine nei grafi di Rules Engine
  2.0
weight: 6
audience: pro
aliases:
- /it/automation/rules_engine_v2/converting_from_rules_engine/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 è una funzionalità disponibile solo in DefectDojo Pro.</span>

I due motori funzionano fianco a fianco. Attivare Rules Engine 2.0 non cambia nulla delle regole [Rules Engine](/automation/rules_engine/about/) esistenti, e non c'è una scadenza entro cui spostarle.

Quando si vuole spostarle, esiste un convertitore. Traduce una regola di Rules Engine (un filtro più un elenco ordinato di azioni) in un grafo Rules Engine 2.0 equivalente.

## Cosa garantisce il convertitore

**Una regola o si converte in modo pulito, o non si converte affatto.** Ogni conversione riporta due tipi di esito:

* I **Problemi** significano che la regola non è stata scritta. Non viene salvato nulla di parziale.
* Gli **Avvisi** significano che la regola si è convertita, ma qualcosa in essa è cambiato e va controllato.

Nulla viene approssimato silenziosamente. Tutto il valore del convertitore sta nel poter fidarsi di una regola convertita senza segnalazioni, e nel controllare a mano una che non lo è stata.

**Le regole convertite vengono sempre create disabilitate.** Entrambi i motori sono in esecuzione, e avere due regole che fanno la stessa cosa sugli stessi Riscontri è l'unico esito che un convertitore non deve mai produrre da solo. Rivedere ogni regola convertita e abilitarla deliberatamente.

**Una regola si converte una sola volta.** Ogni regola convertita ricorda da quale regola proviene, quindi eseguire il convertitore due volte salta ciò che ha già fatto invece di creare duplicati. Usare l'opzione di sovrascrittura per sostituire deliberatamente un grafo convertito in precedenza.

## Eseguire il convertitore

### Dalla UI

L'elenco delle regole offre un'azione di conversione, che riporta per ogni regola cosa si è convertito, cosa è stato saltato e cosa è fallito.

### Dalla riga di comando

```bash
python manage.py convert_rules_to_v2
```

| Opzione | Effetto |
|--------|--------|
| `--dry-run` | Stampa il grafo che ogni regola produrrebbe e non scrive nulla. |
| `--rule-ids 1,2,3` | Converte solo queste regole. Le converte tutte se omesso. |
| `--overwrite` | Sostituisce il grafo di una regola già convertita e ne incrementa la versione, invece di saltarla. |
| `--activate-schedules` | Copia anche ogni pianificazione sulla regola convertita corrispondente. Disattivato per impostazione predefinita. |
| `--drop-invalid-filters` | Elimina i filtri di scope che il set di filtri non riconosce più e avvisa, invece di far fallire la regola. |
| `--json` | Stampa il report come JSON invece che come testo. |

Il comando termina con un codice diverso da zero solo quando una regola non riesce a convertirsi. Le omissioni vengono riportate ma non sono fallimenti.

Iniziare con `--dry-run` sull'intero set per vedere a cosa si va incontro, poi convertire per davvero.

## Cosa produce la conversione

| Concetto di Rules Engine | Diventa |
|----------------------|---------|
| Il filtro della regola | Lo **Scope** sul nodo trigger. |
| Una regola con una pianificazione | Un trigger **On a Schedule**. |
| Una regola senza pianificazione | Un trigger **Manual Run**. |
| Ogni azione, in ordine | Un nodo, concatenato nello stesso ordine. |
| Un'azione condizionata da una condizione | Un nodo **If / Filter** davanti a quel nodo. |

Il vocabolario dei filtri è condiviso tra i due motori, quindi uno scope si converte senza traduzione. Questo è deliberato: è lo stesso set di filtri, con un'unica implementazione.

I grafi convertiti vengono validati allo stesso modo di un grafo costruito a mano, inclusa la configurazione per nodo e i valori consentiti di ogni menu a tendina. Una regola che contiene un valore di gravità o di rischio da cui il prodotto è nel frattempo passato oltre viene intercettata alla conversione invece che in fase di esecuzione.

## Cosa non viene trasferito

Quattro cose da tenere presenti. Il convertitore le riporta come note a ogni esecuzione.

* **La cronologia dei run resta dov'è.** La cronologia di esecuzione esistente, e i relativi record interessati e saltati, rimangono nella UI di Rules Engine. Non vengono copiati.
* **Le pianificazioni non vengono attivate per impostazione predefinita.** Una regola attivata da pianificazione si converte, ma la sua pianificazione non viene copiata a meno di passare `--activate-schedules`. Questo mantiene la proprietà esclusiva delle pianificazioni attive nel motore originale finché entrambi sono in esecuzione, così una regola convertita non può iniziare a scattare di nascosto. Quando si copia effettivamente una pianificazione, alla copia viene dato un nome distinto in modo che non collida con l'originale.
* **Il modello di concorrenza è diverso.** Rules Engine ha un unico lock di esecuzione a livello di istanza. Rules Engine 2.0 serializza per regola, quindi regole distinte vengono eseguite in concorrenza. Un insieme di regole che prima si alternava ora si sovrapporrà.
* **Un'azione non ha equivalente.** Un'azione "imposta falso positivo a falso" non può essere espressa come nodo di Rules Engine 2.0 e deve essere convertita a mano.

Una regola il cui proprietario non è impostato si converte, con un avviso. Ricordare che una regola senza proprietario non vede alcun Riscontro, quindi assegnarne uno prima di abilitarla.

## Un ordine suggerito

1. Attivare Rules Engine 2.0 e lasciare in esecuzione le regole esistenti.
2. Eseguire il convertitore con `--dry-run` e leggere il report.
3. Convertire. Tutto viene creato disabilitato.
4. Aprire ogni regola convertita, controllare il grafo, e lasciare la modalità su **Simulate**.
5. Abilitare la regola convertita, e lasciarla in esecuzione insieme all'originale per un po'. Simulate significa che modifica i Riscontri ma non invia nulla, quindi confrontare le sue esecuzioni con quanto faceva l'originale.
6. Quando si è soddisfatti, disabilitare la regola originale e passare quella convertita a **Live**.
7. Copiare la pianificazione per ultima, una volta che nulla sta più eseguendo la vecchia regola.

Il passaggio 5 è quello che vale la pena non saltare. Vedere i due motori modificare gli stessi Riscontri va bene, ma si vuole essere chi decide quando iniziano gli invii.
