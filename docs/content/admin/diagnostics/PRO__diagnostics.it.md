---
title: Diagnostica
description: 'Consulta il registro trasversale ai sottosistemi dei tentativi di integrazione:
  cosa viene registrato, come filtrarlo, come vengono escluse le credenziali e chi
  può vedere i dettagli tecnici'
weight: 1
audience: pro
---

Diagnostica è un registro unico di ogni tentativo che DefectDojo effettua per comunicare con qualcosa al di fuori di sé stesso — e dei tentativi che altri sistemi effettuano per comunicare con esso. Quando un ticket non è mai comparso, una scansione non è mai stata importata o un utente non è riuscito ad accedere, questa è la pagina che indica cosa è successo, quando, con quale configurazione e chi lo ha provocato.

Diagnostica è una funzionalità di **DefectDojo Pro**. La trovi in **Connect > Diagnostics**.

![Il registro di Diagnostica, vista Errors](images/diagnostics_errors.png)

## Cosa viene registrato

Viene scritta una riga per ogni tentativo, da ogni sottosistema che comunica con l'esterno di DefectDojo:

| Origine | Cosa genera le righe |
| --- | --- |
| **Connector** | Esecuzioni di discovery e sincronizzazione dei connector in ingresso |
| **Integratore downstream** | Invii verso Jira, GitHub, GitLab, ServiceNow e gli altri connector downstream |
| **Jira** | L'integrazione Jira legacy: invii, commenti e anteprime |
| **SSO (OIDC/OAuth2)** | Tentativi di accesso tramite un provider OAuth |
| **SAML** | Asserzioni SAML, compresi gli errori di firma e di attributo |
| **LDAP** | Bind e ricerche LDAP |
| **Import / Reimport** | Caricamenti di scansioni, tramite UI, API o pianificazione |
| **Motore delle regole** | Valutazioni delle regole e le azioni che tentano di eseguire |
| **Pianificazione** | Esecuzioni pianificate, comprese quelle mai avviate |
| **Sensei** | Scansioni dei repository ed esecuzioni di fix |
| **Notifica** | Invio di notifiche in uscita |
| **Sistema** | Attività a livello di istanza che non appartiene a nessun prodotto |

Le righe vengono scritte *insieme* al sottosistema, mai al suo posto. Ogni adapter è collegato al record di origine ed è deliberatamente fail-safe: se la scrittura di una riga diagnostica genera un errore, l'errore viene ignorato e l'operazione originale prosegue. Diagnostica non può quindi mai essere la causa del fallimento di un invio, di un'importazione o di un accesso.

Poiché le righe sono associate al record che le ha generate, salvare di nuovo un record di origine aggiorna la riga diagnostica esistente invece di aggiungerne una duplicata. Un tentativo corrisponde a una riga per tutta la sua durata, da `Queued` a `Running` fino al suo esito.

### Campi di una riga

| Campo | Significato |
| --- | --- |
| **When** | Quando la riga è stata registrata; **Started**, **Finished** e **Duration** descrivono il tentativo stesso |
| **Source** | Il sottosistema, dalla tabella sopra |
| **Provider** | Lo strumento o il provider specifico all'interno di quell'origine (`jira`, `github`, `okta`, il nome di uno scanner) |
| **Operation** | Cosa è stato tentato (`push`, `sync`, `login`, `reimport`, `rule_run`) |
| **Status** | `Queued`, `Running`, `Success`, `Failed`, `Timed out`, `Skipped` o `Dry run` |
| **Severity** | `Info`, `Warning`, `Error` o `Critical` |
| **Summary** | Un esito in una riga, leggibile a colpo d'occhio |
| **Trigger** | Cosa ha fatto scattare il tentativo: `UI`, `API`, `Scheduled`, `Webhook`, `Automatic`, `Command line` o `System` |
| **Triggered by** | L'utente responsabile, oppure `System` per le operazioni non presidiate |
| **Asset** | Il prodotto a cui appartiene il tentativo; vuoto significa a livello di istanza |
| **Related object** | Il riscontro, l'engagement o l'altro record a cui si riferiva il tentativo |
| **Configuration** | Quale configurazione è stata usata, in base alla sua etichetta |
| **External reference** | L'identificativo restituito dall'altro sistema, ad esempio la chiave di un issue creato |
| **Correlation ID** | Collega tra loro le righe di una stessa operazione logica |
| **Reported detail** e **Context** | Il dettaglio tecnico completo (con restrizioni, vedi [Chi vede cosa](#who-sees-what)) |

## Le quattro viste

Le schede sopra la tabella sono punti di partenza salvati, non filtri da ricostruire ogni volta:

* **Errors** — errori e timeout. La prima da aprire.
* **Successes** — la prova che un'integrazione funzionante sta funzionando, utile quando qualcuno segnala che "non si sta sincronizzando nulla".
* **Never completed** — tentativi ancora `Queued` o `Running` ben oltre il momento in cui avrebbero dovuto concludersi. Sono i casi silenziosi: nulla è fallito, quindi nulla è stato segnalato, ma nulla è nemmeno arrivato.
* **All events** — tutto, senza filtri.

![Tutti gli eventi, con ogni origine mostrata](images/diagnostics_all_events.png)

La vista attiva fa parte dell'URL della pagina, quindi una vista è collegabile tramite link e sopravvive a un aggiornamento.

## Restringere l'elenco

* **Time range** — 24 ore, 7 giorni, 30 giorni o 90 giorni, dai pulsanti nell'intestazione.
* **Conteggi per origine** — i conteggi colorati sotto le schede di riepilogo sono anche filtri rapidi. Fai clic su uno per mostrare solo quell'origine; fai clic di nuovo (oppure su **Clear source filter**) per tornare indietro. Ne è attivo uno o nessuno alla volta.
* **Filtri e ordinamento per colonna** — ogni colonna filtra e ordina, incluse Severity e Source. Severity ordina in base alla gravità (`Critical` → `Info`) anziché alfabeticamente, e Source ordina in base all'etichetta visualizzata anziché al valore memorizzato sottostante.
* **Keyword Search** — cerca contemporaneamente in tutti i campi di testo.
* **Preferenze di colonna** — il selettore di colonne e i suoi layout salvati si comportano come in ogni altro elenco di Pro.

![Un conteggio per origine usato come filtro rapido](images/diagnostics_chip_filter.png)

Fai clic sulla lente d'ingrandimento all'inizio di una riga per aprire l'intero tentativo:

![Un singolo evento, con l'avviso di redazione](images/diagnostics_detail.png)

## Le credenziali vengono rimosse prima che la riga venga scritta

Gli errori di integrazione citano la richiesta che è fallita, e queste citazioni contengono segreti: un header `Authorization`, un token in una query string, una password all'interno di un URL di connessione. Diagnostica li elimina **in ingresso**, così il valore originale non raggiunge mai il database e nessun ripensamento successivo può esporlo.

Vengono ripulite due cose:

* **I valori sotto chiavi dalla forma di credenziale** — qualsiasi cosa la cui chiave assomigli a un segreto (`password`, `token`, `secret`, `api_key`, `authorization`, `private_key` e simili, in qualsiasi combinazione di maiuscole/minuscole o con trattini o spazi). Un piccolo insieme di chiavi è esente perché conta solo la loro *presenza*, mai il loro contenuto.
* **I valori che sembrano credenziali ovunque compaiano** — header di autorizzazione bearer e basic, JWT, credenziali incorporate negli URL (`https://user:pass@host`), prefissi di token dei vendor riconoscibili e blocchi PEM.

Ognuno viene sostituito con `[redacted]`. Il messaggio circostante viene mantenuto, così l'errore resta leggibile:

```text
401 Unauthorized: Authorization: [redacted]
upload rejected: https://svc:[redacted]@sftp.example/out/…
```

I valori lunghi vengono troncati e il contesto profondamente annidato viene appiattito, così un payload enorme non può gonfiare la tabella.

Quando qualcosa è stato rimosso da una riga, la riga lo segnala, invece di lasciarti chiedere se il campo fosse vuoto o svuotato.

> **La redazione è best-effort per design.** Il meccanismo di pulizia riconosce le *forme* delle credenziali. Un segreto che assomiglia a prosa comune, sotto una chiave che non sembra sensibile, può comunque essere registrato. Considera Diagnostica come un log operativo, non come un luogo in cui i segreti sono garantiti assenti — e mantieni il dettaglio tecnico riservato a chi ne ha bisogno.

## Chi vede cosa

Diagnostica è organizzata su livelli, perché il riepilogo di un errore è utile per il proprietario di un prodotto, mentre la richiesta grezza che ne sta dietro no.

| | Superuser | Tutti gli altri |
| --- | --- | --- |
| Righe per i prodotti su cui sono autorizzati | Sì | Sì |
| Righe a livello di istanza (nessun prodotto) | Sì | No |
| Summary, source, status, severity, timing, configuration | Sì | Sì |
| **Reported detail**, **Context**, **Remote IP** | Sì | Nascosti, ed etichettati come tali |

Un utente non superuser vede che un dettaglio esiste e viene nascosto, invece di un campo vuoto che sembra un dato mancante. Le righe a livello di istanza — SSO, SAML, LDAP e altre attività che non appartengono a nessun prodotto — sono riservate ai superuser, poiché non esiste alcuna appartenenza a un prodotto che potrebbe concedere l'accesso a esse.

## Per quanto tempo vengono conservati i record

Un'attività pianificata riduce il registro affinché non possa crescere senza limiti:

| Severity | Conservato per |
| --- | --- |
| `Info` | 30 giorni |
| `Warning`, `Error`, `Critical` | 180 giorni |

Entrambe le finestre sono configurabili con le impostazioni `DIAGNOSTIC_EVENT_INFO_RETENTION_DAYS` e `DIAGNOSTIC_EVENT_RETENTION_DAYS`. L'eliminazione viene eseguita a lotti, così una grande cancellazione non mantiene aperta una transazione lunga.

## API

Il registro è di sola lettura tramite API, all'indirizzo `/api/v2/diagnostic_events/`:

| Endpoint | Restituisce |
| --- | --- |
| `GET /api/v2/diagnostic_events/` | L'elenco, con i filtri sottostanti |
| `GET /api/v2/diagnostic_events/{id}/` | Un evento |
| `GET /api/v2/diagnostic_events/summary/` | I conteggi dietro le schede di intestazione, compresi i totali per origine |
| `GET /api/v2/diagnostic_events/choices/` | I valori validi per `source`, `status`, `severity` e `trigger` |

Parametri utili:

| Parametro | Effetto |
| --- | --- |
| `source`, `status`, `severity`, `trigger` | Accettano più valori separati da virgola contemporaneamente |
| `failures_only=true` | Errori e timeout |
| `unresolved_only=true` | Tentativi ancora in coda o in esecuzione |
| `product_name` | Filtra per nome del prodotto |
| `object_model` | Filtra per il tipo di record a cui si riferiva il tentativo |
| `o=` | Ordinamento, con prefisso `-` per invertire (`o=-created_at`) |

Si applicano le stesse regole di accesso: un utente non superuser ottiene righe limitate ai propri prodotti, con i campi riservati nascosti.

## Capire cosa è andato storto

* **Un ticket non è mai comparso.** Filtra Source sull'integratore (o su Jira), quindi leggi Status. `Failed` fornisce il motivo in Summary; `Queued` molto tempo dopo il fatto significa che il job non è mai stato eseguito, il che è un problema di worker o di pianificazione più che di credenziali.
* **Un utente non riesce ad accedere.** Filtra Source su SSO, SAML o LDAP e leggi l'errore per il suo tentativo — una firma di asserzione errata, un bind rifiutato, un attributo non corrispondente. Queste righe sono a livello di istanza, quindi sono riservate ai superuser.
* **Una scansione non è comparsa.** Filtra Source su Import / Reimport. Guarda Trigger per distinguere un caricamento pianificato non presidiato da uno manuale di qualcuno, e Triggered by per sapere a chi chiedere.
* **Qualcosa continua a riprovare all'infinito.** Ordina per Correlation ID, o filtra su uno specifico, per vedere insieme ogni tentativo della stessa operazione logica.
* **"Non funziona niente."** Apri prima Successes per la stessa finestra temporale. Un elenco sano lì trasforma un'interruzione vaga in una specifica.

## Correlati

* [Feature Flags](/admin/feature_flags/pro__feature_flags/) — attivare e disattivare le funzionalità Pro opzionali
* [Connectors](/connectors/upstream/about/) — importare i riscontri
* [Pro Integrations](/connectors/downstream/about/) — esportare i riscontri
* [Single Sign-On](/admin/sso/) — i provider di identità i cui tentativi di accesso compaiono qui
