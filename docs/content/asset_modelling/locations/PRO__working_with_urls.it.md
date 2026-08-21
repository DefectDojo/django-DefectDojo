---
title: Utilizzo degli URL
description: Utilizzo quotidiano delle URL Location come sostituto degli Endpoint
audience: pro
weight: 4
---

Le URL Location sono il sostituto funzionale del vecchio modello Endpoint. Memorizzano gli stessi campi in forma di URL a cui si è abituati — `protocol`, `host`, `port`, `path`, `query`, `fragment` — e svolgono lo stesso ruolo: identificare *dove* risiede un Finding di un'applicazione web.

Questa pagina illustra cosa cambia quando si inizia a usare le URL Location quotidianamente, le nuove superfici dell'interfaccia e gli endpoint API da usare al posto della vecchia API Endpoint.

## Il sottotipo URL

Ogni URL è una Location. Ciò significa che un URL possiede sia:

- I campi strutturati dell'URL (`protocol`, `user_info`, `host`, `port`, `path`, `query`, `fragment`, oltre a un `hash` usato per la deduplicazione).
- I campi condivisi della Location (`location_type="url"`, una stringa canonica `location_value` per la visualizzazione e la ricerca, tag, tag ereditati, metadati e collegamenti Reference ad Asset e Finding).

Quando si crea o si carica un URL, DefectDojo lo analizza nei campi strutturati e scrive sia la riga URL sia la riga Location padre in un'unica transazione. La deduplicazione degli URL avviene per corrispondenza esatta tra i campi strutturati — due URL sono considerati uguali se ogni componente corrisponde, con il consueto collasso della porta predefinita (`http://example.com:80/` e `http://example.com/` risolvono nello stesso URL).

## Nell'interfaccia Pro

Quando la funzionalità Location è abilitata, la navigazione espone:

- **Locations / All** — Un elenco di tutte le Location, sia nel sottotipo URL sia in quello Dependency. Filtrabile per tipo, stato, Asset, Finding o tag.
- **Locations / URLs** — Un elenco limitato alle sole URL Location. È l'equivalente più vicino alla vecchia pagina Endpoint.
- **New URL** — Un modulo per creare un singolo URL con campi strutturati, tag e associazioni opzionali ad Asset/Finding.
- **Locations su un Asset** — Da qualsiasi Asset, la scheda **Locations** mostra gli URL e le Dependency collegati a quell'Asset, con conteggi di stato e azioni rapide.

I flussi di lavoro comuni dell'interfaccia Endpoint sono stati preservati:

- **Aggiornamenti di stato in blocco.** Selezionare più URL Location e applicare uno stato (Attivo, Mitigato, Falso positivo, Rischio accettato, Fuori ambito) ai relativi riferimenti Finding in un'unica azione.
- **Aggiunta di URL esistenti a un Asset.** Usare **Add Existing** nella scheda Locations di un Asset per collegare URL già presenti nel sistema invece di crearne di duplicati.
- **Tag.** I tag applicati a una URL Location si propagano come tag ereditati sui Finding che la referenziano, allo stesso modo in cui facevano prima i tag degli Endpoint.

## Modello di stato

Le URL Location usano le stesse etichette a stato singolo di tutte le altre Location:

| Stato | Significato |
| --- | --- |
| **Attivo** | Il Finding su questo URL è aperto. |
| **Mitigato** | Il Finding è stato risolto per questo URL. |
| **Falso positivo** | Il Finding non è una vulnerabilità reale per questo URL. |
| **Rischio accettato** | Il Finding è riconosciuto ma accettato su questo URL. |
| **Fuori ambito** | Questo URL è escluso dall'engagement. |

Nota che il vecchio modello Endpoint Status consentiva più flag contemporaneamente (ad es. `mitigated=True` e `false_positive=True`). Le Location impongono un solo stato alla volta. Se si è migrato dagli Endpoint, è stato preservato il flag più specifico (vedi la tabella di mappatura in [Migrazione dagli Endpoint](../pro__migrating_from_endpoints)).

Gli Asset Reference usano uno stato più semplice: solo **Attivo** o **Mitigato**, poiché lo stato a livello di Asset non richiede il dettaglio di audit.

## API REST

Usare questi endpoint al posto della vecchia API Endpoint:

| Attività | Endpoint |
| --- | --- |
| Elencare gli URL | `GET /api/v2/urls/` |
| Creare un URL | `POST /api/v2/urls/` |
| Aggiornare i tag o i metadati di un URL | `PATCH /api/v2/urls/{id}/` |
| Elencare tutte le Location (URL + Dependency) | `GET /api/v2/location/?location_type=url` |
| Collegare un URL a un Finding | `POST /api/v2/location_findings/` |
| Collegare un URL a un Asset | `POST /api/v2/location_Assets/` |
| Aggiornare lo stato di un collegamento Finding | `PATCH /api/v2/location_findings/{id}/` |
| Rimuovere un collegamento Finding | `DELETE /api/v2/location_findings/{id}/` |

I filtri su `/api/v2/urls/` includono i campi strutturati dell'URL più `tag(s)`, `has_tags`, `Asset`, e l'ordinamento per `host`, `Asset` o conteggio dei Finding attivi.

Il vecchio endpoint `/api/v2/endpoints/` continua a servire il traffico in **lettura** tramite uno shim di compatibilità — vedi [Migrazione dagli Endpoint](../pro__migrating_from_endpoints) per ciò che viene preservato e dove lo shim si discosta dal comportamento originale. Le **scritture** verso gli endpoint legacy restituiscono `403` e devono essere spostate verso gli endpoint sopra indicati.

## Importazione di URL dalle scansioni

Gli import dello scanner creano automaticamente le URL Location. Quando un parser genera un URL per un Finding (nello stesso modo in cui prima generava un Endpoint), l'importatore:

1. Cerca un URL esistente con campi strutturati corrispondenti, oppure ne crea uno.
2. Crea un Finding Reference che collega il Finding all'URL con stato **Attivo**.
3. Crea (o riutilizza) un Asset Reference in modo che l'URL compaia anche sull'Asset padre.

I parser DefectDojo che in precedenza creavano Endpoint sono stati aggiornati per creare automaticamente Location in Pro.

## Cose che si comportano diversamente

Vale la pena notare alcuni piccoli cambiamenti di comportamento:

- **Un solo stato per coppia URL/Finding.** Come descritto sopra, il modello Endpoint_Status multi-flag viene compresso in un unico stato. I flussi di lavoro che attivavano i flag in modo indipendente devono scegliere una singola transizione.
- **I tag risiedono sulla Location, non sull'URL.** Il sottotipo URL non ha un proprio insieme di tag; i tag appartengono alla Location padre. Se si legge un URL tramite l'API, il campo `tags` proviene da `location.tags`.
- **La deduplicazione è per URL canonico, non per Asset.** Due Asset che hanno lo stesso URL condividono un'unica URL Location sottostante e la referenziano due volte (un Asset Reference ciascuno). Questo è intenzionale ed è ciò che consente il reporting cross-Asset.
- **Il campo `endpoints` sui Finding.** Quando il flag è attivo, questo campo nell'API Finding continua a restituire righe, ma sono proiettate dalle URL Location anziché dalla tabella Endpoint. Trattarlo come sola lettura e scrivere invece tramite `/api/v2/location_findings/`.
