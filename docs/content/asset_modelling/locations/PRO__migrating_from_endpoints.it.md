---
title: Migrazione dagli Endpoint
description: Cosa succede quando si migrano i dati Endpoint esistenti verso Location
audience: pro
weight: 3
---

Quando si abilita Location su un'istanza DefectDojo Pro esistente, i dati già memorizzati come Endpoint devono essere riportati nel nuovo modello Location. Questa pagina descrive la migrazione, cosa viene preservato e come si comporta l'API Endpoint legacy una volta eseguita la migrazione.

Nota che la migrazione è **a senso unico**. Non esiste un percorso di rollback automatizzato che ricrei gli Endpoint a partire dalle Location.

## Cosa fa la migrazione

Per ogni Endpoint esistente, la migrazione:

1. **Crea una URL Location** (o ne riutilizza una esistente) usando i campi `protocol`, `userinfo`, `host`, `port`, `path`, `query` e `fragment` dell'Endpoint. Il nuovo URL viene collegato automaticamente a un oggetto `Location` padre.
2. **Riporta i tag.** Ogni tag presente sull'Endpoint viene aggiunto all'insieme di tag della Location.
3. **Riporta i metadati.** Ogni riga `DojoMeta` collegata all'Endpoint viene ricollegata alla nuova Location.
4. **Crea una `LocationProductReference`** in modo che l'URL compaia sotto l'Asset (Product) corretto.
5. **Crea una `LocationFindingReference` per ogni `Endpoint_Status`**:

   | Flag Endpoint_Status | Stato Location risultante |
   | --- | --- |
   | `risk_accepted=True` | **Rischio accettato** |
   | `false_positive=True` | **Falso positivo** |
   | `out_of_scope=True` | **Fuori ambito** |
   | `mitigated=True` | **Mitigato** |
   | (nessuno dei precedenti) | **Attivo** |

   La mappatura dipende dall'ordine: vince il *primo* flag corrispondente. Questo comprime intenzionalmente le vecchie combinazioni multi-flag in un unico stato canonico usato dalle Location.


## Cosa non fa la migrazione

- **Non** crea Dependency Location. I dati SBOM e delle librerie non sono mai esistiti come Endpoint, quindi non c'è nulla da convertire per la migrazione. Per popolare le Dependency, caricare gli SBOM (vedi [Utilizzo degli SBOM](../pro__working_with_sboms)) oppure rieseguire le scansioni con parser che generano dati sulle dipendenze.
- **Non** elimina le righe originali di Endpoint o Endpoint_Status. Rimangono nel database a supporto dell'API legacy in sola lettura. Non vengono utilizzate dalla nuova interfaccia né dagli import dopo l'abilitazione della funzionalità.

## API Endpoint dopo la migrazione

Una volta abilitata Location, l'API Endpoint legacy entra in una modalità di **compatibilità in lettura** pensata per mantenere funzionanti le automazioni esistenti senza modifiche al codice, ma solo per il traffico in lettura.

### Cosa continua a funzionare

- `GET /api/v2/endpoints/` — Restituisce righe che *sembrano* Endpoint ma sono in realtà proiettate dalle righe Location Product Reference unite alle URL Location. I campi consueti (`protocol`, `host`, `port`, `path`, `query`, `fragment`, `tags`, `product`, `active_finding_count`) sono tutti presenti.
- `GET /api/v2/endpoints/{id}/` — Il recupero di un singolo Endpoint funziona allo stesso modo. L'`id` è l'ID Endpoint originale e viene preservato durante la migrazione tramite la mappatura Asset Reference.
- `GET /api/v2/endpoint_status/` e `GET /api/v2/endpoint_status/{id}/` — Restituiscono righe proiettate da `LocationFindingReference`. I campi booleani legacy `mitigated`, `false_positive`, `out_of_scope` e `risk_accepted` vengono ricostruiti.
- Il filtraggio per `protocol`, `host`, `port`, `path`, `query`, `fragment`, `product` e `tag(s)` continua a funzionare.
- L'azione `generate_report` sui singoli Endpoint continua a funzionare.

### Cosa restituisce 403

- `POST`, `PUT`, `PATCH` e `DELETE` su `/api/v2/endpoints/` e `/api/v2/endpoint_status/` restituiscono tutti `HTTP 403` con il seguente corpo:

  > Writes to this endpoint are deprecated when V3_FEATURE_LOCATIONS is enabled

  I client che scrivono dati Endpoint devono passare ai nuovi endpoint Reference (`POST /api/v2/location_findings/`, `POST /api/v2/location_products/`) e all'endpoint URL (`POST /api/v2/urls/`).

### Differenze di comportamento da tenere presenti

Alcuni aspetti si comportano diversamente rispetto all'API Endpoint originale:

- **Stato singolo invece di flag.** Le Location hanno un solo stato alla volta. Se il codice si basava su un Finding con *sia* `mitigated=True` *sia* `false_positive=True` contemporaneamente su un Endpoint_Status, questo non è più rappresentabile — la migrazione sceglie il flag con priorità più alta (l'ordine mostrato nella tabella sopra).
- **Campo `endpoint` su Endpoint_Status.** Il campo legacy `endpoint` viene ricostruito cercando l'Asset Reference corrispondente. Nei rari casi in cui l'Asset di un Finding non corrisponde più agli Asset Reference della sua Location, questo campo può essere nullo.
- **Paginazione e ordinamento.** I campi di ordinamento disponibili sullo shim di compatibilità in lettura sono `host`, `product`, `id` e `active_finding_count`. Se il client ordina per un altro campo, passare a uno di questi o migrare ai nuovi endpoint Location.

## Tag e metadati

I tag applicati agli Endpoint diventano tag sull'oggetto Location (non sul sottotipo URL). I filtri basati su tag nell'API legacy continuano a funzionare correttamente.

I metadati Endpoint vengono ricollegati alla Location durante la migrazione. Le automazioni esistenti che leggono i metadati tramite `/api/v2/endpoint_meta/` dovrebbero continuare a funzionare; i nuovi metadati vanno scritti attraverso gli endpoint Location.
