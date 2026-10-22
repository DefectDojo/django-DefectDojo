---
title: Ottimizzazione della Deduplicazione
description: 'Configura la deduplicazione in DefectDojo Open Source: algoritmi, campi
  hash, endpoint e servizio'
weight: 5
audience: opensource
aliases:
- /it/en/working_with_findings/finding_deduplication/deduplication_tuning_os
- /it/en/working_with_findings/finding_deduplication/deduplication_algorithms
---

L'edizione Open Source di DefectDojo utilizza file di impostazioni e variabili d'ambiente per ottimizzare la deduplicazione.

Vedi anche: [Configurazione Open Source](/get_started/open_source/configuration/) per i dettagli sulle variabili d'ambiente e sugli override di `local_settings.py`.

## Cosa puoi configurare

- **Algoritmo per parser**: scegli tra Unique ID From Tool, Hash Code, Unique ID From Tool or Hash Code, oppure Legacy (solo OS).
- **Campi hash per scanner**: decidi quali campi contribuiscono all'hash per ciascun parser.
- **Consenti CWE nullo**: controlla se un CWE mancante/zero è accettabile durante l'hashing.
- **Considerazione degli endpoint**: utilizza facoltativamente gli endpoint per la deduplicazione quando non fanno parte dell'hash.
- **Campi sempre inclusi**: aggiungi campi (ad es. `service`) a tutti gli hash indipendentemente dalle impostazioni per scanner.

## Impostazioni principali (valori predefiniti mostrati)

Tutti i valori predefiniti sono definiti in `dojo/settings/settings.dist.py`. Sovrascrivili tramite variabili d'ambiente o `local_settings.py`.

### Algoritmo per parser

- Impostazione: `DEDUPLICATION_ALGORITHM_PER_PARSER`
- Valori per parser: uno tra `unique_id_from_tool`, `hash_code`, `unique_id_from_tool_or_hash_code`, `legacy`.
- Esempio (stringa JSON come variabile d'ambiente):

```bash
DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Trivy Scan": "hash_code", "Veracode Scan": "unique_id_from_tool_or_hash_code"}'
```

### Campi hash per scanner

- Impostazione: `HASHCODE_FIELDS_PER_SCANNER`
- Esempio di valore predefinito per Trivy in OS:

```startLine:endLine:dojo/settings/settings.dist.py
1318:1321:dojo/settings/settings.dist.py
    "Trivy Operator Scan": ["title", "severity", "vulnerability_ids", "description"],
    "Trivy Scan": ["title", "severity", "vulnerability_ids", "cwe", "description"],
    "TFSec Scan": ["severity", "vuln_id_from_tool", "file_path", "line"],
    "Snyk Scan": ["vuln_id_from_tool", "file_path", "component_name", "component_version"],
```

- Esempio di override (stringa JSON come variabile d'ambiente):

```bash
DD_HASHCODE_FIELDS_PER_SCANNER='{"ZAP Scan":["title","cwe","severity"],"Trivy Scan":["title","severity","vulnerability_ids","description"]}'
```

### Consenti CWE nullo per scanner

- Impostazione: `HASHCODE_ALLOWS_NULL_CWE`
- Controlla per ciascun parser se un CWE nullo/zero è accettabile nell'hashing. Se è False e il riscontro ha `cwe = 0`, l'hash ricade sul calcolo legacy per quel riscontro.

### Campi sempre inclusi nell'hash

- Impostazione: `HASH_CODE_FIELDS_ALWAYS`
- Predefinito: `["service"]`
- Impatto: viene aggiunto all'hash per ogni scanner. Rimuovendo `service` da qui, smette di influenzare gli hash in generale.

```startLine:endLine:dojo/settings/settings.dist.py
1464:1466:dojo/settings/settings.dist.py
# Adding fields to the hash_code calculation regardless of the previous settings
HASH_CODE_FIELDS_ALWAYS = ["service"]
```

### Deduplicazione opzionale basata su endpoint

- Impostazione: `DEDUPE_ALGO_ENDPOINT_FIELDS`
- Predefinito: `["host", "path"]`
- Scopo: se gli endpoint non fanno parte dei campi hash, puoi comunque richiedere una corrispondenza minima degli endpoint per la deduplicazione. Se l'elenco è vuoto `[]`, gli endpoint vengono ignorati nel percorso di deduplicazione.

```startLine:endLine:dojo/settings/settings.dist.py
1491:1499:dojo/settings/settings.dist.py
# Allows to deduplicate with endpoints if endpoints is not included in the hashcode.
# Possible values are: scheme, host, port, path, query, fragment, userinfo, and user.
# If a finding has more than one endpoint, only one endpoint pair must match to mark the finding as duplicate.
DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "path"]
```

## Endpoint: come ottimizzare

Gli endpoint possono influenzare la deduplicazione tramite due meccanismi:

1) Includi `endpoints` in `HASHCODE_FIELDS_PER_SCANNER` per un parser. In questo caso gli endpoint fanno parte dell'hash e devono corrispondere esattamente secondo le regole di hashing del parser.
2) Se gli endpoint non sono presenti nei campi hash, usa `DEDUPLE_ALGO_ENDPOINT_FIELDS` per specificare gli attributi da confrontare. Esempi:
   - `[]`: gli endpoint vengono ignorati per la deduplicazione.
   - `["host"]`: i riscontri vengono deduplicati se una coppia di endpoint corrisponde per host.
   - `["host", "port"]`: i riscontri vengono deduplicati se una coppia di endpoint corrisponde per host E porta.

Note:

- Per l'algoritmo Legacy, i riscontri statici e dinamici hanno regole di corrispondenza degli endpoint diverse (vedi la pagina degli algoritmi). L'impostazione `DEDUPLE_ALGO_ENDPOINT_FIELDS` si applica al percorso hash-code, non alla logica intrinseca dell'algoritmo Legacy.
- Per la corrispondenza `unique_id_from_tool` (basata su ID), gli endpoint vengono ignorati per la decisione di deduplicazione.

## Campo Service: deduplicazione e reimportazione

- Con il valore predefinito `HASH_CODE_FIELDS_ALWAYS = ["service"]`, il campo `service` viene aggiunto all'hash. Due riscontri altrimenti identici con valori `service` diversi non verranno deduplicati sui percorsi basati su hash.
- Durante l'importazione tramite UI/API, il campo `Service` può sovrascrivere il servizio fornito dal parser. Modificarlo cambia l'hash e può alterare il comportamento di deduplicazione e la corrispondenza in fase di reimportazione.
- Se vuoi una deduplicazione indipendente dal servizio, rimuovi `service` da `HASH_CODE_FIELDS_ALWAYS` oppure lascia vuoto il campo `Service` durante l'importazione.

## Dopo aver modificato le impostazioni di deduplicazione

Dopo aver modificato gli algoritmi o il calcolo dell'Hash, dovrai **ricalcolare gli hash** per il parser/tipo di test interessato prima che il nuovo comportamento di corrispondenza si applichi in modo coerente ai dati esistenti.

Nota: il ricalcolo degli hash può comportare tempi di attesa lunghi su istanze di grandi dimensioni. Pianifica di conseguenza le finestre di manutenzione.

- Le modifiche alla configurazione di deduplicazione (ad es. `HASHCODE_FIELDS_PER_SCANNER`, `HASH_CODE_FIELDS_ALWAYS`, `DEDUPLICATION_ALGORITHM_PER_PARSER`) non vengono applicate retroattivamente in modo automatico. Per rivalutare i riscontri esistenti devi eseguire il comando di gestione seguente.

### Eseguire la deduplicazione su un backlog di dati preesistenti

Quando configuri per la prima volta le impostazioni di deduplicazione (o le modifichi in seguito), i Riscontri importati prima della modifica mantengono i loro vecchi hash finché non riesegui esplicitamente la deduplicazione.  Usa il comando di gestione `dedupe` per ricalcolare l'hash e/o rivalutare i Riscontri esistenti.

Esegui all'interno del container uwsgi. Esempio (solo codici hash, nessuna deduplicazione):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --hash_code_only"
```

Per **ricalcolare gli hash ed eseguire la deduplicazione** per tutti i parser (il tipico flusso di lavoro "ho appena attivato la deduplicazione e voglio ripulire il backlog"):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe"
```

Per interessare solo un parser specifico:

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --parser 'Trivy Scan'"
```

Guida/utilizzo:
```
options:
  --parser PARSER       List of parsers for which hash_code needs recomputing
                        (defaults to all parsers)
  --hash_code_only      Only compute hash codes
  --dedupe_only         Only run deduplication
  --dedupe_sync         Run dedupe in the foreground, default false
```

Se invii la deduplicazione a Celery (senza `--dedupe_sync`), lascia il tempo necessario affinché i task si completino prima di valutare i risultati.  Su istanze di grandi dimensioni questo può richiedere una quantità di tempo considerevole — monitora i log dei worker Celery per seguire l'avanzamento.

## Dove configurare

- Preferisci le variabili d'ambiente nei deployment. Per lo sviluppo locale o override avanzati, usa `local_settings.py`.
- Consulta `configuration.md` per i dettagli su come impostare le variabili d'ambiente e configurare gli override locali.

### Risoluzione dei problemi

Per facilitare la risoluzione dei problemi di deduplicazione, utilizza i seguenti strumenti:

- Osserva l'output di log nella categoria `dojo.specific-loggers.deduplication`. Si tratta di un logger indipendente dalla classe che restituisce dettagli sul processo di deduplicazione e sulle impostazioni durante l'elaborazione dei riscontri.
- Osserva i valori `unique_id_from_tool` e `hash_code` passando il mouse sopra il campo `ID` o la colonna `Status`:

![Unique ID from Tool e Hash Code nella pagina Visualizza Riscontro](images/hash_code_id_field.png)

![Unique ID from Tool e Hash Code nella colonna Stato dell'elenco Riscontri](images/hash_code_status_column.png)
