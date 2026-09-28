---
title: Panoramica delle Posizioni
description: Cosa sono le Posizioni e perché sostituiscono gli Endpoint
audience: pro
weight: 1
---

Le **Posizioni** sono un nuovo strumento di modellazione degli asset in DefectDojo Pro. Sostituiscono il modello legacy degli **Endpoint** e assorbono i precedenti dati dei **Componenti** (librerie), offrendo a DefectDojo un modo unico e polimorfico per descrivere *dove* si trova un Riscontro — che si tratti di un URL, di una dipendenza software proveniente da una **SBOM**, oppure, in futuro, di un **ID di risorsa cloud**, di un'**immagine container** o di un **repository di codice**.

Le Posizioni devono essere abilitate sulla tua istanza prima di poterle utilizzare. Puoi abilitare autonomamente le Posizioni dalla [pagina dei Feature Flag](/admin/feature_flags/pro__feature_flags/) — non è richiesta alcuna richiesta al Supporto. Tieni presente che, una volta abilitate, le Posizioni non possono più essere disattivate.

## Perché sostituire gli Endpoint?

Il modello originale degli Endpoint era costruito attorno a URL e indirizzi IP — includeva campi tipici delle applicazioni web come `protocol`, `host`, `port`, `path`, e una tabella di stato fissa strettamente accoppiata ai Riscontri. Ne derivavano tre problemi:

1. **Fedeltà limitata.** Gli Endpoint non potevano descrivere in modo pulito asset non-URL come librerie di terze parti, immagini container o risorse cloud, nonostante gli scanner producano sempre più spesso riscontri relativi a questi elementi.
2. **Limite di prestazioni.** Le righe Endpoint_Status per ciascun Riscontro e lo schema modellato sugli URL non scalavano bene con grandi volumi di clienti.
3. **I Componenti erano di seconda classe.** Le librerie software esistevano solo come campi denormalizzati su un Riscontro, quindi una libreria non poteva esistere indipendentemente da una vulnerabilità — rendendo impossibile una vera gestione delle SBOM.

Le Posizioni risolvono tutti e tre i problemi introducendo un **oggetto `Location` di base** con un payload tipizzato, oltre a **sottotipi** dedicati per ciascuna forma di asset:

- **Posizioni URL** — equivalente funzionale dei vecchi Endpoint, con gli stessi campi protocol/host/port/path/query/fragment.
- **Posizioni Dipendenza** — librerie software identificate tramite [Package URL (pURL)](https://github.com/package-url/purl-spec), utilizzate per modellare il contenuto delle SBOM.
- **[Posizioni Codice Sorgente](/asset_modelling/locations/pro__source_code_locations/)** — dove risiede nel codice sorgente un riscontro di analisi statica, identificato da percorso file e numero di riga. Gestite dalla scansione, e sono il substrato per [il tracciamento dei riscontri al variare del codice](/triage_findings/finding_deduplication/pro__location_drift_matching/).

Tra i futuri tipi di Posizione in fase di valutazione figurano gli ID di risorsa dei cloud provider (AWS ARN, Azure Resource ID, GCP Full Resource Name) e le immagini container (registry/repository:tag e impronte SHA256).

## Concetti chiave

### Posizioni e sottotipi

Una **Location** è il genitore condiviso. Contiene:

- Un `Location Type` (ad es. `"url"`, `"dependency"`)
- Una stringa `Location Value` canonica, utilizzata per la visualizzazione, la ricerca e la deduplicazione
- `Tags` e i tag ereditati dall'Asset padre
- Metadati (coppie chiave/valore personalizzate)

Un **sottotipo** (URL o Dependency) contiene i campi strutturati specifici per quel tipo di posizione. Gli URL e le Dependency vivono sempre accanto a un oggetto Location padre; il `Location Value` del sottotipo viene generato a partire dai suoi campi strutturati.

### Riferimenti

Le Posizioni non sono collegate direttamente a Prodotti o Riscontri. Sono invece due oggetti **Reference** a collegarle:

- **Asset Reference** — le relazioni che la Posizione ha con gli Asset (ad es. `libFoo` è *di proprietà di* Asset 6, *utilizzata da* Asset 9). Ogni riferimento ha uno stato (`Active` o `Mitigated`) e una **relazione** opzionale ("Used By" o "Owned By").
- **Finding Reference** — le relazioni che la Posizione ha con i Riscontri. Ogni riferimento ha uno stato più articolato (`Active`, `Mitigated`, `False Positive`, `Risk Accepted`, `Out of Scope`) oltre all'auditor e all'orario di audit.

Questa separazione è ciò che consente a una libreria di esistere su un Prodotto *senza* richiedere un Riscontro — una funzionalità mancante nel vecchio modello dei Componenti.

### Associazione automatica al momento dell'importazione

Quando un parser produce un Riscontro che fa riferimento a un URL o a una libreria, l'importer:

1. Cerca una Posizione esistente corrispondente all'URL o al pURL; se non ne esiste una, la crea.
2. Crea un Finding Reference che collega il Riscontro alla Posizione con stato `Active`.
3. Crea (o riutilizza) un Asset Reference in modo che la Posizione risieda anche sull'Asset padre.

I parser esistenti sono stati aggiornati per generare dati di Location quando il feature flag è attivo, e per ricadere sul vecchio modello Endpoint quando è disattivato. Non è necessaria alcuna riconfigurazione quando le Posizioni sono abilitate — la prossima importazione passerà automaticamente attraverso la pipeline delle Posizioni.

## Cosa include l'MVP

| Funzionalità | Stato |
| --- | --- |
| Modelli fondamentali `Location`, `URL`, `Dependency` | Rilasciato |
| API REST per Location e Reference | Rilasciato (`Location` in sola lettura, CRUD completo su Reference) |
| Shim di compatibilità in lettura per l'API Endpoint | Rilasciato |
| Comando di migrazione monodirezionale Endpoint → URL | Rilasciato |
| Aggiornamenti dei parser (URL e dipendenze) | Rilasciato per i parser principali |
| Caricamento SBOM (CycloneDX, SPDX v2/v3) | Rilasciato tramite `/api/v2/sbom-import/` |
| UI Pro per Location, URL, Dependency | Rilasciato |
| Ricerca/filtro pURL | Rilasciato |
| Tracciamento delle licenze sulle dipendenze | Parziale (campo `license_expression`) |
| Formato SBOM SWID Tag | Non incluso nell'MVP |

## Prossimi passi

- **Abilita la funzionalità** — contatta [support@defectdojo.com](mailto:support@defectdojo.com) per attivare le Posizioni sulla tua istanza.
- **Esegui la migrazione dagli Endpoint** — consulta [Migrazione dagli Endpoint](../pro__migrating_from_endpoints) per sapere cosa preserva la migrazione e come si comporta successivamente la vecchia API Endpoint.
- **Flussi di lavoro quotidiani con gli URL** — consulta [Utilizzo degli URL](../pro__working_with_urls).
- **SBOM e dipendenze** — consulta [Utilizzo delle SBOM](../pro__working_with_sboms).
