---
title: Utilizzo degli SBOM
description: Gestire le dipendenze software e gli SBOM come Location
audience: pro
weight: 5
---

DefectDojo Pro rappresenta le librerie software come **Dependency Location**. Una Dependency è un sottotipo di Location identificato da un [Package URL (pURL)](https://github.com/package-url/purl-spec) e pensato per rappresentare una singola libreria o pacchetto — `org.apache.logging.log4j:log4j-core@2.17.0`, `pypi/django@5.0.2`, `npm/react@18.2.0`, e così via.

Le Dependency sostituiscono il precedente modello **Components**, che era collegato solo ai Finding. Con Location, le librerie possono esistere indipendentemente da qualsiasi vulnerabilità — è possibile caricare un SBOM su un Asset e lasciare che i Finding si colleghino automaticamente alle dipendenze a cui fanno riferimento man mano che arrivano le scansioni.

## Cosa contiene una Dependency

Ogni Dependency è identificata in modo univoco da un pURL, scomposto in campi atomici su cui è possibile cercare e filtrare:

| Campo | Significato | Esempio |
| --- | --- | --- |
| `purl_type` | Ecosistema della libreria | `npm`, `pypi`, `maven`, `cargo`, `nuget`, `gem` |
| `namespace` | Vendor o organizzazione | `org.apache.logging` |
| `name` | Nome della libreria | `log4j-core` |
| `version` | Versione specifica | `2.17.0` |
| `qualifiers` *(opzionale)* | Dettagli implementativi | `arch=amd64` |
| `subpath` *(opzionale)* | Percorso all'interno di un archivio o monorepo | `src/lib/foo` |
| `artifact_hashes` *(opzionale)* | Impronte digitali | somme SHA256 |
| `license_expression` *(opzionale)* | Espressione di licenza SPDX | `Apache-2.0`, `MIT` |
| `file_path` *(opzionale)* | Dove è stata trovata la libreria nel progetto | `package-lock.json` |

Questa scomposizione atomica è ciò che rende utile la ricerca basata su pURL: si può chiedere *"tutti i pacchetti `pypi` nel namespace `django` alla versione 4.x"* e DefectDojo può rispondere senza dover analizzare una stringa di testo libero.

## Owned-By vs Used-By

Quando una Dependency è associata a un Asset, l'Asset Reference porta con sé una **relazione** opzionale che descrive *come* la libreria appartiene all'Asset:

- **`owned_by`** — *"questa libreria è di proprietà di questo Asset"*. Utilizzare questo valore per le librerie proprietarie che un Asset pubblica o mantiene.
- **`used_by`** — *"questa libreria è utilizzata da questo Asset"*. Utilizzare questo valore per le dipendenze di terze parti che un Asset consuma.

La stessa libreria può essere `owned_by` per un Asset e `used_by` per molti altri, che è esattamente la relazione necessaria per rispondere a *"chi consuma il pacchetto pubblicato dal mio team?"* durante il triage delle vulnerabilità.

## Caricamento di un SBOM

Per popolare le Dependency in blocco, caricare un file SBOM su un Product. L'endpoint è:

```
POST /api/v2/sbom-import/
```

| Campo | Descrizione |
| --- | --- |
| `product` | L'ID del Product (Asset) di destinazione |
| `file` | Il file SBOM |
| `scan_type` | Il formato dell'SBOM — vedi i formati supportati di seguito |
| `replace` *(opzionale)* | Se `true`, le associazioni Product obsolete non supportate da un riferimento a un Finding esistente vengono rimosse. Predefinito: `false` (cumulativo) |

L'importatore analizza il file, estrae i record `Dependency`, li deduplica rispetto alle Location esistenti (creandone di nuove quando necessario) e crea Asset Reference che collegano ogni Dependency al Product. L'interfaccia Pro espone lo stesso flusso di caricamento — vedi l'azione **Upload SBOM** nella scheda Location di un Product.

### Formati supportati

L'MVP include parser per i due formati SBOM dominanti:

- **CycloneDX** — JSON e XML
- **SPDX** — JSON (v2 e v3), XML e tag-value

Il formato SWID Tag non è ancora supportato.

### Sostituzione o Aggiunta

Per impostazione predefinita, i caricamenti ripetuti sono **additivi**: le dipendenze già presenti sull'Asset vengono mantenute, quelle nuove vengono aggiunte e nulla viene rimosso. Questo corrisponde al tipico flusso di lavoro degli aggiornamenti incrementali degli SBOM.

Impostare `replace=true` per effettuare una pulizia. Quando la modalità replace è attiva, dopo un import riuscito l'importatore rimuove le associazioni Product che non erano presenti nel nuovo SBOM **e** che non sono attualmente referenziate da un Finding attivo. I riferimenti collegati a Finding attivi vengono preservati anche in modalità replace, quindi non si perde il contesto della vulnerabilità solo perché un nuovo SBOM omette un pacchetto.

## Findings che fanno riferimento a librerie

Quando un parser acquisisce una vulnerabilità collegata a una libreria — ad esempio, uno strumento SCA che segnala `CVE-2021-44228` contro `log4j-core@2.14.1` — l'importatore:

1. Cerca una Dependency Location esistente tramite il pURL, oppure ne crea una nuova.
2. Crea una `LocationFindingReference` che collega il Finding alla Dependency con stato **Attivo**.
3. Crea una `LocationProductReference` in modo che la Dependency compaia anche sul Product padre, se non è già presente.

Poiché i Finding e i caricamenti SBOM condividono gli stessi oggetti Dependency sottostanti, un Finding acquisito *prima* di un caricamento SBOM sarà visibile retroattivamente nella vista SBOM, e viceversa.

## API REST

| Attività | Endpoint |
| --- | --- |
| Caricare un SBOM | `POST /api/v2/sbom-import/` |
| Elencare le Dependency | `GET /api/v2/dependencies/` |
| Creare una Dependency manualmente | `POST /api/v2/dependencies/` |
| Elencare le Dependency Location | `GET /api/v2/location/?location_type=dependency` |
| Collegare una Dependency a un Finding | `POST /api/v2/location_findings/` |
| Collegare una Dependency a un Product (con `owned_by` / `used_by`) | `POST /api/v2/location_products/` |

I filtri su `/api/v2/dependencies/` includono i campi componenti del pURL, i tag e l'ordinamento su `name`, `version` e il conteggio dei Finding attivi.

## Nell'interfaccia Pro

Quando Location è abilitata, la navigazione espone:

- **Locations / Dependencies** — Elenco globale di tutte le Dependency nell'istanza, con filtri pURL.
- **Locations su un Product/Asset** — Vista per Asset che mostra sia URL sia Dependency, con l'azione **Upload SBOM** disponibile nella scheda Dependencies.
- **New Dependency** — Modulo per creare una singola libreria inserendo manualmente i componenti del suo pURL.
- **Findings detail** — Un Finding che riguarda una libreria mostra le sue Dependency Location insieme a eventuali URL Location, così è possibile vedere *"questa CVE riguarda `log4j-core@2.14.1` sull'Asset 6 e sull'Asset 9"* in un unico posto.

## Cosa non è incluso nell'MVP

- **Formato SBOM SWID Tag** — Non viene analizzato. È richiesto CycloneDX o SPDX.
- **Valutazione del rischio di licenza** — Il campo `license_expression` viene acquisito quando presente nell'SBOM, ma DefectDojo non segnala ancora i riscontri per incompatibilità di licenza. Il reporting basato sulle licenze è nella roadmap come seguito dell'MVP di Location.
- **Location per immagini container e risorse cloud** — Futuri sottotipi di Location. Per ora, le librerie individuate all'interno di un'immagine container vengono registrate come Dependency; l'immagine container stessa non è ancora una Location di prima classe.
