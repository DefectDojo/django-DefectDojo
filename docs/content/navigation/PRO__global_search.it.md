---
title: Ricerca globale
description: Cerca tra Riscontri, Asset e oggetti correlati dalla barra superiore
  di DefectDojo Pro
audience: pro
weight: 3
---

DefectDojo Pro include una **ricerca globale** che esplora i Riscontri e gli oggetti correlati da un'unica casella nella barra superiore. È basata sulla ricerca full-text nativa di Postgres, con corrispondenza fuzzy e tolleranza agli errori di battitura, così è possibile trovare un oggetto anche senza ricordarne la dicitura esatta.

## Eseguire una ricerca

- **Casella di ricerca nella barra superiore** — fare clic sulla casella **Search** nella barra di navigazione superiore e iniziare a digitare. Durante la digitazione, un menu a discesa mostra un'anteprima dei principali risultati **raggruppati per tipo di oggetto**, con un conteggio accanto a ciascun tipo e un link **See all *N* results** in fondo.
- **Pagina dei risultati completa** — premere **Invio**, oppure fare clic su **See all *N* results**, per aprire la pagina dei risultati completa. Si tratta di un'unica tabella ordinabile e filtrabile che riporta tutte le corrispondenze tra tutti i tipi di oggetto.

I risultati sono sempre **limitati a ciò che si è autorizzati a visualizzare** — la ricerca globale non mostra mai oggetti a cui non si avrebbe altrimenti accesso. (I Finding Template sono l'unica eccezione: come nel resto di DefectDojo, sono visibili a qualsiasi utente autenticato.)

## Cosa è possibile cercare

La ricerca globale copre questi tipi di oggetto:

| Tipo di oggetto | Note |
| --- | --- |
| **Findings** | |
| **Assets** | (Products) |
| **Organizations** | (Product Types) |
| **Engagements** | |
| **Tests** | |
| **Endpoints** *oppure* **Locations** | A seconda di quale utilizza la propria istanza — le istanze con [Locations](/asset_modelling/locations/pro__locations_overview/) abilitate cercano tra le Locations; le altre cercano tra gli Endpoint. |
| **Finding Templates** | |
| **Technologies** | |
| **Vulnerability IDs** | ad es. CVE |

Per la maggior parte dei tipi, la ricerca trova corrispondenze nel **nome/titolo e nella descrizione** dell'oggetto. Per Findings, Assets, Engagements e Tests, la ricerca trova corrispondenze anche nei **tag** (per prefisso). I Vulnerability ID trovano corrispondenza sul valore dell'ID stesso.

## Sintassi della query

### Testo libero

Digitare qualsiasi parola chiave per cercare tutto contemporaneamente. Le corrispondenze vengono classificate per rilevanza, con i risultati su titolo/nome classificati sopra quelli su descrizione. Grazie alla corrispondenza fuzzy (vedere sotto), anche i termini simili ma non esatti trovano corrispondenza.

### Frasi tra virgolette

Racchiudere una frase tra virgolette doppie per mantenerla unita — `"space inside"` viene trattato come un unico termine anziché come due parole chiave.

### Operatori

Anteporre a un termine un operatore (`operator:value`) per restringere la ricerca. Gli operatori supportati sono:

| Operatore | Cosa fa |
| --- | --- |
| `finding:` `product:` `engagement:` `test:` `template:` `technology:` | Limita la ricerca a un singolo tipo di oggetto e la esegue su quel valore (ad es. `finding:sqli`). |
| `id:` | Cerca un Riscontro in base al suo ID numerico (ad es. `id:12345`). |
| `endpoint:` | Trova i Riscontri il cui host endpoint/location contiene il valore. |
| `vulnerability_id:` | Corrispondenza esatta su un Vulnerability ID. Accetta un elenco separato da virgole e può essere ripetuto (ad es. `vulnerability_id:CVE-2020-1234,CVE-2018-7489`). |
| `tag:` / `tags:` | Trova oggetti in base al tag. `tag:` trova un singolo tag per sottostringa; `tags:` trova qualsiasi tag presente in un elenco. |
| `test-tag:` `engagement-tag:` `product-tag:` (e i rispettivi plurali `-tags`) | Trova corrispondenza in base a un tag sul Test, l'Engagement o l'Asset correlato, anziché sull'oggetto stesso. |
| `not-tag:` `not-tags:` (e le varianti di relazione `not-…-tag`) | Nega uno qualsiasi degli operatori di tag sopra indicati per **escludere** le corrispondenze. |

È possibile combinare gli operatori con parole chiave in testo libero nella stessa query.

### Corrispondenza fuzzy

Per le query di **tre o più caratteri**, la ricerca globale esegue anche una corrispondenza trigram (per similarità delle parole). Questo tollera gli errori di battitura e trova termini **all'interno** di valori più lunghi con punti o trattini — ad esempio, `internal` trova corrispondenza con `api.internal.example.com`.

## Filtrare e ordinare la pagina dei risultati

Nella pagina dei risultati completa, le colonne possono essere filtrate e ordinate indipendentemente dal testo della query — filtrare per **object type**, **severity**, **title**, o **context**, e ordinare in base a qualsiasi colonna. Questi filtri sono indipendenti dalla sintassi `operator:` descritta sopra e si applicano alla tabella dei risultati unificata.

## Limiti dei risultati

- La pagina dei risultati completa è **paginata** (25 righe per pagina per impostazione predefinita).
- Ogni tipo di oggetto contribuisce fino a un **numero massimo di corrispondenze** per ricerca — **100** per impostazione predefinita. Quando esistono più corrispondenze di quelle mostrate, i risultati vengono contrassegnati come troncati; restringere la query per vedere le corrispondenze più rilevanti.
- Il menu a discesa nella barra superiore mostra un'anteprima più piccola (le prime corrispondenze per ciascun tipo) con i conteggi totali, quindi **See all *N* results** riflette sempre i totali reali.
