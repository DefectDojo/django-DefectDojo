---
title: Copertura dei controlli
description: Quali controlli 800-53 testano i tuoi scanner, e le vulnerabilità aperte
  per controllo
weight: 6
audience: pro
---

La vista di copertura dei controlli risponde a una domanda semplice: quali controlli 800-53 testano
davvero i miei scanner, e dove si trovano le vulnerabilità aperte per ciascun controllo?

![La heatmap di copertura dei controlli](images/07-control-coverage.png)

## Da dove provengono le mappature

Molti scanner emettono già riferimenti ai controlli, e DefectDojo li estrae automaticamente in
mappature dei controlli. Tra gli altri:

* **Prowler** scrive elenchi di controlli NIST 800-53 nei riferimenti dei riscontri.
* I plugin di **Tenable** riportano riferimenti incrociati 800-53.
* I profili **InSpec** e **MITRE SAF** etichettano i propri controlli con identificatori `nist`.

L'estrazione si basa sul catalogo importato, quindi un identificativo che il catalogo non riconosce
non produce mai una mappatura.

I riscontri privi di propri riferimenti ai controlli vengono attribuiti ai default scan controls
del Compliance Profile — vedi [Profilo di conformità](../compliance_profile).

### Colmare a ritroso i riscontri esistenti

L'estrazione viene eseguita man mano che arrivano i riscontri. Per mappare i riscontri già
importati prima che la funzionalità fosse abilitata, esegui un backfill:

```
manage.py extract_control_mappings --product <id>
```

Usa `--all` per analizzare ogni riscontro attivo invece di un solo prodotto. Il comando riporta
quante mappature ha creato, e lascia intatte le mappature manuali e quelle soppresse.

## Correggere una mappatura

Le mappature che crei o correggi manualmente prevalgono sempre su quelle estratte, e una mappatura
che elimini resta eliminata — le reimportazioni non la faranno riapparire.

## Cosa mostra la vista

* Una **heatmap per famiglia di controlli**.
* Per ogni controllo, i **riscontri aperti mappati su di esso**.

I controlli provengono dai cataloghi inclusi: NIST 800-53 Rev 5 e NIST 800-171 Rev 2, entrambi
importati all'avvio.

**La copertura ha valore puramente indicativo finché la funzionalità è in beta.** La copertura dei
controlli riflette ciò che riportano i tuoi scanner e ciò che i cataloghi inclusi riconoscono. Non
costituisce un'attestazione che un controllo sia implementato o efficace. Verifica la copertura
rispetto al tuo System Security Plan prima di farvi affidamento per una valutazione.

## Tracciabilità

Le mappature dei controlli sono soggette a cronologia delle modifiche. Ogni modifica registra chi,
cosa e quando.
