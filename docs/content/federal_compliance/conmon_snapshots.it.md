---
title: Snapshot ConMon
description: Deliverable mensili in Excel e OSCAL FedRAMP, e il servizio opzionale
  di validazione OSCAL
weight: 3
audience: pro
---

Nella scheda **Snapshots**, **Generate Snapshot** produce i deliverable per un periodo di rendicontazione.
Uno snapshot **blocca il registro** a quel momento: le modifiche successive non cambiano mai un
deliverable già generato.

![Snapshot ConMon generati](images/04-poam-snapshots.png)

Ogni riga mostra il periodo, il suo stato, il numero di elementi aperti e in ritardo, quando è stato
completato, e i link di download per entrambi gli artefatti.

## Cosa produce uno snapshot

Ogni snapshot produce due artefatti:

* L'ufficiale **FedRAMP POA&M Excel workbook** (versione template 3.0), con gli elementi aperti,
  chiusi e di configurazione nei rispettivi fogli di lavoro.
* Un documento **OSCAL plan-of-action-and-milestones**, fissato alla versione OSCAL 1.0.4 — quella
  accettata dalle attuali regole di validazione di FedRAMP.

### Cosa contiene l'output OSCAL

Il documento OSCAL usa il namespace di estensione di FedRAMP per i campi che gli strumenti FedRAMP
ricercano: ID POA&M, ID dei controlli impattati, stati di deviazione, dipendenza dal fornitore e
tracciamento KEV.

Ogni rischio riporta:

* Le sfaccettature di probabilità e impatto — iniziali, e adeguate quando è stato approvato un
  adeguamento del rischio.
* La correzione consigliata e la remediation pianificata, come risposte separate.
* Un registro dei rischi che riporta il rilevamento e l'ultima revisione dello stato.

I documenti vengono verificati rispetto allo schema NIST ufficiale al momento della generazione.

## Metriche mese su mese

Gli snapshot calcolano anche i numeri richiesti da un pacchetto ConMon: cosa è comparso, cosa è
stato risolto, cosa è in ritardo, e il conteggio degli elementi aperti per livello di rischio.

## Servizio di validazione OSCAL

Per un controllo più rigoroso, un deployment può eseguire l'**OSCAL validator service** incluso —
un piccolo container che racchiude `oscal-cli`, mantenuto da FedRAMP.

| Servizio di validazione | Cosa succede alla generazione |
| --- | --- |
| Non configurato | I documenti vengono validati rispetto allo schema JSON NIST. Il controllo più approfondito viene segnato come **skipped**. |
| Configurato | I documenti vengono validati anche tramite `oscal-cli`, e i risultati vengono memorizzati insieme allo snapshot. |

Per abilitarlo, imposta `DD_OSCAL_VALIDATOR_URL`, oppure abilita `oscalValidator` nell'Helm chart.

**Mantieni raggiungibile l'URL `import-ssp`.** `oscal-cli` dereferenzia l'href `import-ssp` durante
la validazione. Se il tuo Compliance Profile indica un URL OSCAL SSP che il container di validazione
non riesce a raggiungere, la validazione si interrompe invece di saltare quel passaggio. Rendi l'URL
raggiungibile dal validatore, oppure lascialo non impostato.

## Immutabilità

Gli snapshot e i loro artefatti sono immutabili per progettazione. Rigenerare un periodo produce un
nuovo snapshot; non riscrive mai uno esistente.
