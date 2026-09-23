---
title: Conformità federale
description: Deliverable POA&M e ConMon FedRAMP, valutazioni CMMC Level 2 e copertura
  dei controlli NIST 800-53
summary: ''
draft: false
weight: 6
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
audience: pro
exclude_search: true
---

DefectDojo Pro può gestire la parte di vulnerability management di un programma di conformità federale. Mantiene
un Plan of Action and Milestones (POA&M) in stile FedRAMP per ciascun sistema, produce mensilmente i deliverable
di Continuous Monitoring (ConMon) nei formati ufficiali Excel e OSCAL, valuta le autovalutazioni CMMC
Level 2 e mostra quali controlli NIST 800-53 i tuoi scanner esercitano realmente.

Tutto ciò che è descritto in questa sezione si trova nella scheda **Compliance** di un Asset.

## Abilitare la funzionalità

Federal Compliance è disponibile dietro il feature flag **Compliance**, che è in beta e disattivato per
impostazione predefinita. Un amministratore lo attiva dal menu dei feature flag — vedi
[Feature Flags](/admin/feature_flags/pro__feature_flags/). Una volta abilitato, la scheda Compliance
compare su ogni Asset.

## Beta: verifica i risultati prima di affidarti a essi

**Questa funzionalità è in beta.** Le dichiarazioni di controllo NIST 800-171 e 800-53 incluse, i pesi
dei punteggi DoD SPRS e le regole di idoneità al POA&M sono fornite per aiutarti a monitorare e stimare
la tua postura, e sono in attesa di validazione indipendente rispetto ai documenti di origine autorevoli.

I punteggi SPRS, i risultati di idoneità condizionale e la copertura dei controlli hanno **valore puramente
indicativo**. Verificali rispetto alla DoD NIST SP 800-171 Assessment Methodology ufficiale e alle linee
guida FedRAMP correnti prima di affidarti a essi per una certificazione, l'invio di una valutazione o
qualsiasi finalità contrattuale.

## In questa sezione

| Pagina | Cosa tratta |
| --- | --- |
| [Compliance Profile](compliance_profile) | Registrare un Asset come sistema e impostare i dati che compaiono su ogni deliverable |
| [The POA&M Ledger](poam_ledger) | Come vengono creati gli elementi POA&M a partire dai riscontri, e le convenzioni seguite dal registro |
| [ConMon Snapshots](conmon_snapshots) | Deliverable mensili in Excel e OSCAL FedRAMP, e il servizio opzionale di validazione OSCAL |
| [Remediation Deadlines](remediation_slas) | I preset SLA di FedRAMP Rev 5 e FedRAMP VDR |
| [CMMC Level 2 Assessments](cmmc_assessments) | Valutare un'autovalutazione rispetto a NIST 800-171 Rev 2 |
| [Control Coverage](control_coverage) | Quali controlli 800-53 testano i tuoi scanner, e le vulnerabilità aperte per controllo |
