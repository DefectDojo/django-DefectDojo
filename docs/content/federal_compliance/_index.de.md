---
title: Bundes-Compliance
description: FedRAMP-POA&M- und ConMon-Deliverables, CMMC-Level-2-Assessments und
  NIST-800-53-Kontrollabdeckung
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

DefectDojo Pro kann den Schwachstellenmanagement-Teil eines Compliance-Programms für Bundesbehörden übernehmen. Es
führt für jedes System einen Plan of Action and Milestones (POA&M) im FedRAMP-Stil, erstellt monatliche
Continuous-Monitoring-Deliverables (ConMon) in den offiziellen Excel- und OSCAL-Formaten, bewertet CMMC-
Level-2-Selbstbewertungen und zeigt, welche NIST-800-53-Kontrollen Ihre Scanner tatsächlich abdecken.

Alles, was in diesem Abschnitt beschrieben wird, befindet sich auf dem Tab **Compliance** eines Assets.

## Die Funktion aktivieren

Bundes-Compliance wird über das Feature-Flag **Compliance** ausgeliefert, das sich in der Beta-Phase befindet und
standardmäßig deaktiviert ist. Ein Administrator aktiviert es über das Feature-Flags-Menü — siehe
[Feature-Flags](/admin/feature_flags/pro__feature_flags/). Sobald es aktiviert ist, erscheint bei jedem
Asset ein Compliance-Tab.

## Beta: Ergebnisse prüfen, bevor Sie sich darauf verlassen

**Diese Funktion befindet sich in der Beta-Phase.** Die mitgelieferten NIST-800-171- und 800-53-Kontrollaussagen, die
DoD-SPRS-Punktgewichte und die POA&M-Eignungsregeln sollen Ihnen helfen, Ihre Sicherheitslage zu verfolgen und
einzuschätzen, und stehen noch aus, unabhängig gegen die maßgeblichen Quelldokumente validiert zu werden.

SPRS-Werte, Ergebnisse zur bedingten Eignung und Kontrollabdeckung sind **unverbindliche Hinweise**. Prüfen Sie sie
gegen die offizielle DoD-NIST-SP-800-171-Assessment-Methodik und die aktuelle FedRAMP-Richtlinie, bevor Sie
sich für eine Zertifizierung, eine Assessment-Einreichung oder einen sonstigen vertraglichen Zweck darauf
verlassen.

## In diesem Abschnitt

| Seite | Inhalt |
| --- | --- |
| [Compliance-Profil](compliance_profile) | Ein Asset als System erfassen und die Angaben festlegen, die auf jedem Deliverable erscheinen |
| [Das POA&M-Register](poam_ledger) | Wie POA&M-Einträge aus Befunden erstellt werden, und die Konventionen, denen das Register folgt |
| [ConMon-Snapshots](conmon_snapshots) | Monatliche Deliverables in FedRAMP-Excel und OSCAL sowie der optionale OSCAL-Validierungsdienst |
| [Behebungsfristen](remediation_slas) | Die SLA-Vorlagen für FedRAMP Rev 5 und FedRAMP VDR |
| [CMMC-Level-2-Assessments](cmmc_assessments) | Eine Selbstbewertung gegen NIST 800-171 Rev 2 bewerten |
| [Kontrollabdeckung](control_coverage) | Welche 800-53-Kontrollen Ihre Scanner testen, und offene Schwachstellen pro Kontrolle |
