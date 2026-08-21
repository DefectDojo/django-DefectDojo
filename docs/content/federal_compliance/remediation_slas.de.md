---
title: Behebungsfristen
description: Die SLA-Vorlagen für FedRAMP Rev 5 und FedRAMP VDR
weight: 4
audience: pro
---

Mit der Funktion werden zwei fertige SLA-Konfigurationen ausgeliefert. Weisen Sie eine davon Ihren Produkten
über die SLA-Konfigurationseinstellungen zu, oder kopieren Sie eine und passen Sie sie an.

## FedRAMP Rev 5

| Schweregrad | Fällig innerhalb |
| --- | --- |
| Kritisch | 30 Tage ab Entdeckung |
| Hoch | 30 Tage ab Entdeckung |
| Mittel | 90 Tage |
| Niedrig | 180 Tage |

Fristen werden durchgesetzt, und ein Befund, der im CISA-KEV-Katalog aufgeführt ist, wird nie über sein
CISA-Fälligkeitsdatum hinaus terminiert.

## FedRAMP VDR

Dieselben Basisfristen, weiter verschärft durch Ausnutzbarkeit und Exposition:

| Bedingung | Fällig innerhalb |
| --- | --- |
| Glaubhaft ausnutzbar **und** über das Internet erreichbar | 4 Tage |
| Nur glaubhaft ausnutzbar | 14 Tage |
| Nur über das Internet erreichbar | 30 Tage |
| Keines von beidem | Die oben genannten FedRAMP-Rev-5-Fristen |

**Glaubhaft ausnutzbar** bedeutet, dass der Befund im KEV gelistet ist oder sein EPSS-Score Ihren
Schwellenwert erreicht oder überschreitet. **Über das Internet erreichbar** wird durch einen Befund-Tag
signalisiert — standardmäßig `internet-reachable`.

Alle Schwellenwerte, Tag-Namen und Tagesangaben sind in der SLA-Konfiguration bearbeitbar.

**FedRAMP VDR wird am 7. Dezember 2026 verpflichtend.** Der Vulnerability-Detection-and-Response-Standard
von FedRAMP wird an diesem Datum für Cloud-Service-Provider verpflichtend. Es wird empfohlen, die
VDR-Vorlage bereits vorher zu übernehmen.

## Beziehung zum Ledger

SLA-Fristen bestimmen die geplanten Fertigstellungstermine von POA&M-Einträgen und legen fest, welche
Einträge in den monatlichen Kennzahlen eines Snapshots als überfällig zählen. Sie bestimmen außerdem, was
eine **Past-Due-Only**-Scan-Item-Policy einschließt — siehe [Compliance-Profil](../compliance_profile).

Wie Priorität und SLAs außerhalb eines Bundesbehörden-Kontexts funktionieren, erfahren Sie unter
[Priorität, Risiko und SLAs zuweisen](/asset_modelling/pro_hierarchy/priority_sla/).
