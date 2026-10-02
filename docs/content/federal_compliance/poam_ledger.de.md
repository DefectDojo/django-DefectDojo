---
title: Das POA&M-Register
description: Wie POA&M-Einträge aus Befunden erstellt werden, und die Konventionen,
  denen das Register folgt
weight: 2
audience: pro
---

POA&M-Einträge werden automatisch aus Befunden erstellt und aktualisiert. Die Synchronisierung läuft kurz
nach Importen und Befundänderungen, und ein nächtlicher Durchlauf erfasst alles, was durchgerutscht ist.
Sie können Einträge auch manuell hinzufügen, für Schwachstellen, die kein Scanner meldet.

![Das POA&M-Register](images/02-poam-items.png)

## Konventionen des Registers

Das Register folgt den FedRAMP-Konventionen:

* **Stabile Nummerierung.** Jeder Eintrag behält innerhalb seines Systems eine fortlaufende Nummer, und
  Nummern werden nie wiederverwendet.
* **Gruppierte Befunde werden zusammengefasst.** Dieselbe CVE über viele Hosts hinweg wird zu einem
  Eintrag, wobei jedes betroffene Asset darauf aufgeführt ist.
* **Konfigurationsbefunde können unter CM-6 konsolidiert werden**, statt das Register mit einem Eintrag
  pro Benchmark-Regel zu überfluten. Im obigen Screenshot ist `V-4` dieser konsolidierte Eintrag.
* **Geschlossene Einträge werden nie wieder geöffnet.** Kehrt dieselbe Schwachstelle zurück, öffnet das
  Register einen neuen Eintrag, der auf den alten verweist, sodass Ihre Behebungshistorie erhalten bleibt.

## Einen Eintrag bearbeiten

Der Stift in einer beliebigen Zeile öffnet den Eintrag zur Bearbeitung.

![Bearbeiten eines POA&M-Eintrags](images/03-poam-item-detail.png)

Von hier aus legen Sie den Ansprechpartner, die benötigten Ressourcen und den Behebungsplan fest und
erfassen etwaige Deviations.

### Deviations

Deviations werden bei jedem Eintrag als drei getrennte Zustände erfasst:

| Deviation | Werte |
| --- | --- |
| Falsch-positiv | Nein, Ausstehend oder Ja |
| Risk Adjustment | Nein, Ausstehend oder Ja |
| Operational Requirement | Nein, Ausstehend oder Ja |

Jede trägt eine gemeinsame **Deviation Rationale**. Eine Risikoanpassung erfasst zusätzlich die
**Adjusted Risk Rating** neben der ursprünglichen, und beide erscheinen auf den erzeugten Deliverables.

### Anbieterabhängigkeiten

Einträge können ein Flag **Vendor Dependency** und den Namen **Vendor Product** tragen, für
Schwachstellen, die Sie nicht direkt beheben können. Das Datum Ihres letzten Anbieter-Check-ins wird beim
Eintrag erfasst.

## KEV-Tracking

Einträge, die mit einer CISA Known Exploited Vulnerability verknüpft sind, tragen das
KEV-Fälligkeitsdatum. Dieses Datum begrenzt zusätzlich die Behebungsfrist — siehe
[Behebungsfristen](../remediation_slas).

## Meilensteine

Meilensteine enthalten eine Beschreibung mit geplantem und abgeschlossenem Datum und erscheinen sowohl
in der Excel- als auch in der OSCAL-Ausgabe. Sie werden über die Compliance-API verwaltet und nicht über
das Formular für Einträge.

## Einen Eintrag manuell hinzufügen

Fügen Sie einen Eintrag für eine Schwachstelle hinzu, die kein Scanner meldet. Manuell erstellte Einträge
verhalten sich wie synchronisierte: Sie erhalten die nächste fortlaufende Nummer, akzeptieren Deviations
und Meilensteine und erscheinen im nächsten Snapshot.

## Nachvollziehbarkeit

POA&M-Einträge, Meilensteine und Deviations unterliegen allesamt der Audit-Historie. Jede Änderung
protokolliert, wer was wann getan hat.
