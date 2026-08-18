---
title: ConMon-Snapshots
description: Monatliche Deliverables in FedRAMP-Excel und OSCAL sowie der optionale
  OSCAL-Validierungsdienst
weight: 3
audience: pro
---

Auf dem Tab **Snapshots** erzeugt **Generate Snapshot** die Deliverables für einen Berichtszeitraum.
Ein Snapshot **friert das Register** zu diesem Zeitpunkt ein: spätere Änderungen wirken sich nie auf ein
bereits erzeugtes Deliverable aus.

![Erzeugte ConMon-Snapshots](images/04-poam-snapshots.png)

Jede Zeile zeigt den Zeitraum, seinen Status, die Anzahl offener und überfälliger Einträge, den
Abschlusszeitpunkt sowie Download-Links für beide Artefakte.

## Was ein Snapshot erzeugt

Jeder Snapshot erzeugt zwei Artefakte:

* Die offizielle **FedRAMP-POA&M-Excel-Arbeitsmappe** (Vorlagenversion 3.0) mit offenen, geschlossenen und
  Konfigurationseinträgen auf den jeweils passenden Arbeitsblättern.
* Ein **OSCAL-Plan-of-Action-and-Milestones**-Dokument, festgelegt auf OSCAL 1.0.4 — die Version, die
  FedRAMPs aktuelle Validierungsregeln akzeptieren.

### Was die OSCAL-Ausgabe enthält

Das OSCAL-Dokument verwendet FedRAMPs Erweiterungs-Namespace für die Felder, nach denen FedRAMP-Tools
suchen: POA&M-IDs, betroffene Kontroll-IDs, Deviation-Status, Anbieterabhängigkeit und KEV-Tracking.

Jedes Risiko enthält:

* Facetten zu Wahrscheinlichkeit und Auswirkung — initial und angepasst, wenn eine Risikoanpassung
  genehmigt wurde.
* Die empfohlene Korrektur und die geplante Behebung als getrennte Antworten.
* Ein Risikoprotokoll, das die Erkennung und die letzte Statusüberprüfung festhält.

Dokumente werden zum Zeitpunkt der Erzeugung gegen das offizielle NIST-Schema geprüft.

## Monat-zu-Monat-Kennzahlen

Snapshots berechnen außerdem die Kennzahlen, die ein ConMon-Paket benötigt: was neu aufgetreten ist, was
behoben wurde, was überfällig ist, und die Anzahl offener Einträge nach Risikoeinstufung.

## OSCAL-Validierungsdienst

Für eine strengere Prüfung kann ein Deployment den mitgelieferten **OSCAL-Validator-Dienst** ausführen —
einen kleinen Container, der das von FedRAMP gepflegte `oscal-cli` einbettet.

| Validator-Dienst | Was bei der Erzeugung passiert |
| --- | --- |
| Nicht konfiguriert | Dokumente werden gegen das NIST-JSON-Schema validiert. Die tiefergehende Prüfung wird als **skipped** markiert. |
| Konfiguriert | Dokumente werden zusätzlich über `oscal-cli` validiert, und die Ergebnisse werden zusammen mit dem Snapshot gespeichert. |

Um ihn zu aktivieren, setzen Sie `DD_OSCAL_VALIDATOR_URL`, oder aktivieren Sie `oscalValidator` im Helm-Chart.

**Halten Sie die `import-ssp`-URL erreichbar.** `oscal-cli` löst den `import-ssp`-Href während der
Validierung auf. Wenn Ihr Compliance-Profil eine OSCAL-SSP-URL angibt, die der Validator-Container nicht
erreichen kann, bricht die Validierung ab, statt diesen Schritt zu überspringen. Sorgen Sie entweder
dafür, dass die URL vom Validator erreichbar ist, oder lassen Sie sie ungesetzt.

## Unveränderlichkeit

Snapshots und ihre Artefakte sind per Design unveränderlich. Das erneute Erzeugen eines Zeitraums erstellt
einen neuen Snapshot; ein bestehender wird nie überschrieben.
