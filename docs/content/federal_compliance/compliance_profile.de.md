---
title: Compliance-Profil
description: Ein Asset als System erfassen und die Angaben festlegen, die auf jedem
  Deliverable erscheinen
weight: 1
audience: pro
---

Das Compliance-Profil erfasst ein Asset als System und enthält die Angaben, die auf jedem daraus erzeugten
Deliverable erscheinen. Öffnen Sie das Asset, das Ihre Systemgrenze darstellt, gehen Sie zum Tab
**Compliance** und dann zu **Profile**.

![Das Formular für das Compliance-Profil](images/01-compliance-profile.png)

## Profilfelder

| Feld | Funktion |
| --- | --- |
| **Enabled** | Aktiviert die Compliance-Verfolgung für dieses Produkt. |
| **Automatic Sync** | Hält POA&M-Einträge mit den Befunden synchron. |
| **POA&M ID Prefix** | Nummerierung der Einträge. Erforderlich. Einträge werden standardmäßig als `V-1`, `V-2` usw. nummeriert. |
| **Impact Level** | LI-SaaS, Low, Moderate oder High. |
| **Cloud Service Provider** | Der CSP-Name, wie er auf den Deckblattdaten des POA&M erscheinen soll. |
| **System / Offering Name** | Der Systemname, wie er auf den Deckblattdaten des POA&M erscheinen soll. |
| **FedRAMP System Identifier** | Die Kennung Ihres Systems, zum Beispiel `F00000042`. |
| **Default Point of Contact** | Der Ansprechpartner, der auf Einträge ohne eigenen Ansprechpartner angewendet wird. |
| **Scan Item Policy** | Entweder alle offenen Einträge einbeziehen oder nur überfällige Scan-Einträge. |
| **OSCAL SSP Reference** | Optional. Wenn gesetzt, verweisen generierte OSCAL-POA&Ms darauf über `import-ssp`. |

### Eine Scan-Item-Policy wählen

Nur überfällige Einträge ist das FedRAMP-ConMon-Minimum. **Include all open items** ist die konservativere
Wahl und die Standardeinstellung.

## Speichern und Synchronisieren

**Save Compliance Profile** erfasst das Asset. Das POA&M-Register füllt sich anschließend aus den
vorhandenen Befunden des Assets, und der Rest des Compliance-Tabs wird verfügbar.

Bei aktivem **Automatic Sync** hält sich das Register selbst aktuell — siehe
[Das POA&M-Register](../poam_ledger). **Sync POA&M Now** führt sofort eine Synchronisierung durch, was
direkt nach einer Profiländerung oder dem Import eines neuen Scans nützlich ist.

## Nur über die API verfügbare Einstellungen

Zwei Profileinstellungen befinden sich nicht im Formular und werden über die Compliance-API gesetzt:

* **Default scan controls** — die Kontrollen, die Scanner-Befunden ohne eigene Kontroll-Zuordnung
  zugeschrieben werden. `RA-5` ist die gängige Wahl für Ergebnisse von Schwachstellenscans. Befunde, die
  *doch* eigene Kontrollverweise mitbringen, werden stattdessen anhand dieser zugeordnet; siehe
  [Kontrollabdeckung](../control_coverage).
* **Configuration test types** — die Testtypen, deren Befunde als Konfigurationselemente behandelt werden,
  was die CM-6-Konsolidierung im Register steuert.

## Nachvollziehbarkeit

Compliance-Profile unterliegen der Audit-Historie: Jede Änderung protokolliert, wer was wann geändert hat.
