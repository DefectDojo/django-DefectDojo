---
title: Audit-Protokollierung
description: Jede Erstellungs-, Aktualisierungs- und Löschaktion, die DefectDojo in
  seinem Audit-Protokoll erfasst, sowie was aufgezeichnet wird und wie Sie die Aufbewahrung
  konfigurieren.
draft: false
weight: 4
---

DefectDojo zeichnet einen Audit-Trail der Änderungen an seinen Daten auf. Jedes verfolgte Objekt zeichnet automatisch Ereignisse für **Erstellen**, **Aktualisieren** und **Löschen** auf, und Beziehungstabellen (many-to-many) zeichnen Ereignisse für **Hinzufügen** und **Entfernen** auf.

## Funktionsweise

Die Audit-Verfolgung wird durch Datenbank-Trigger gesteuert, die pro Modell registriert sind. Für jedes
verfolgte Objekt können drei Ereignistypen ausgelöst werden:

| Ereignistyp    | Wann es ausgelöst wird                                                                 | Aktion     |
| ------------- | ----------------------------------------------------------------------------- | ---------- |
| `InsertEvent` | Ein neuer Datensatz wird erstellt                                                        | **Erstellen** |
| `UpdateEvent` | Ein Datensatz ändert sich — nur wenn sich ein tatsächlicher Feldwert wirklich ändert               | **Aktualisieren** |
| `DeleteEvent` | Ein Datensatz wird gelöscht                                                            | **Löschen** |

Many-to-many-Beziehungstabellen (Tags, Reviewer, Firewall-IP-Bereiche) verfolgen
nur **Hinzufügen** (`InsertEvent`) und **Entfernen** (`DeleteEvent`) — für eine Beziehungszeile gibt es kein
„Update“.

### Was bei jedem Ereignis erfasst wird

- **Wer** — der handelnde Benutzer, entnommen aus dem Request-Kontext.
- **Wann** — ein Zeitstempel.
- **Quell-IP** — die Remote-Adresse, unter Berücksichtigung von `X-Forwarded-For`-Proxy-Ketten.
- **Vorher-/Nachher-Snapshot** — die vollständigen Feldwerte des Datensatzes.
- **Context / Label** — gruppiert Ereignisse, die aus derselben Anfrage stammen. Das
  Label `initial_backfill` kennzeichnet historische Datensätze, die importiert wurden, als die Verfolgung
  erstmals aktiviert wurde.

Ereignisse, die von Hintergrundjobs erzeugt werden, werden dem Kontext
der ursprünglichen Anfrage wieder zugeordnet, sodass eine asynchron abgeschlossene Aktion weiterhin
dem Benutzer zugeschrieben wird, der sie ausgelöst hat.

## Core (Open Source) — verfolgte Aktionen

| Objekt                         | Erstellen | Aktualisieren | Löschen | Notizen                                          |
| ------------------------------ | :----: | :----: | :----: | ---------------------------------------------- |
| Benutzer                       |   ✅   |   ✅   |   ✅   | `password` von Snapshots ausgeschlossen             |
| Produkttyp                   |   ✅   |   ✅   |   ✅   |                                                |
| Produkt                        |   ✅   |   ✅   |   ✅   |                                                |
| Engagement                     |   ✅   |   ✅   |   ✅   |                                                |
| Test                           |   ✅   |   ✅   |   ✅   |                                                |
| Befund                        |   ✅   |   ✅   |   ✅   |                                                |
| Befundgruppe                  |   ✅   |   ✅   |   ✅   |                                                |
| Befundvorlage               |   ✅   |   ✅   |   ✅   |                                                |
| Risikoakzeptanz                |   ✅   |   ✅   |   ✅   |                                                |
| Endpunkt                       |   ✅   |   ✅   |   ✅   |                                                |
| Location                       |   ✅   |   ✅   |   ✅   |                                                |
| URL                            |   ✅   |   ✅   |   ✅   |                                                |
| Benachrichtigungs-Webhook           |   ✅   |   ✅   |   ✅   | `header_name` / `header_value` ausgeschlossen (Geheimnisse) |

### Core — Beziehungsereignisse (Add / Remove)

| Beziehung                       | Hinzufügen | Entfernen |
| ---------------------------------- | :-: | :----: |
| Befund → Reviewer                | ✅  |   ✅   |
| Befund → Tags                     | ✅  |   ✅   |
| Befund → Geerbte Tags           | ✅  |   ✅   |
| Produkt → Tags                     | ✅  |   ✅   |
| Engagement → Tags                  | ✅  |   ✅   |
| Engagement → Geerbte Tags        | ✅  |   ✅   |
| Test → Tags                        | ✅  |   ✅   |
| Test → Geerbte Tags              | ✅  |   ✅   |
| Endpunkt → Tags                    | ✅  |   ✅   |
| Endpunkt → Geerbte Tags          | ✅  |   ✅   |
| Befundvorlage → Tags            | ✅  |   ✅   |
| App-Analyse (Technologie) → Tags   | ✅  |   ✅   |
| Objekte/Produkt → Tags             | ✅  |   ✅   |

## Pro — verfolgte Aktionen

| Objekt                            | Erstellen | Aktualisieren | Löschen | Notizen                          |
| --------------------------------- | :----: | :----: | :----: | ------------------------------ |
| Erweiterter Befund                  |   ✅   |   ✅   |   ✅   | Pro-Pendant zum Befund       |
| Regel                              |   ✅   |   ✅   |   ✅   | Regel-Engine                   |
| Regelaktion                       |   ✅   |   ✅   |   ✅   |                                |
| Regelaktionsbedingung             |   ✅   |   ✅   |   ✅   |                                |
| Regelfiltereintrag                 |   ✅   |   ✅   |   ✅   |                                |
| Regel-Engine-Vorgang            |   ✅   |   ✅   |   ✅   |                                |
| Regel-Engine-Vorgangsmeldung    |   ✅   |   ✅   |   ✅   |                                |
| Geplanter Task                    |   ✅   |   ✅   |   ✅   |                                |
| Lauf eines geplanten Tasks                |   ✅   |   ✅   |   ✅   |                                |
| Mitigationsrichtlinie                 |   ✅   |   ✅   |   ✅   |                                |
| Anpassbare Einstellung                   |   ✅   |   ✅   |   ✅   | Systemkonfigurationsänderungen   |
| Feature-Flag-Status                |   ✅   |   ✅   |   ✅   | Flag-Umschaltungen + System-Pins |
| Feature-Flag-Definition           |   ✅   |   ✅   |   ✅   | Metadaten / Registry-Synchronisierung |
| Cloud-Firewall                    |   ✅   |   ✅   |   ✅   | Feld `locked` ausgeschlossen        |
| Firewall-IP-Maske                  |   ✅   |   ✅   |   ✅   |                                |

### Pro — RBAC / Berechtigungen

| Objekt                        | Erstellen | Aktualisieren | Löschen |
| ----------------------------- | :----: | :----: | :----: |
| Gruppe                         |   ✅   |   ✅   |   ✅   |
| Rolle                          |   ✅   |   ✅   |   ✅   |
| Gruppenmitgliedschaft              |   ✅   |   ✅   |   ✅   |
| Globale Rolle                   |   ✅   |   ✅   |   ✅   |
| Produkt-Gruppen-Zuweisung      |   ✅   |   ✅   |   ✅   |
| Produkttyp-Gruppen-Zuweisung |   ✅   |   ✅   |   ✅   |
| Produktmitglied                |   ✅   |   ✅   |   ✅   |
| Produkttyp-Mitglied           |   ✅   |   ✅   |   ✅   |

### Pro — Beziehungsereignisse (Add / Remove)

| Beziehung                | Hinzufügen | Entfernen |
| --------------------------- | :-: | :----: |
| Cloud-Firewall → IP-Bereiche  | ✅  |   ✅   |

## Konfiguration und Aufbewahrung (On-Premise Controls)

| Einstellung              | Umgebungsvariable                  | Standardwert            | Auswirkung                                                              |
| -------------------- | ------------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Audit-Protokollierung aktivieren | `DD_ENABLE_AUDITLOG`                  | `True`             | Bei `False` werden alle History-Trigger deaktiviert und es werden keine Ereignisse aufgezeichnet |
| Aufbewahrungszeitraum     | `DD_AUDITLOG_FLUSH_RETENTION_PERIOD`  | `-1` (nie leeren) | Anzahl der Monate an Historie, die aufbewahrt werden; ältere Ereignisse werden vom Flush-Job stapelweise gelöscht  |
| Flush-Batchgröße     | `DD_AUDITLOG_FLUSH_BATCH_SIZE`        | `1000`             | Pro Batch gelöschte Zeilen während der Bereinigung                              |
| Maximale Flush-Batches    | `DD_AUDITLOG_FLUSH_MAX_BATCHES`       | `100`              | Obergrenze für die Anzahl der Batches pro Flush-Lauf                        |

## Hinweise und Einschränkungen

- **Geheimnisse werden niemals erfasst.** Benutzerpasswörter und die Header-Werte von Benachrichtigungs-Webhooks
  sind ausdrücklich von Ereignis-Snapshots ausgeschlossen.
- **Updates werden nur bei einer echten Änderung aufgezeichnet.** Ein Speichervorgang, der keinen
  Feldwert ändert, erzeugt kein Update-Ereignis; automatisch verwaltete Felder wie
  `last_updated` allein lösen keines aus.
- **Authentifizierungsereignisse werden hier nicht erfasst.** Nur
  Datenänderungen. Login-, Logout- und fehlgeschlagene Login-Versuche werden separat behandelt und sind nicht Teil dieses Audit-Protokolls.
