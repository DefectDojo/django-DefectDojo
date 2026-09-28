---
title: Quellcode-Locations
description: Code-Locations modellieren, wo sich ein Befund einer statischen Analyse
  im Quellcode befindet, und zeichnen dessen Bewegungsverlauf im Zuge der Codeentwicklung
  auf
weight: 6
audience: pro
---

**Source Code Locations** erweitern das Locations-Modell auf die statische Analyse: Neben URLs (DAST) und Dependencies (SCA) beschreibt eine **Code**-Location, wo ein SAST-Befund im Quellcode liegt — identifiziert anhand von **Dateipfad und Zeilennummer**.

> Quellcode-Locations erfordern das Feature Locations (Beta). Um Locations auf Ihrer Instanz zu aktivieren, wenden Sie sich an [support@defectdojo.com](mailto:support@defectdojo.com).

## Was sie modellieren

Jeder statische Befund, der einen Dateipfad meldet, erhält eine Code-Location. Der kanonische Wert der Location ist `path/to/file.py:42` (oder nur der Dateipfad, wenn das Tool keine Zeile meldet). Wie alle Locations sind Code-Locations gemeinsam genutzte Objekte: Zwei Befunde an derselben Datei und Zeile verweisen auf dieselbe Location, die pro Befund und pro Asset jeweils eigene Referenzstatus führt.

Code-Locations werden **scan-verwaltet**: Sie werden durch Imports und Reimports erstellt und aktualisiert, nicht manuell. Es gibt keine Aktion „Neue Source Code Location" — der Scanner ist die maßgebliche Quelle dafür, wo Code-Befunde liegen.

## Wo Sie sie finden

- **All Source Code** in der Seitenleiste listet jede Code-Location der Instanz auf, mit denselben Filter- und Tagging-Möglichkeiten wie bei URLs und Dependencies.
- **View Source Code** im Locations-Menü eines Assets grenzt die Liste auf ein einzelnes Asset ein.
- Die Seite eines Befunds zeigt seine aktuelle Code-Location und, wenn sich der Befund verschoben hat, seinen **Location-Verlauf**.

## Verschiebungsverlauf

Quellcode ändert sich ständig: Commits verschieben Zeilennummern, Refactorings benennen Dateien um. Wenn [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) für ein Tool aktiviert ist, behält ein Befund, der sich verschiebt, seine Identität, und seine Code-Location-Referenzen zeichnen den Verlauf auf:

- Die Referenz des Befunds auf die **alte** Location erhält den Status **Behoben** und wird mit Angaben dazu versehen, *wohin sich der Befund verschoben hat* und *warum die Zuordnung getroffen wurde* (nächstgelegene Zeile, Datenfluss, Dateiumbenennung ...).
- Eine Referenz auf die **neue** Location wird erstellt und bleibt aktiv.

Das Ergebnis ist eine durchsuchbare Ablösekette — „dieser Befund lag bei `auth.py:42`, dann bei `auth.py:57`, dann bei `session.py:31`" — dargestellt als Zeitleiste auf der Befundseite. Derselbe Verlaufsmechanismus deckt auch URL-Verschiebungen und Versionssprünge bei Dependencies ab, sodass sich alle drei Location-Typen eine gemeinsame Zeitleisten-Oberfläche teilen.

Der Verlauf wird ab dem Zeitpunkt erfasst, an dem Locations auf der Instanz aktiviert wird. Befunde, die sich davor verschoben haben, behalten ihre aktuelle Location; frühere Sprünge wurden angewendet, aber nicht aufgezeichnet. Für Instanzen mit jahrelanger Historie vor Einführung des Features kann der [Befehl zur Konsolidierung von Churn](/triage_findings/finding_deduplication/pro__location_drift_matching/#consolidating-historical-churn) Verläufe rekonstruieren und dabei historische Schließen-und-Neuanlegen-Ketten zusammenführen.

## Statuskorrektheit

Die Referenzstatus von Code-Locations werden bei **jedem** Abgleichsalgorithmus durch Reimport korrekt gehalten, unabhängig davon, ob Drift Matching aktiviert ist:

- Die aktuelle Code-Referenz eines abgeglichenen Befunds wird bei jedem Reimport synchronisiert, sodass ein verschobener Befund seine alte Referenz nicht dauerhaft aktiv hinterlässt.
- Dieselbe von der Einstellung unabhängige Synchronisierung gilt für Dependency-Referenzen: Wenn sich die Paketversion eines SCA-Befunds ändert, wird die Referenz der alten Version auf Behoben gesetzt, anstatt neben der neuen weiterhin aktiv zu bleiben.

## Zusammenhang mit Befundfeldern

Die eigenen Felder `file_path` / `line` des Befunds bleiben die maßgeblichen Skalarwerte (sie sind es, was Filter, Hashes und die API offenlegen); die Code-Location ist die gemeinsam genutzte, referenzgezählte Sicht auf dieselbe Koordinate. Der Reimport aktualisiert die Skalarwerte anhand des neuesten Scans, und die Location-Logik leitet die Locations daraus ab — die beiden können nicht auseinanderdriften.
