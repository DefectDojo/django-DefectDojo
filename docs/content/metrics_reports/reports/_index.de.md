---
title: Report Builder
description: Leistungskennzahlen und Einblicke
summary: ''
date: 2026-01-20 17:33:00+00:00
lastmod: 2026-01-20 17:33:00+00:00
draft: false
weight: 2
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

Mit dem Report Builder können Sie DefectDojo-Daten in ansprechende, teilbare Berichte verwandeln — Executive Summaries, Compliance-Snapshots, POA&M-Pakete, technische Detailberichte und mehr — für Zielgruppen innerhalb und außerhalb Ihres Sicherheitsteams.

## Open Source vs. DefectDojo Pro

Wie Sie Berichte erstellen, hängt davon ab, welche Edition Sie einsetzen:

| | Open Source | DefectDojo Pro |
|---|---|---|
| **Bericht erstellen** | Ja — aus Widgets zusammenstellen | Ja — aus wiederverwendbaren Blocks zusammensetzen |
| **Ausführen und Ausgabe abrufen** | Ja (HTML, Drucken als PDF) | Ja (gespeichertes PDF oder HTML) |
| **Wiederverwendbare Themes / Blocks / Templates speichern** | Nein — jedes Mal neu erstellen | Ja |
| **Persistenter Verlauf generierter Berichte** | Nein | Ja — auflisten, herunterladen, erneut ausführen |
| **REST-API + LLM-Automatisierung** | — | Ja — vollständig erstellen → ausführen → herunterladen |

Kurz gesagt: **Open Source** ermöglicht es Ihnen, einen Bericht zu erstellen, auszuführen und das Ergebnis zu exportieren, speichert aber keine Templates und führt keinen Berichtsverlauf. **DefectDojo Pro** macht aus dem Reporting wiederverwendbare, brandingfähige Bausteine, die Sie über die Benutzeroberfläche, die REST-API oder ein LLM steuern können.

## Wie es weitergeht

**DefectDojo Pro**

- **[Report Builder](report-builder/)** — Konzepte (Themes, Blocks, Templates, Generated Reports) und eine vollständige Anleitung durch die Benutzeroberfläche.
- **[Automatisierung von Berichten mit der API](report-builder-api/)** — Berichte über die REST-API erstellen, ausführen, abfragen und herunterladen, mit einem vollständigen Skript.
- **[Berichte mit einem LLM erstellen](report-builder-llm/)** — lassen Sie ein LLM Berichte für Sie entwerfen, erstellen, ausführen und herunterladen.

**Open Source**

- **[Verwendung des Report Builders](using-the-report-builder/)** — einen Bericht mit dem Widget-basierten Builder erstellen, ausführen und exportieren.
