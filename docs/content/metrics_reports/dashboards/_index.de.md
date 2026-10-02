---
title: Dashboards
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 1
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

Das Dashboard ist die Startseite von DefectDojo — eine Zusammenfassung der Leistung Ihres Teams und ein Ausgangspunkt für die Überwachung der für Sie wichtigen Bereiche.

## Open Source vs. DefectDojo Pro

Wie das Dashboard funktioniert, hängt davon ab, welche Edition Sie einsetzen:

| | Open Source | DefectDojo Pro |
|---|---|---|
| **Start-Dashboard** | Ein festes Haupt-Dashboard für alle | Pro Benutzer **anpassbare** Dashboards |
| **Auswahl der Inhalte** | Superuser schalten einen festen Satz an Diagrammen ein/aus | Jeder Benutzer fügt **Widgets** hinzu, konfiguriert und ordnet sie an |
| **Mehrere benannte Dashboards** | Nein | Ja — beliebig viele **Layouts** erstellen und zwischen ihnen wechseln |
| **Teilen / duplizieren / als Standard festlegen** | — | Ja — Layouts für Ihr Team veröffentlichen, Vorlagen duplizieren, Ihren Standard festlegen |
| **REST-API + LLM-Automatisierung** | — | Ja — den Katalog erkunden, Layouts erstellen, Widget-Daten rendern |

Kurz gesagt: **Open Source** bietet jedem Benutzer dasselbe integrierte Haupt-Dashboard mit einem festen Satz an Komponenten. **DefectDojo Pro** ermöglicht es jedem Benutzer, eigene Dashboards aus Widgets zu erstellen, sie zu teilen und das gesamte System über die Benutzeroberfläche, die REST-API oder ein LLM zu steuern.

## Wie es weitergeht

**Open Source**

- **[DefectDojo-Hauptdashboard](introduction_dashboard/)** — die integrierte Startseite: Übersichtskarten, Schweregrad-Diagramme und wie ein Superuser sie konfiguriert.

**DefectDojo Pro**

- **[Anpassbare Dashboards](custom-dashboards/)** — Konzepte (Layouts, Widgets, der Katalog, Teilen) und eine vollständige Anleitung zur Benutzeroberfläche.
- **[Dashboards mit der API automatisieren](custom-dashboards-api/)** — den Widget-Katalog erkunden, Layouts erstellen und aktualisieren und Widget-Daten über die REST-API rendern, mit einem vollständigen Skript.
- **[Dashboards mit einem LLM erstellen](custom-dashboards-llm/)** — lassen Sie ein LLM Dashboards für Sie entwerfen und erstellen.
