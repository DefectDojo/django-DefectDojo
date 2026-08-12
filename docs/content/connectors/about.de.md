---
title: Über Connectors
description: Die zentrale Anlaufstelle für Upstream- und Downstream-Connectors in
  der Pro-UI
summary: ''
date: 2026-07-14 00:00:00+00:00
lastmod: 2026-07-14 00:00:00+00:00
draft: false
weight: 1
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Connectors sind eine Funktion, die nur in DefectDojo Pro verfügbar ist.</span>

**Connectors** ist die zentrale Anlaufstelle in der DefectDojo Pro-UI für jedes Tool, mit dem DefectDojo in beide Richtungen kommuniziert. Sie vereint zwei Funktionen, die zuvor an getrennten Stellen konfiguriert wurden:

* **Upstream Connectors** (früher **API Connectors**) ziehen Findings und Asset-Inventar *ein* aus Ihren Scannern und Sicherheitstools.
* **Downstream Connectors** (früher **Integrations**) senden Findings *heraus* an Ihre Issue-Tracker und Ticketing-Systeme.

Wenn Sie sich DefectDojo als Drehscheibe Ihrer Sicherheitsdaten vorstellen, sind Upstream Connectors der Weg, auf dem Daten eintreffen, und Downstream Connectors der Weg, auf dem die Behebungsarbeit hinausgeht.

## Wo Sie Connectors finden

Öffnen Sie in der Seitenleiste der Pro-UI die Gruppe **Connectors** unter der Überschrift **Import**:

* **Connectors > Upstream Connectors** — ersetzt den alten Eintrag **API Connectors** (zuvor unter Import).
* **Connectors > Downstream Connectors** — ersetzt den alten Eintrag **Integrations** (zuvor unter Settings). Diese Richtung befindet sich derzeit in der **Beta**-Phase.

Alte Lesezeichen und Deep Links funktionieren weiterhin: Die alten URLs für **API Connectors** und **Integrations** leiten automatisch auf die neuen Seiten **Upstream Connectors** und **Downstream Connectors** weiter.

## Wer was sehen kann

* **Upstream Connectors** ist für Benutzer mit einer Global Role von Reader oder höher sichtbar.
* **Downstream Connectors** ist nur für Superuser sichtbar und befindet sich für Cloud-gehostete DefectDojo Pro-Instanzen derzeit in der **Beta**-Phase.

Die Gruppe **Connectors** erscheint in der Seitenleiste, wenn mindestens eine der beiden Seiten für Sie sichtbar ist.

## Die Connectors-Seiten

Beide Richtungen verwenden dasselbe überarbeitete Layout:

* Jedes Tool wird als **Kachel** in voller Breite dargestellt — Logo links, der Tool-Name und eine kurze Beschreibung in der Mitte sowie eine Aktionsschaltfläche rechts.
* Jeder Abschnitt verfügt über ein **Suchfeld**, das Kacheln beim Eingeben nach Tool-Namen filtert.

Auf der Seite **Upstream Connectors**:

* **Configured Connectors** listet die Connectors auf, die Sie bereits eingerichtet haben. Jede Kachel zeigt eine Zusammenfassung des Betriebszustands (Health-Status, letzter Vorgang sowie Gesamt- / gemappte Datensatzanzahl) und ein Menü **Manage Configuration** mit den Aktionen **Manage Records & Operations**, **Edit Configuration** und **Delete Configuration**.
* **Available Connectors** listet die unterstützten Tools auf, die Sie noch nicht konfiguriert haben, jeweils mit einer Schaltfläche **Add Configuration**.
* Ein Filter in der Seitenkopfzeile grenzt beide Abschnitte nach Connector-Typ ein: **All**, **Asset** (oder **Product**, je nach Terminologie Ihrer Instanz) für Connectors, die Asset-Inventar importieren, und **Finding** für Connectors, die Schwachstellendaten importieren.

Auf der Seite **Downstream Connectors**:

* **Available Integrations** listet jeden unterstützten Issue-Tracker auf. Kacheln für bereits konfigurierte Integrations zeigen die Anzahl vorhandener Integration Instances.

## Nächste Schritte

* Lesen Sie [About Upstream Connectors](/connectors/upstream/about/) und [fügen Sie Ihren ersten Upstream Connector hinzu](/connectors/upstream/add_edit/), um automatisch mit dem Import von Findings zu beginnen.
* Lesen Sie den [Downstream Connectors guide](/connectors/downstream/about/), um Findings an Ihre Issue-Tracker zu senden.
