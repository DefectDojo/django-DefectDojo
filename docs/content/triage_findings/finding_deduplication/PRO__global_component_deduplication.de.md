---
title: Global Component Deduplication
description: Deduplizieren Sie Befunde aus der Softwarezusammensetzungsanalyse anhand
  von Komponentenname und -version über alle Produkte hinweg
weight: 5
audience: pro
---

Global Component Deduplication ist ein DefectDojo-Pro-Algorithmus, der doppelte Befunde über **alle Produkte** hinweg anhand des Komponentennamens und der Version identifiziert, auf die sie sich beziehen. Er ist für Software-Composition-Analysis-Tools (SCA) gedacht, bei denen dieselbe verwundbare Abhängigkeit (zum Beispiel `timespan@2.3.0`) in vielen Produkten auftreten kann und Sie möchten, dass DefectDojo diese Vorkommen als Duplikate eines einzigen ursprünglichen Befunds behandelt.

Anders als bei den übrigen Deduplizierungsalgorithmen ist der Global-Component-Abgleich **nicht auf ein einzelnes Produkt oder Engagement beschränkt**. Ein in Produkt B importierter Befund kann als Duplikat eines älteren Befunds in Produkt A markiert werden, selbst wenn die beiden Produkte in keinem Zusammenhang stehen.

> **Global Component vs. Global Locations:** Global Component gleicht nur anhand von Komponentenname und -version ab. Wenn Ihre Instanz das Locations-Datenmodell verwendet, ist [Global Locations Deduplication](/triage_findings/finding_deduplication/pro__global_locations_deduplication/) der präzisere Nachfolger — er schlüsselt Abhängigkeiten anhand der vollständigen Package-URL und dedupliziert zusätzlich URL-/DAST-Befunde über Produkte hinweg. In welchem Fall Sie welchen wählen sollten, zeigt die Vergleichstabelle auf jener Seite.

## Aktivieren des Global-Component-Algorithmus

Global Component Deduplication ist hinter einem Feature-Flag verborgen und standardmäßig **deaktiviert**. Ein Superuser kann sie sowohl auf Cloud- als auch auf On-Premise-Instanzen über **Settings > Feature Flags** aktivieren. Siehe [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Sobald die Funktion aktiviert ist, steht **Global Component** als Option im Dropdown-Menü **Deduplication Algorithm** sowohl für die Same-Tool- als auch für die Cross-Tool-Deduplizierungseinstellungen im Tuner zur Verfügung.

## Konfigurieren von Global Component Deduplication

Global Component kann auf Same-Tool-Deduplizierung, Cross-Tool-Deduplizierung oder beides angewendet werden und wird pro Sicherheitstool über **Settings > Finding Workflow** konfiguriert (**Settings > Pro Settings > Deduplication Settings** bei Instanzen, die noch das vorherige Menülayout verwenden; siehe [The Settings Menu](/navigation/pro__settings_menu/)).

### Same-Tool

Verwenden Sie Same-Tool Deduplication mit dem Global-Component-Algorithmus, wenn Sie Befunde eines einzelnen SCA-Tools über mehrere Produkte hinweg deduplizieren möchten.

1. Öffnen Sie den Tab **Same Tool Deduplication**.
2. Wählen Sie das SCA-Tool aus dem Dropdown-Menü **Security Tool** aus (zum Beispiel `Dependency Track Finding Packaging Format (FPF) Export`).
3. Setzen Sie den **Deduplication Algorithm** auf **Global Component**.
4. Senden Sie das Formular ab.

Hash Code Fields werden von diesem Algorithmus nicht verwendet und werden bei Auswahl ausgeblendet.

### Cross-Tool

Verwenden Sie Cross-Tool Deduplication mit dem Global-Component-Algorithmus, wenn Sie Befunde derselben Komponente über verschiedene SCA-Tools und Produkte hinweg deduplizieren möchten.

Der Cross-Tool-Abgleich erfordert, dass Global Component auf **jedem** teilnehmenden Tool konfiguriert ist.

1. Öffnen Sie den Tab **Cross Tool Deduplication**.
2. Für jedes einzubeziehende Tool: wählen Sie es aus dem Dropdown-Menü **Security Tool** aus, setzen Sie den Algorithmus auf **Global Component** und senden Sie das Formular ab.

## Wie der Abgleich funktioniert

Ein neuer Befund wird als Duplikat eines vorhandenen Befunds markiert, wenn:

- Komponentenname und Komponentenversion exakt übereinstimmen, **und**
- irgendwo in der DefectDojo-Instanz — in einem beliebigen Produkt oder Engagement — bereits ein älterer Befund mit demselben Komponentennamen und derselben Version existiert.

Der Abgleich der Komponentenversion erfolgt exakt. Ein Befund für `timespan@2.3.0` wird **nicht** mit einem für `timespan@2.3.1` dedupliziert.

Die auf das Engagement beschränkte Deduplizierungseinstellung wird für diesen Algorithmus ignoriert; der Abgleich erfolgt immer global.

## Beispiel

Angenommen, Global Component ist bei `Dependency Track Finding Packaging Format (FPF) Export` (Same Tool) und bei einem Generic-Findings-Import-Tool (Cross Tool) aktiviert:

| Schritt | Import | In Produkt | Ergebnis |
| --- | --- | --- | --- |
| 1 | Dependency-Track-Scan für `timespan@2.3.0` | Application 0 | 1 aktiver Befund erstellt |
| 2 | Derselbe Dependency-Track-Scan | Application 1 | 1 Befund erstellt, als Duplikat des Befunds von Application 0 markiert |
| 3 | Generic Findings Import für `timespan@2.3.0` | Application 2 | 1 Befund erstellt, als Duplikat des Befunds von Application 0 markiert (Cross-Tool-Übereinstimmung) |
| 4 | Dependency-Track-Scan für `timespan@2.3.1` | Application 3 | 1 aktiver Befund erstellt — andere Version, keine Übereinstimmung |

Jeder doppelte Befund zeigt seinen Originalbefund unten auf der Befundseite in der Duplikatkette an.

## Sichtbarkeit über Produkte hinweg

Da der Global-Component-Abgleich Produktgrenzen überschreitet, kann der ursprüngliche Befund in einer Duplikatkette in einem Produkt liegen, auf das der Benutzer, der das Duplikat betrachtet, keinen Zugriff hat.

In diesem Fall wird der Befund sichtbar und als Duplikat gekennzeichnet angezeigt, der Benutzer kann jedoch nicht zum Original wechseln oder es öffnen. Berücksichtigen Sie dies, bevor Sie Global Component für Tools aktivieren, deren Befunde gegenüber produktbezogenen Zugriffskontrollen sensibel sind.

## Zurücksetzen

Um die Verwendung von Global Component für ein bestimmtes Tool zu beenden, öffnen Sie dessen Deduplizierungseinstellungen und stellen Sie den Algorithmus wieder auf eine der eingeschränkten Optionen um.

Für **Same Tool** Deduplication:

- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Für **Cross Tool** Deduplication:

- Hash Code
- Disabled

Das Ändern des Algorithmus löst eine Neuberechnung der Deduplizierungs-Hashes für die vorhandenen Befunde des Tools im Hintergrund aus.
