---
title: Global Locations Deduplication
description: Deduplizieren Sie Befunde anhand eines gemeinsamen Standorts (URL oder
  Abhängigkeit) über alle Produkte hinweg
weight: 6
audience: pro
---

Global Locations Deduplication ist ein DefectDojo-Pro-Algorithmus, der doppelte Befunde über **alle Produkte** hinweg rein anhand eines **gemeinsamen Standorts** identifiziert: einer URL oder einer Abhängigkeit (identifiziert über ihre Package-URL). Zwei Befunde, die sich einen Standort eines ausgewählten Typs teilen, werden unabhängig von Titel, Schweregrad, CWE oder Schwachstellen-IDs als Duplikate behandelt — der Standort allein bildet die Identität.

Er ist das standortbewusste Gegenstück zu [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/), angewendet auf das DefectDojo-Locations-Datenmodell. Während Global Component nur anhand von Komponentenname und -version abgleicht, gleicht Global Locations dieselbe Abhängigkeit **anhand der vollständigen Package-URL** ab *sowie* anhand gemeinsamer **URLs** — sodass es DAST-/Web-Befunde über Produkte hinweg deduplizieren kann, was Global Component nicht kann.

Anders als bei den eingeschränkten Algorithmen ist der Global-Locations-Abgleich **nicht auf ein einzelnes Produkt oder Engagement beschränkt**. Ein in Produkt B importierter Befund kann als Duplikat eines älteren Befunds in Produkt A markiert werden, selbst wenn die beiden Produkte in keinem Zusammenhang stehen.

## Voraussetzungen

Global Locations ist über das DefectDojo-**Locations**-Datenmodell definiert und wird nur angeboten, wenn die Funktion **Locations** aktiviert ist. Auf Instanzen, auf denen Locations deaktiviert ist, wird das Global-Locations-Feature-Flag als gesperrt angezeigt („Requires Locations to be enabled“), und der Algorithmus erscheint nicht im Tuner.

## Aktivieren des Global-Locations-Algorithmus

Global Locations Deduplication ist hinter einem Feature-Flag verborgen und standardmäßig **deaktiviert**. Sobald Locations aktiviert ist, kann ein Superuser die Funktion sowohl auf Cloud- als auch auf On-Premise-Instanzen über **Settings > Feature Flags** aktivieren. Siehe [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Sobald die Funktion aktiviert ist, steht **Global Locations** als Option im Dropdown-Menü **Deduplication Algorithm** sowohl für die Same-Tool- als auch für die Cross-Tool-Deduplizierungseinstellungen im Tuner zur Verfügung.

## Konfigurieren von Global Locations Deduplication

Global Locations kann auf Same-Tool-Deduplizierung, Cross-Tool-Deduplizierung oder beides angewendet werden und wird pro Sicherheitstool über **Settings > Finding Workflow** konfiguriert (**Settings > Pro Settings > Deduplication Settings** bei Instanzen, die noch das vorherige Menülayout verwenden; siehe [The Settings Menu](/navigation/pro__settings_menu/)).

Wenn Sie **Global Locations** auswählen, wird die Auswahl der Hash Code Fields ausgeblendet (sie ist nicht anwendbar), und stattdessen erscheint eine Auswahl **Location Types**.

### Location Types

Wählen Sie aus, welche Standorttypen am Abgleich teilnehmen:

- **URLs** — zwei Befunde stimmen überein, wenn sie sich eine URL teilen (verglichen anhand der konfigurierten Endpunktfelder, `DEDUPE_ALGO_ENDPOINT_FIELDS`).
- **Dependencies** — zwei Befunde stimmen überein, wenn sie sich auf dieselbe Abhängigkeit beziehen, identifiziert anhand der vollständigen Package-URL.

Mindestens ein Typ muss ausgewählt sein; standardmäßig sind beide ausgewählt. Ein nur für **URLs** konfiguriertes Tool ignoriert gemeinsame Abhängigkeiten, und ein nur für **Dependencies** konfiguriertes Tool ignoriert gemeinsame URLs.

### Same-Tool

Verwenden Sie Same-Tool Deduplication mit dem Global-Locations-Algorithmus, wenn Sie Befunde eines einzelnen Tools über mehrere Produkte hinweg anhand eines gemeinsamen Standorts deduplizieren möchten.

1. Öffnen Sie den Tab **Same Tool Deduplication**.
2. Wählen Sie das Tool aus dem Dropdown-Menü **Security Tool** aus.
3. Setzen Sie den **Deduplication Algorithm** auf **Global Locations**.
4. Wählen Sie die **Location Types** aus, anhand derer abgeglichen werden soll.
5. Senden Sie das Formular ab.

### Cross-Tool

Verwenden Sie Cross-Tool Deduplication mit dem Global-Locations-Algorithmus, wenn Sie Befunde deduplizieren möchten, die sich einen Standort über **unterschiedliche** Tools und Produkte hinweg teilen.

Der Cross-Tool-Abgleich liest die Standorttypauswahl des importierenden Tools, konfigurieren Sie also Global Locations auf **jedem** teilnehmenden Tool mit übereinstimmenden Location Types.

1. Öffnen Sie den Tab **Cross Tool Deduplication**.
2. Für jedes einzubeziehende Tool: wählen Sie es aus dem Dropdown-Menü **Security Tool** aus, setzen Sie den Algorithmus auf **Global Locations**, wählen Sie die Location Types aus und senden Sie das Formular ab.

## Wie der Abgleich funktioniert

Ein neuer Befund wird als Duplikat eines an beliebiger Stelle in der Instanz vorhandenen Befunds markiert, wenn sich beide **mindestens einen konkreten Standort eines ausgewählten Typs** teilen:

- **Eine URL**, deren konfigurierte Endpunktfelder (`DEDUPE_ALGO_ENDPOINT_FIELDS`) alle übereinstimmen, **oder**
- **eine Abhängigkeit** mit derselben Package-URL (ein exakter Purl-Abgleich, sodass `pkg:npm/timespan@2.3.0` **nicht** mit `pkg:npm/timespan@2.3.1` übereinstimmt).

Der Abgleich ist **strikt und nicht trivial erfüllt**: Zwei Befunde ohne Standorte eines ausgewählten Typs werden **niemals** dedupliziert (anders als beim eingeschränkten Standortabgleich gilt „beide leer“ nicht als Übereinstimmung). Ist der Endpunktfeldvergleich deaktiviert (`DEDUPE_ALGO_ENDPOINT_FIELDS = []`), können URLs überhaupt keine Übereinstimmung herstellen — nur eine gemeinsame Abhängigkeit kann dies dann noch.

Der Same-Tool-Abgleich bleibt innerhalb eines einzelnen Tools (Testtyp). Der Cross-Tool-Abgleich überschreitet Tool-Grenzen absichtlich. Die auf das Engagement beschränkte Deduplizierungseinstellung wird für diesen Algorithmus ignoriert; der Abgleich erfolgt immer global, und das Feld `service` unterteilt die Deduplizierung weiterhin wie bei den anderen globalen Algorithmen.

## Beispiel

Angenommen, Global Locations (beide Standorttypen) ist bei einem DAST-Tool (Same Tool) und, für die Cross-Tool-Zeile, bei einem zweiten DAST-Tool aktiviert:

| Schritt | Import | In Produkt | Ergebnis |
| --- | --- | --- | --- |
| 1 | DAST-Befund unter `https://shared.example.com/login` | Application 0 | 1 aktiver Befund erstellt |
| 2 | Dieselbe URL, **andere** Schwachstelle (Titel + Schweregrad) | Application 1 | 1 Befund erstellt, als Duplikat des Befunds von Application 0 markiert (allein der Standort stimmt überein) |
| 3 | Zweites DAST-Tool, dieselbe URL | Application 2 | 1 Befund erstellt, als Duplikat des Befunds von Application 0 markiert (Cross-Tool-Übereinstimmung) |
| 4 | DAST-Befund unter `https://other.example.com/admin` | Application 3 | 1 aktiver Befund erstellt — andere URL, kein gemeinsamer Standort |
| 5 | Befund ohne URL und ohne Abhängigkeit | Application 4 | 1 aktiver Befund erstellt — kein gemeinsamer Standort vorhanden |

Jeder doppelte Befund zeigt seinen Originalbefund unten auf der Befundseite in der Duplikatkette an.

## Global Component vs. Global Locations

Beide sind globale (produktübergreifende) Algorithmen, die den Engagement-Geltungsbereich ignorieren und anhand einer einzelnen Identität statt der Hash-Felder abgleichen. Die Wahl richtet sich danach, was für Ihr Tool ein Duplikat identifiziert:

| | Global Component | Global Locations |
| --- | --- | --- |
| Gleicht ab anhand von | Komponenten**name + -version** | Ein gemeinsamer **Standort**: eine URL und/oder eine Abhängigkeit |
| Abhängigkeitsidentität | Name und Version | Vollständige **Package-URL** (Typ, Namespace, Name, Version, Qualifier) |
| URL-/DAST-Befunde | Nicht abgeglichen | Abgeglichen (anhand der konfigurierten Endpunktfelder) |
| Konfigurierbar | Nein | Ja — pro Tool URLs, Dependencies oder beides wählbar |
| Datenmodell | Funktioniert mit oder ohne Locations | Erfordert **Locations** (Pro) |
| Am besten geeignet für | SCA-Tools, bei denen Paketname + -version die Identität bilden | Web-/DAST-Tools und SCA unter dem Locations-Modell, bei denen die URL oder die exakte Abhängigkeit die Identität bildet |

Für eine neue Instanz, die das Locations-Datenmodell verwendet, ist Global Locations der präzisere Nachfolger von Global Component: Es schlüsselt Abhängigkeiten anhand der exakten Package-URL und dedupliziert zusätzlich URL-basierte Befunde. Global Component bleibt unverändert verfügbar für Tools, bei denen Komponentenname + -version die gewünschte Identität darstellen.

## Sichtbarkeit über Produkte hinweg

Da der Global-Locations-Abgleich Produktgrenzen überschreitet, kann der ursprüngliche Befund in einer Duplikatkette in einem Produkt liegen, auf das der Benutzer, der das Duplikat betrachtet, keinen Zugriff hat.

In diesem Fall wird der Befund sichtbar und als Duplikat gekennzeichnet angezeigt, der Benutzer kann jedoch nicht zum Original wechseln oder es öffnen. Berücksichtigen Sie dies, bevor Sie Global Locations für Tools aktivieren, deren Befunde gegenüber produktbezogenen Zugriffskontrollen sensibel sind.

## Zurücksetzen

Um die Verwendung von Global Locations für ein bestimmtes Tool zu beenden, öffnen Sie dessen Deduplizierungseinstellungen und stellen Sie den Algorithmus wieder auf eine der eingeschränkten Optionen um.

Für **Same Tool** Deduplication:

- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Für **Cross Tool** Deduplication:

- Hash Code
- Disabled

Das Ändern des Algorithmus löst eine Neuberechnung der Deduplizierungs-Hashes für die vorhandenen Befunde des Tools im Hintergrund aus.
