---
title: Globale Suche
description: Durchsuchen Sie Befunde, Assets und verwandte Objekte über die DefectDojo
  Pro-Kopfleiste
audience: pro
weight: 3
---

DefectDojo Pro enthält eine **globale Suche**, die Ihre Befunde und verwandte Objekte über ein einziges Feld in der Kopfleiste durchsucht. Sie basiert auf der nativen Postgres-Volltextsuche mit unscharfem, tippfehlertolerantem Abgleich, sodass Sie ein Objekt finden können, ohne sich an dessen genauen Wortlaut erinnern zu müssen.

## Eine Suche durchführen

- **Suchfeld in der Kopfleiste** — Klicken Sie auf das **Search**-Feld in der oberen Navigation und beginnen Sie mit der Eingabe. Während der Eingabe zeigt ein Dropdown eine Vorschau der besten Treffer, **gruppiert nach Objekttyp**, mit einer Anzahl neben jedem Typ und einem Link **See all *N* results** am unteren Rand.
- **Vollständige Ergebnisseite** — Drücken Sie die **Eingabetaste**, oder klicken Sie auf **See all *N* results**, um die vollständige Ergebnisseite zu öffnen. Dies ist eine einzige sortier- und filterbare Tabelle mit allen Treffern über alle Objekttypen hinweg.

Die Ergebnisse sind immer **auf das beschränkt, wofür Sie eine Zugriffsberechtigung haben** — die globale Suche zeigt niemals Objekte an, auf die Sie ansonsten keinen Zugriff hätten. (Finding-Vorlagen sind die einzige Ausnahme: Wie auch sonst in DefectDojo sind sie für jeden angemeldeten Benutzer sichtbar.)

## Was Sie durchsuchen können

Die globale Suche deckt folgende Objekttypen ab:

| Objekttyp | Hinweise |
| --- | --- |
| **Befunde** | |
| **Assets** | (Produkte) |
| **Organisationen** | (Produkttypen) |
| **Engagements** | |
| **Tests** | |
| **Endpunkte** *oder* **Standorte** | Je nachdem, was Ihre Instanz verwendet — Instanzen mit aktivierten [Standorten](/asset_modelling/locations/pro__locations_overview/) durchsuchen Standorte; andere durchsuchen Endpunkte. |
| **Finding-Vorlagen** | |
| **Technologien** | |
| **Schwachstellen-IDs** | z. B. CVEs |

Bei den meisten Typen sucht die Suche im **Namen/Titel und in der Beschreibung** des Objekts. Bei Befunden, Assets, Engagements und Tests werden zusätzlich **Tags** abgeglichen (nach Präfix). Schwachstellen-IDs werden anhand des ID-Werts selbst abgeglichen.

## Abfragesyntax

### Freitext

Geben Sie beliebige Stichwörter ein, um alles auf einmal zu durchsuchen. Die Treffer werden nach Relevanz sortiert, wobei Treffer im Titel/Namen höher eingestuft werden als Treffer in der Beschreibung. Durch den unscharfen Abgleich (siehe unten) werden auch Begriffe gefunden, die dem Suchbegriff ähnlich, aber nicht exakt gleich sind.

### Phrasen in Anführungszeichen

Setzen Sie eine Phrase in doppelte Anführungszeichen, damit sie zusammenbleibt — `"space inside"` wird als ein einzelner Begriff behandelt und nicht als zwei Stichwörter.

### Operatoren

Stellen Sie einem Begriff einen Operator voran (`operator:value`), um die Suche einzugrenzen. Unterstützte Operatoren:

| Operator | Was er bewirkt |
| --- | --- |
| `finding:` `product:` `engagement:` `test:` `template:` `technology:` | Beschränkt die Suche auf einen einzelnen Objekttyp und durchsucht diesen nach dem Wert (z. B. `finding:sqli`). |
| `id:` | Sucht einen Befund anhand seiner numerischen ID (z. B. `id:12345`). |
| `endpoint:` | Findet Befunde, deren Endpunkt-/Standort-Host den Wert enthält. |
| `vulnerability_id:` | Exakter Abgleich einer Schwachstellen-ID. Akzeptiert eine durch Kommas getrennte Liste und kann wiederholt werden (z. B. `vulnerability_id:CVE-2020-1234,CVE-2018-7489`). |
| `tag:` / `tags:` | Gleicht Objekte anhand eines Tags ab. `tag:` gleicht ein einzelnes Tag anhand eines Teilstrings ab; `tags:` gleicht ein beliebiges Tag aus einer Liste ab. |
| `test-tag:` `engagement-tag:` `product-tag:` (sowie deren Pluralformen `-tags`) | Gleicht anhand eines Tags am zugehörigen Test, Engagement oder Asset ab, statt am Objekt selbst. |
| `not-tag:` `not-tags:` (sowie die Beziehungsvarianten `not-…-tag`) | Negiert einen der obigen Tag-Operatoren, um Treffer **auszuschließen**. |

Sie können Operatoren mit Freitext-Stichwörtern in derselben Abfrage kombinieren.

### Unscharfer Abgleich

Bei Abfragen mit **drei oder mehr Zeichen** führt die globale Suche zusätzlich einen Trigramm-Abgleich (Wortähnlichkeit) durch. Dadurch werden Tippfehler toleriert und Begriffe **innerhalb** längerer, durch Punkte oder Bindestriche getrennter Werte gefunden — zum Beispiel findet `internal` eine Übereinstimmung in `api.internal.example.com`.

## Filtern und Sortieren der Ergebnisseite

Auf der vollständigen Ergebnisseite können die Spalten unabhängig vom Abfragetext gefiltert und sortiert werden — filtern Sie nach **Objekttyp**, **Schweregrad**, **Titel** oder **Kontext**, und sortieren Sie nach beliebigen Spalten. Dies ist unabhängig von der oben beschriebenen `operator:`-Syntax und gilt für die zusammengeführte Ergebnistabelle.

## Ergebnisbegrenzungen

- Die vollständige Ergebnisseite ist **paginiert** (standardmäßig 25 Zeilen pro Seite).
- Jeder Objekttyp trägt pro Suche bis zu einer **maximalen Anzahl an Treffern** bei — standardmäßig **100**. Wenn mehr Treffer vorhanden sind, als angezeigt werden, werden die Ergebnisse als gekürzt gekennzeichnet; grenzen Sie Ihre Abfrage ein, um die relevantesten Treffer zu sehen.
- Das Dropdown in der Kopfleiste zeigt eine kleinere Vorschau (die obersten Treffer pro Typ) zusammen mit den Gesamtzahlen, sodass **See all *N* results** immer die tatsächlichen Gesamtzahlen widerspiegelt.
