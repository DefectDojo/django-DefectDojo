---
title: Arbeiten mit SBOMs
description: Software-Abhängigkeiten und SBOMs als Locations verwalten
audience: pro
weight: 5
---

DefectDojo Pro modelliert Software-Bibliotheken als **Dependency-Locations**. Eine Dependency ist ein Location-Subtyp, der durch eine [Package URL (pURL)](https://github.com/package-url/purl-spec) identifiziert wird und ein einzelnes Bibliotheks- oder Paket-Objekt darstellen soll — `org.apache.logging.log4j:log4j-core@2.17.0`, `pypi/django@5.0.2`, `npm/react@18.2.0` und so weiter.

Dependencies ersetzen das bisherige **Components**-Modell, das nur an Befunde angehängt war. Mit Locations können Bibliotheken unabhängig von einer Schwachstelle existieren — Sie können ein SBOM zu einem Asset hochladen und Befunde dann automatisch an die Dependencies anhängen lassen, auf die sie sich beziehen, sobald Scans eintreffen.

## Was eine Dependency enthält

Jede Dependency wird eindeutig durch eine pURL identifiziert, die in atomare Felder zerlegt wird, nach denen Sie suchen und filtern können:

| Feld | Bedeutung | Beispiel |
| --- | --- | --- |
| `purl_type` | Bibliotheks-Ökosystem | `npm`, `pypi`, `maven`, `cargo`, `nuget`, `gem` |
| `namespace` | Anbieter oder Organisation | `org.apache.logging` |
| `name` | Bibliotheksname | `log4j-core` |
| `version` | Konkrete Version | `2.17.0` |
| `qualifiers` *(optional)* | Implementierungsdetails | `arch=amd64` |
| `subpath` *(optional)* | Pfad innerhalb eines Archivs oder Monorepos | `src/lib/foo` |
| `artifact_hashes` *(optional)* | Fingerabdrücke | SHA256-Summen |
| `license_expression` *(optional)* | SPDX-Lizenzausdruck | `Apache-2.0`, `MIT` |
| `file_path` *(optional)* | Wo die Bibliothek im Projekt gefunden wurde | `package-lock.json` |

Diese atomare Zerlegung macht die pURL-basierte Suche nützlich: Sie können fragen *„alle `pypi`-Pakete im Namespace `django` in Version 4.x"*, und DefectDojo kann das beantworten, ohne eine Freitext-Zeichenkette zu parsen.

## Owned-By vs. Used-By

Wenn eine Dependency mit einem Asset verknüpft ist, trägt die Asset Reference eine optionale **Beziehung**, die beschreibt, *wie* die Bibliothek zum Asset gehört:

- **`owned_by`** — *„diese Bibliothek gehört zu diesem Asset"*. Verwenden Sie dies für Eigenentwicklungen (First-Party-Bibliotheken), die ein Asset veröffentlicht oder pflegt.
- **`used_by`** — *„diese Bibliothek wird von diesem Asset verwendet"*. Verwenden Sie dies für Drittanbieter-Abhängigkeiten, die ein Asset nutzt.

Dieselbe Bibliothek kann für ein Asset `owned_by` und für mehrere andere `used_by` sein — genau die Beziehung, die Sie benötigen, um bei der Schwachstellen-Triage die Frage *„wer nutzt das Paket, das mein Team veröffentlicht?"* zu beantworten.

## Hochladen eines SBOMs

Um Dependencies in großem Umfang zu befüllen, laden Sie eine SBOM-Datei zu einem Produkt hoch. Der Endpunkt lautet:

```
POST /api/v2/sbom-import/
```

| Feld | Beschreibung |
| --- | --- |
| `product` | Die ID des Ziel-Produkts (Asset) |
| `file` | Die SBOM-Datei |
| `scan_type` | Das SBOM-Format — siehe unterstützte Formate unten |
| `replace` *(optional)* | Wenn `true`, werden veraltete Produkt-Zuordnungen ohne bestehende Finding-Referenz entfernt. Standard: `false` (kumulativ) |

Der Importer parst die Datei, extrahiert `Dependency`-Datensätze, dedupliziert sie gegen bestehende Locations (bei Bedarf werden neue erstellt) und erstellt Asset References, die jede Dependency mit dem Produkt verknüpfen. Die Pro-Benutzeroberfläche bietet denselben Upload-Ablauf — siehe die Aktion **Upload SBOM** im Locations-Tab eines Produkts.

### Unterstützte Formate

Das MVP enthält Parser für die beiden dominanten SBOM-Formate:

- **CycloneDX** — JSON und XML
- **SPDX** — JSON (v2 und v3), XML und Tag-Value

Das SWID-Tag-Format wird noch nicht unterstützt.

### Replace vs. Append

Standardmäßig sind wiederholte Uploads **additiv**: Dependencies, die auf dem Asset bereits vorhanden sind, bleiben erhalten, neue werden hinzugefügt, und nichts wird entfernt. Das entspricht dem typischen Workflow für inkrementelle SBOM-Aktualisierungen.

Setzen Sie `replace=true`, um zu bereinigen. Ist der Replace-Modus aktiv, entfernt der Importer nach einem erfolgreichen Import Produkt-Zuordnungen, die im neuen SBOM nicht enthalten waren **und** aktuell nicht von einem aktiven Befund referenziert werden. Referenzen, die mit aktiven Befunden verknüpft sind, bleiben auch im Replace-Modus erhalten, sodass Sie den Schwachstellenkontext nicht verlieren, nur weil ein neues SBOM ein Paket auslässt.

## Befunde, die auf Bibliotheken verweisen

Wenn ein Parser eine an eine Bibliothek gebundene Schwachstelle einliest — zum Beispiel ein SCA-Tool, das `CVE-2021-44228` gegen `log4j-core@2.14.1` meldet —, führt der Importer Folgendes aus:

1. Sucht anhand der pURL nach einer bestehenden Dependency-Location oder erstellt eine neue.
2. Erstellt eine `LocationFindingReference`, die den Befund mit dem Status **Aktiv** mit der Dependency verknüpft.
3. Erstellt eine `LocationProductReference`, damit die Dependency auch beim übergeordneten Produkt erscheint, falls noch nicht geschehen.

Da Befunde und SBOM-Uploads dieselben zugrunde liegenden Dependency-Objekte gemeinsam nutzen, wird ein Befund, der *vor* einem SBOM-Upload eingelesen wurde, rückwirkend in der SBOM-Ansicht sichtbar, und umgekehrt.

## REST-API

| Aufgabe | Endpunkt |
| --- | --- |
| Ein SBOM hochladen | `POST /api/v2/sbom-import/` |
| Dependencies auflisten | `GET /api/v2/dependencies/` |
| Eine Dependency manuell erstellen | `POST /api/v2/dependencies/` |
| Dependency-Locations auflisten | `GET /api/v2/location/?location_type=dependency` |
| Eine Dependency mit einem Befund verknüpfen | `POST /api/v2/location_findings/` |
| Eine Dependency mit einem Produkt verknüpfen (mit `owned_by` / `used_by`) | `POST /api/v2/location_products/` |

Filter für `/api/v2/dependencies/` umfassen die pURL-Komponentenfelder, Tags sowie die Sortierung nach `name`, `version` und der Anzahl aktiver Befunde.

## In der Pro-Benutzeroberfläche

Wenn Locations aktiviert ist, bietet die Navigation:

- **Locations / Dependencies** — Globale Liste aller Dependencies der Instanz, mit pURL-Filtern.
- **Locations on a Product/Asset** — Asset-bezogene Ansicht, die sowohl URLs als auch Dependencies zeigt, mit der Aktion **Upload SBOM** im Dependencies-Tab.
- **New Dependency** — Formular zum Erstellen einer einzelnen Bibliothek durch manuelle Eingabe ihrer pURL-Komponenten.
- **Findings detail** — Ein Befund, der eine Bibliothek betrifft, zeigt seine Dependency-Locations zusammen mit etwaigen URL-Locations, sodass Sie an einer Stelle sehen können: *„diese CVE betrifft `log4j-core@2.14.1` bei Asset 6 und Asset 9"*.

## Was nicht im MVP enthalten ist

- **SWID-Tag-SBOM-Format** — Wird nicht geparst. CycloneDX oder SPDX ist erforderlich.
- **Lizenzrisiko-Bewertung** — Das Feld `license_expression` wird erfasst, sofern es im SBOM vorhanden ist, aber DefectDojo kennzeichnet Befunde noch nicht bei Lizenzinkompatibilität. Lizenzbasierte Berichte stehen als Folgeschritt zum Locations-MVP auf der Roadmap.
- **Container-Image- und Cloud-Ressourcen-Locations** — Zukünftige Location-Subtypen. Derzeit werden Bibliotheken, die innerhalb eines Container-Images gefunden werden, als Dependencies erfasst; das Container-Image selbst ist noch keine eigenständige Location.
