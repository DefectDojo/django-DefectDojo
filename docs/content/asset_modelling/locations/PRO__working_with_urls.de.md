---
title: Arbeiten mit URLs
description: Alltägliche Nutzung von URL-Locations als Ersatz für Endpoints
audience: pro
weight: 4
---

URL-Locations sind der funktionale Ersatz für das veraltete Endpoints-Modell. Sie speichern dieselben URL-förmigen Felder, die Sie gewohnt sind — `protocol`, `host`, `port`, `path`, `query`, `fragment` — und erfüllen dieselbe Aufgabe: zu identifizieren, *wo* ein Webanwendungs-Befund liegt.

Diese Seite beschreibt, was sich bei der täglichen Nutzung von URL-Locations ändert, welche neuen Oberflächen es gibt und welche API-Endpunkte anstelle der veralteten Endpoint-API zu verwenden sind.

## Der URL-Subtyp

Jede URL ist eine Location. Das bedeutet, eine URL verfügt über beides:

- Die strukturierten URL-Felder (`protocol`, `user_info`, `host`, `port`, `path`, `query`, `fragment` sowie einen `hash` zur Deduplizierung).
- Die gemeinsamen Location-Felder (`location_type="url"`, eine kanonische `location_value`-Zeichenkette für Anzeige und Suche, Tags, geerbte Tags, Metadaten sowie Reference-Verknüpfungen zu Assets und Befunden).

Wenn Sie eine URL erstellen oder hochladen, zerlegt DefectDojo sie in die strukturierten Felder und schreibt sowohl die URL-Zeile als auch die zugehörige übergeordnete Location-Zeile in einer einzigen Transaktion. Die URL-Deduplizierung erfolgt als exakter Abgleich über die strukturierten Felder — zwei URLs gelten als identisch, wenn jede Komponente übereinstimmt, wobei der Standard-Port wie üblich zusammengefasst wird (`http://example.com:80/` und `http://example.com/` ergeben dieselbe URL).

## In der Pro-Benutzeroberfläche

Wenn das Feature Locations aktiviert ist, bietet die Navigation:

- **Locations / All** — Eine Liste aller Locations über die Subtypen URL und Dependency hinweg. Filterbar nach Typ, Status, Asset, Befund oder Tag.
- **Locations / URLs** — Eine eingegrenzte Liste ausschließlich der URL-Locations. Dies entspricht am ehesten der alten Endpoints-Seite.
- **New URL** — Ein Formular zum Erstellen einer einzelnen URL mit strukturierten Feldern, Tags und optionalen Asset-/Befund-Zuordnungen.
- **Locations on an Asset** — Von jedem Asset aus zeigt der Tab **Locations** die diesem Asset zugeordneten URLs und Dependencies, mit Statuszählungen und Schnellaktionen.

Gängige Workflows aus der Endpoints-Oberfläche bleiben erhalten:

- **Massen-Statusaktualisierungen.** Wählen Sie mehrere URL-Locations aus und wenden Sie in einer Aktion einen Status (Aktiv, Behoben, Falsch-positiv, Risiko akzeptiert, Außerhalb des Geltungsbereichs) auf deren Befund-Referenzen an.
- **Bestehende URLs zu einem Asset hinzufügen.** Verwenden Sie **Add Existing** im Locations-Tab eines Assets, um bereits im System vorhandene URLs zu verknüpfen, anstatt Duplikate zu erstellen.
- **Tags.** Auf eine URL-Location angewendete Tags werden als geerbte Tags an die Befunde weitergegeben, die auf sie verweisen — genauso, wie es zuvor bei Endpoint-Tags der Fall war.

## Statusmodell

URL-Locations verwenden dieselben Einzelstatus-Bezeichnungen wie alle anderen Locations:

| Status | Bedeutung |
| --- | --- |
| **Aktiv** | Der Befund an dieser URL ist offen. |
| **Behoben** | Der Befund wurde für diese URL behoben. |
| **Falsch-positiv** | Der Befund ist für diese URL keine echte Schwachstelle. |
| **Risiko akzeptiert** | Der Befund wird zur Kenntnis genommen, aber für diese URL akzeptiert. |
| **Außerhalb des Geltungsbereichs** | Diese URL ist vom Engagement ausgeschlossen. |

Beachten Sie, dass das alte Endpoint-Status-Modell mehrere Flags gleichzeitig zuließ (z. B. `mitigated=True` und `false_positive=True`). Locations erzwingen jeweils nur einen Status. Wenn Sie von Endpoints migriert haben, wurde das spezifischste Flag beibehalten (siehe die Zuordnungstabelle unter [Migrating from Endpoints](../pro__migrating_from_endpoints)).

Asset References verwenden einen einfacheren Status: nur **Aktiv** oder **Behoben**, da der Status auf Asset-Ebene nicht dieselbe Prüfdetailtiefe benötigt.

## REST-API

Verwenden Sie diese Endpunkte anstelle der veralteten Endpoint-API:

| Aufgabe | Endpunkt |
| --- | --- |
| URLs auflisten | `GET /api/v2/urls/` |
| Eine URL erstellen | `POST /api/v2/urls/` |
| Tags oder Metadaten einer URL aktualisieren | `PATCH /api/v2/urls/{id}/` |
| Alle Locations auflisten (URLs + Dependencies) | `GET /api/v2/location/?location_type=url` |
| Eine URL mit einem Befund verknüpfen | `POST /api/v2/location_findings/` |
| Eine URL mit einem Asset verknüpfen | `POST /api/v2/location_Assets/` |
| Status einer Befund-Verknüpfung aktualisieren | `PATCH /api/v2/location_findings/{id}/` |
| Eine Befund-Verknüpfung entfernen | `DELETE /api/v2/location_findings/{id}/` |

Filter für `/api/v2/urls/` umfassen die strukturierten URL-Felder sowie `tag(s)`, `has_tags`, `Asset` und die Sortierung nach `host`, `Asset` oder der Anzahl aktiver Befunde.

Der veraltete Endpunkt `/api/v2/endpoints/` bedient über einen Kompatibilitäts-Shim weiterhin **Lese**-Zugriffe — siehe [Migrating from Endpoints](../pro__migrating_from_endpoints), was dabei erhalten bleibt und wo sich der Shim vom ursprünglichen Verhalten unterscheidet. **Schreibzugriffe** auf die veralteten Endpunkte liefern `403` zurück und müssen auf die obigen Endpunkte umgestellt werden.

## Importieren von URLs aus Scans

Scanner-Importe erstellen URL-Locations automatisch. Wenn ein Parser für einen Befund eine URL ausgibt (so wie er früher einen Endpoint ausgegeben hat), führt der Importer Folgendes aus:

1. Sucht nach einer bestehenden URL mit übereinstimmenden strukturierten Feldern oder erstellt eine neue.
2. Erstellt eine Finding Reference, die den Befund mit dem Status **Aktiv** mit der URL verknüpft.
3. Erstellt eine Asset Reference (oder verwendet eine bestehende weiter), damit die URL auch beim übergeordneten Asset erscheint.

DefectDojo-Parser, die zuvor Endpoints erstellt haben, wurden aktualisiert, um in Pro automatisch Locations zu erstellen.

## Dinge, die sich anders verhalten

Ein paar kleine Verhaltensänderungen sind erwähnenswert:

- **Ein Status pro URL-/Befund-Paar.** Wie oben beschrieben wird das Mehrfach-Flag-Modell von Endpoint_Status auf einen einzelnen Status reduziert. Workflows, die Flags unabhängig voneinander umgeschaltet haben, müssen sich für einen einzelnen Übergang entscheiden.
- **Tags liegen bei der Location, nicht bei der URL.** Der URL-Subtyp führt keine eigene Tag-Menge; Tags gehören zur übergeordneten Location. Wenn Sie eine URL über die API lesen, stammt das Feld `tags` aus `location.tags`.
- **Deduplizierung erfolgt pro kanonischer URL, nicht pro Asset.** Zwei Assets mit derselben URL teilen sich eine einzige zugrunde liegende URL-Location und referenzieren sie zweimal (jeweils eine Asset Reference). Das ist beabsichtigt und ermöglicht assetübergreifende Berichte.
- **Das Feld `endpoints` bei Befunden.** Ist das Flag aktiviert, liefert dieses Feld der Finding-API weiterhin Zeilen, diese werden jedoch aus URL-Locations statt aus der Endpoint-Tabelle projiziert. Behandeln Sie es als schreibgeschützt und schreiben Sie stattdessen über `/api/v2/location_findings/`.
