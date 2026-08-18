---
title: Migration von Endpoints
description: Was passiert, wenn Sie vorhandene Endpoint-Daten zu Locations migrieren
audience: pro
weight: 3
---

Wenn Sie Locations auf einer bestehenden DefectDojo-Pro-Instanz aktivieren, müssen die bereits als Endpoints gespeicherten Daten in das neue Locations-Modell übernommen werden. Diese Seite beschreibt die Migration, was dabei erhalten bleibt, und wie sich die veraltete Endpoint-API nach der Migration verhält.

Beachten Sie, dass die Migration **einseitig** ist. Es gibt keinen automatisierten Rollback-Pfad, der Endpoints aus Locations wiederherstellt.

## Was die Migration bewirkt

Für jeden bestehenden Endpoint führt die Migration Folgendes durch:

1. **Erstellt eine URL-Location** (oder verwendet eine bestehende weiter) anhand der Felder `protocol`, `userinfo`, `host`, `port`, `path`, `query` und `fragment` des Endpoints. Die neue URL wird automatisch einem übergeordneten `Location`-Objekt zugeordnet.
2. **Überträgt Tags.** Jeder Tag am Endpoint wird der Tag-Menge der Location hinzugefügt.
3. **Überträgt Metadaten.** Jede an den Endpoint angehängte `DojoMeta`-Zeile wird auf die neue Location umgeleitet.
4. **Erstellt eine `LocationProductReference`**, damit die URL unter dem richtigen Asset (Produkt) erscheint.
5. **Erstellt eine `LocationFindingReference` für jeden `Endpoint_Status`**:

   | Endpoint_Status-Flag | Resultierender Location-Status |
   | --- | --- |
   | `risk_accepted=True` | **Risiko akzeptiert** |
   | `false_positive=True` | **Falsch-positiv** |
   | `out_of_scope=True` | **Außerhalb des Geltungsbereichs** |
   | `mitigated=True` | **Behoben** |
   | (keine der oben genannten) | **Aktiv** |

   Die Zuordnung ist reihenfolgeabhängig: Das *erste* zutreffende Flag gewinnt. Dadurch werden die alten Mehrfach-Flag-Kombinationen bewusst auf den einen kanonischen Status reduziert, den Locations verwenden.


## Was die Migration nicht bewirkt

- Sie erstellt **keine** Dependency-Locations. SBOM- und Bibliotheksdaten existierten nie als Endpoints, daher gibt es für die Migration nichts zu konvertieren. Um Dependencies zu befüllen, laden Sie SBOMs hoch (siehe [Working with SBOMs](../pro__working_with_sboms)) oder führen Sie Scans erneut mit Parsern aus, die Dependency-Daten liefern.
- Sie löscht **nicht** die ursprünglichen Endpoint- oder Endpoint_Status-Zeilen. Diese bleiben in der Datenbank erhalten, um die schreibgeschützte veraltete API zu unterstützen. Sie werden von der neuen Benutzeroberfläche oder von Imports nach Aktivierung des Features nicht mehr verwendet.

## Endpoint-API nach der Migration

Sobald Locations aktiviert ist, wechselt die veraltete Endpoint-API in einen **Lese-Kompatibilitätsmodus**, der bestehende Automatisierungen ohne Codeänderungen weiterlaufen lässt — allerdings nur für Lesezugriffe.

### Was weiterhin funktioniert

- `GET /api/v2/endpoints/` — Liefert Zeilen, die *wie* Endpoints aussehen, tatsächlich aber aus Location-Product-Reference-Zeilen in Verbindung mit URL-Locations projiziert werden. Die bekannten Felder (`protocol`, `host`, `port`, `path`, `query`, `fragment`, `tags`, `product`, `active_finding_count`) sind alle vorhanden.
- `GET /api/v2/endpoints/{id}/` — Der Abruf eines einzelnen Endpoints funktioniert auf dieselbe Weise. Die `id` ist die ursprüngliche Endpoint-ID und bleibt durch die Migration über das Asset-Reference-Mapping erhalten.
- `GET /api/v2/endpoint_status/` und `GET /api/v2/endpoint_status/{id}/` — Liefert Zeilen, die aus `LocationFindingReference` projiziert werden. Die veralteten booleschen Felder `mitigated`, `false_positive`, `out_of_scope` und `risk_accepted` werden rekonstruiert.
- Das Filtern nach `protocol`, `host`, `port`, `path`, `query`, `fragment`, `product` und `tag(s)` funktioniert weiterhin.
- Die Aktion `generate_report` für einzelne Endpoints funktioniert weiterhin.

### Was 403 zurückgibt

- `POST`, `PUT`, `PATCH` und `DELETE` auf `/api/v2/endpoints/` und `/api/v2/endpoint_status/` liefern alle `HTTP 403` mit folgendem Inhalt zurück:

  > Writes to this endpoint are deprecated when V3_FEATURE_LOCATIONS is enabled

  Clients, die Endpoint-Daten schreiben, müssen auf die neuen Reference-Endpunkte (`POST /api/v2/location_findings/`, `POST /api/v2/location_products/`) und auf den URL-Endpunkt (`POST /api/v2/urls/`) umsteigen.

### Verhaltensunterschiede, auf die Sie achten sollten

Einige Dinge verhalten sich anders als bei der ursprünglichen Endpoint-API:

- **Ein einzelner Status statt Flags.** Locations haben jeweils nur einen Status. Wenn Ihr Code davon ausging, dass ein Befund bei einem Endpoint_Status gleichzeitig *sowohl* `mitigated=True` *als auch* `false_positive=True` sein kann, lässt sich das nicht mehr abbilden — die Migration wählt das Flag mit der höchsten Priorität (Reihenfolge siehe Tabelle oben).
- **Feld `endpoint` bei Endpoint_Status.** Das veraltete Feld `endpoint` wird durch Nachschlagen der passenden Asset Reference rekonstruiert. In seltenen Fällen, in denen das Asset eines Befunds nicht mehr mit den Asset-Referenzen seiner Location übereinstimmt, kann dieses Feld null sein.
- **Paginierung und Sortierung.** Verfügbare Sortierfelder im Lese-Kompatibilitäts-Shim sind `host`, `product`, `id` und `active_finding_count`. Wenn Ihr Client nach einem anderen Feld sortiert, wechseln Sie zu einem dieser Felder oder zu den neuen Locations-Endpunkten.

## Tags und Metadaten

Auf Endpoints angewendete Tags werden zu Tags am Location-Objekt (nicht am URL-Subtyp). Tag-basierte Filter in der veralteten API funktionieren weiterhin.

Endpoint-Metadaten werden während der Migration auf die Location umgeleitet. Bestehende Automatisierungen, die Metadaten über `/api/v2/endpoint_meta/` lesen, sollten weiterhin funktionieren; neue Metadaten sollten über die Location-Endpunkte geschrieben werden.
