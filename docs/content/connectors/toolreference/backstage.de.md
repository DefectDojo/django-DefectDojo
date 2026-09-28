---
title: "Backstage"
description: "Einrichtung des Backstage Upstream-Connectors für DefectDojo"
weight: 22
audience: pro
---
Der Backstage-Connector ist ein **Asset-Connector**: Anstatt Befunde zu importieren, überträgt er Ihren [Backstage](https://backstage.io)-Software-Katalog in DefectDojo und hält Ihre Produkthierarchie und Team-Zuständigkeit damit synchron. Er ist für Organisationen konzipiert, die ihr Service-Inventar und ihre Organisationsstruktur in Backstage pflegen und möchten, dass DefectDojo diese Struktur widerspiegelt, statt sie manuell zu pflegen.

#### Was zugeordnet wird

| Backstage | DefectDojo |
|---|---|
| **System** | Produkttyp (Components ohne System werden unter einem konfigurierbaren Produkttyp „Backstage / Uncategorized" gruppiert) |
| **Component** | Produkt — benannt nach dem `title` der Entität (Rückgriff auf `name`), mit der Katalogbeschreibung |
| **Owning Group** (`ownedBy`-Beziehung) | Eine mit dem Produkt verknüpfte DefectDojo-Gruppe (Standardrolle: Maintainer, konfigurierbar) |
| **Owner email** (E-Mail des Gruppenprofils oder E-Mail eines User-Owners) | Ein Produktmitglied, sofern bereits ein DefectDojo-Benutzer mit dieser E-Mail-Adresse existiert (es werden nie Benutzer angelegt) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, Namespace, Domain | Produkt-Tags mit dem Präfix `backstage:` |
| `metadata.annotations` | Wird am Eintrag gespeichert (begrenzt); ausgewählte Annotationen können über **Annotation Mappings** zu vollwertigen Attributen oder Tags hochgestuft werden |

Einträge werden über die vom Server vergebene `metadata.uid` der Entität identifiziert, sodass Umbenennungen in Backstage das zugeordnete Produkt beim nächsten Sync **an Ort und Stelle** aktualisieren — keine Duplikate. Der Produktname folgt stets dem Katalog: Um ein von diesem Connector verwaltetes Produkt umzubenennen, benennen Sie die Component in Backstage um (eine Umbenennung auf DefectDojo-Seite oder ein bei der manuellen Zuordnung vergebener eigener Name wird beim nächsten Sync auf den Katalognamen zurückgesetzt, sofern dies nicht mit einem anderen Produkt kollidieren würde). Eigentümerwechsel verschieben die Gruppenzuordnung des Produkts. Components, die aus dem Katalog verschwinden (oder mit der Annotation `backstage.io/orphan` gekennzeichnet sind), werden als **MISSING** markiert — DefectDojo löscht nie von sich aus ein Produkt. Domain- und Group-Hierarchie (übergeordnete Teams) werden nur als Tags/Metadaten erfasst; sie erzeugen keine zusätzlichen Hierarchieebenen.

#### Voraussetzungen

Der Connector authentifiziert sich mit einem **statischen externen Zugriffstoken** gegenüber dem Backstage-Backend. Definieren Sie in Ihrer Backstage-App-Konfiguration ein Token und beschränken Sie es (empfohlen) auf das Catalog-Plugin:

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

Generieren Sie ein starkes Zufallstoken (zum Beispiel mit `openssl rand -hex 32`) und speichern Sie es in der Umgebung Ihrer Backstage-Bereitstellung. Einzelheiten finden Sie in der [Backstage-Dokumentation zur Service-to-Service-Authentifizierung](https://backstage.io/docs/auth/service-to-service-auth).

#### Connector-Zuordnungen

1. Geben Sie Ihre **Backstage-Backend-Root-URL** in das Feld **Location** ein: zum Beispiel `https://backstage.example.com` (der Connector hängt `/api/catalog` an). Dies muss die **Backend**-URL sein, nicht die Frontend-Web-UI.
2. Geben Sie das statische externe Zugriffstoken in das Feld **Secret** ein.

Optionale Felder (für die Standardwerte leer lassen):

* **Namespaces** — kommagetrennte Katalog-Namespaces, die importiert werden sollen; bei leerem Feld werden alle Namespaces importiert.
* **Component Types** — kommagetrennte `spec.type`-Werte (z. B. `service,website`); bei leerem Feld werden alle Typen importiert.
* **Page Size** — Seitengröße der Katalogabfrage (1\-500, Standard 250).
* **TLS Verification** — nur auf `false` setzen, wenn Backstage ein Zertifikat verwendet, das DefectDojo nicht verifizieren kann (interne CA); nicht empfohlen.
* **Uncategorized Product Type** — der Produkttyp für Components ohne System (Standard `Backstage / Uncategorized`).
* **Owner Group Role** — die Rolle, die dem verantwortlichen Team bei zugeordneten Produkten gewährt wird (Standard `Maintainer`).
* **Annotation Mappings** — ein JSON-Objekt, das Annotationsschlüssel auf Namen von Eintragsattributen abbildet, oder auf `"tag"`, um eine Annotation als Produkt-Tag zu importieren, z. B. `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

Bei aktiviertem **Auto\-Map** baut ein einziger Discover \+ Sync die vollständige Struktur aus Produkttyp/Produkt/Eigentümerschaft ohne manuelle Schritte auf. Bei deaktiviertem Auto\-Map erscheinen ermittelte Components als Einträge, die auf Ihre Zuordnungsentscheidung warten.

#### Einschränkungen (v1)

* Die **Group-Mitgliedschaft von Backstage wird nicht synchronisiert**: Der Connector erstellt/verknüpft das verantwortliche Team als DefectDojo-Gruppe, aber das Befüllen dieser Gruppe mit Benutzern bleibt Ihrem Identity-Provider oder Ihren Administratoren überlassen.
* Nur Components werden zu Produkten; APIs, Resources und Domains werden nicht als Assets importiert (Domains erscheinen als Tags).
* Tags und Annotationen werden normalisiert und begrenzt, um in die DefectDojo-Feldgrenzen zu passen (überlange Werte werden gekürzt).

**Ein Hinweis zur umgekehrten Richtung:** Die Anzeige von DefectDojo-Befunden und -Bewertungen *innerhalb* von Backstage (auf Entitätsseiten) wäre ein naheliegender nächster Schritt, der als Backstage-Frontend-Plugin umgesetzt würde, das die DefectDojo-REST-API konsumiert — dies liegt bewusst außerhalb des Umfangs dieses Connectors, der ausschließlich Katalogdaten in DefectDojo überträgt.
