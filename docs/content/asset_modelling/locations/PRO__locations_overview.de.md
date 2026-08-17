---
title: Übersicht über Standorte
description: Was Standorte sind und warum sie Endpunkte ersetzen
audience: pro
weight: 1
---

**Standorte** sind ein neues Asset-Modellierungs-Tool in DefectDojo Pro. Sie ersetzen das bisherige **Endpunkte**-Modell und übernehmen die früheren **Komponenten**-Daten (Bibliotheken), wodurch DefectDojo über eine einzige, polymorphe Möglichkeit verfügt, zu beschreiben, *wo* sich ein Befund befindet — sei es eine URL, eine Software-Abhängigkeit aus einer **SBOM** oder, zukünftig, eine **Cloud-Ressourcen-ID**, ein **Container-Image** oder ein **Code-Repository**.

Standorte müssen auf Ihrer Instanz aktiviert werden, bevor Sie sie nutzen können. Sie können Standorte selbst über die [Seite Feature Flags](/admin/feature_flags/pro__feature_flags/) aktivieren — eine Support-Anfrage ist nicht erforderlich. Beachten Sie, dass Standorte nach der Aktivierung nicht wieder deaktiviert werden können.

## Warum Endpunkte ersetzen?

Das ursprüngliche Endpunkte-Modell war auf URLs und IP-Adressen ausgelegt — es enthielt Webanwendungsfelder wie `protocol`, `host`, `port`, `path` sowie eine feste Statustabelle, die eng an Befunde gekoppelt war. Daraus ergaben sich drei Probleme:

1. **Begrenzte Genauigkeit.** Endpunkte konnten Nicht-URL-Assets wie Drittanbieter-Bibliotheken, Container-Images oder Cloud-Ressourcen nicht sauber beschreiben, obwohl Scanner zunehmend Befunde zu genau solchen Dingen erzeugen.
2. **Performance-Obergrenze.** Die Endpoint_Status-Zeilen pro Befund und das URL-förmige Schema skalierten bei großen Kundenvolumen nicht gut.
3. **Komponenten waren zweitrangig.** Software-Bibliotheken existierten nur als denormalisierte Felder an einem Befund, sodass eine Bibliothek nicht unabhängig von einer Schwachstelle existieren konnte — was ein echtes SBOM-Management unmöglich machte.

Standorte beheben alle drei Probleme, indem sie ein **Basis-`Location`-Objekt** mit einem typisierten Payload sowie dedizierte **Subtypen** für jede Asset-Form einführen:

- **URL-Standorte** — das funktionale Äquivalent der alten Endpunkte, mit denselben Feldern protocol/host/port/path/query/fragment.
- **Abhängigkeits-Standorte** — Software-Bibliotheken, identifiziert durch [Package URL (pURL)](https://github.com/package-url/purl-spec), zur Modellierung von SBOM-Inhalten.
- **[Quellcode-Standorte](/asset_modelling/locations/pro__source_code_locations/)** — wo sich ein Befund einer statischen Analyse im Quellcode befindet, identifiziert durch Dateipfad und Zeilennummer. Scan-verwaltet und die Grundlage für die [Verfolgung von Befunden, wenn sich ihr Code verschiebt](/triage_findings/finding_deduplication/pro__location_drift_matching/).

Zu den zukünftigen, in Erwägung gezogenen Standort-Typen zählen Cloud-Provider-Ressourcen-IDs (AWS ARN, Azure Resource ID, GCP Full Resource Name) sowie Container-Images (registry/repository:tag und SHA256-Fingerabdrücke).

## Kernkonzepte

### Standorte und Subtypen

Ein **Standort** ist das gemeinsame übergeordnete Objekt. Er enthält:

- Einen `Location Type` (z. B. `"url"`, `"dependency"`)
- Eine kanonische `Location Value`-Zeichenkette, die für Anzeige, Suche und Deduplizierung verwendet wird
- `Tags` sowie von dem übergeordneten Asset geerbte Tags
- Metadaten (benutzerdefinierte Schlüssel-/Wert-Paare)

Ein **Subtyp** (URL oder Abhängigkeit) enthält die strukturierten Felder, die für diese Art von Standort spezifisch sind. URLs und Abhängigkeiten existieren stets zusammen mit einem übergeordneten Location-Objekt; der `Location Value` des Subtyps wird aus dessen strukturierten Feldern generiert.

### Referenzen

Standorte werden nicht direkt an Produkte oder Befunde angehängt. Stattdessen verknüpfen sie zwei **Referenz**-Objekte:

- **Asset-Referenzen** — Beziehungen, die der Standort zu Assets hat (z. B. gehört `libFoo` zu Asset 6 und wird von Asset 9 verwendet). Jede Referenz trägt einen Status (`Active` oder `Mitigated`) sowie optional eine **Beziehung** („Verwendet von“ oder „Gehört zu“).
- **Befund-Referenzen** — Beziehungen, die der Standort zu Befunden hat. Jede Referenz trägt einen umfangreicheren Status (`Active`, `Mitigated`, `False Positive`, `Risk Accepted`, `Out of Scope`) sowie den Prüfer und den Prüfzeitpunkt.

Diese Trennung ermöglicht es, dass eine Bibliothek auf einem Produkt existieren kann, *ohne* einen Befund zu benötigen — eine Fähigkeit, die im alten Komponenten-Modell fehlte.

### Automatische Zuordnung beim Import

Wenn ein Parser einen Befund erzeugt, der auf eine URL oder eine Bibliothek verweist, geht der Importer wie folgt vor:

1. Er sucht nach einem vorhandenen Standort, der der URL oder pURL entspricht; existiert keiner, wird einer erstellt.
2. Er erstellt eine Befund-Referenz, die den Befund mit dem Status `Active` mit dem Standort verknüpft.
3. Er erstellt (oder verwendet erneut) eine Asset-Referenz, damit der Standort auch am übergeordneten Asset existiert.

Bestehende Parser wurden aktualisiert, um Standort-Daten auszugeben, wenn das Feature-Flag aktiviert ist, und auf das alte Endpunkt-Modell zurückzugreifen, wenn es deaktiviert ist. Nach der Aktivierung von Standorten ist keine erneute Konfiguration erforderlich — der nächste Import wird automatisch über die Standorte-Pipeline geleitet.

## Was im MVP enthalten ist

| Funktion | Status |
| --- | --- |
| Grundlegende Modelle `Location`, `URL`, `Dependency` | Veröffentlicht |
| REST-API für Standorte und Referenzen | Veröffentlicht (schreibgeschütztes `Location`, vollständiges CRUD für Referenzen) |
| Kompatibilitäts-Shim für die Endpunkt-API (nur Lesezugriff) | Veröffentlicht |
| Einseitiger Migrationsbefehl Endpunkt → URL | Veröffentlicht |
| Parser-Aktualisierungen (URLs und Abhängigkeiten) | Für die wichtigsten Parser veröffentlicht |
| SBOM-Upload (CycloneDX, SPDX v2/v3) | Veröffentlicht über `/api/v2/sbom-import/` |
| Pro-UI für Standorte, URLs, Abhängigkeiten | Veröffentlicht |
| pURL-Suche/-Filter | Veröffentlicht |
| Lizenz-Tracking für Abhängigkeiten | Teilweise (Feld `license_expression`) |
| SWID-Tag-SBOM-Format | Nicht im MVP enthalten |

## Wie geht es weiter

- **Funktion aktivieren** — wenden Sie sich an [support@defectdojo.com](mailto:support@defectdojo.com), um Standorte für Ihre Instanz zu aktivieren.
- **Migration von Endpunkten** — siehe [Migration von Endpunkten](../pro__migrating_from_endpoints), um zu erfahren, was bei der Migration erhalten bleibt und wie sich die alte Endpunkt-API danach verhält.
- **Tägliche URL-Workflows** — siehe [Arbeiten mit URLs](../pro__working_with_urls).
- **SBOMs und Abhängigkeiten** — siehe [Arbeiten mit SBOMs](../pro__working_with_sboms).
