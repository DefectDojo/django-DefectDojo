---
title: Vergleich der Import-Methoden
description: Erfahren Sie, wie Sie Daten manuell, über die API oder per Connector
  importieren
weight: 1
aliases:
- /de/en/connecting_your_tools/import_intro
---

Eines der Dinge, die wir bei DefectDojo verstanden haben, ist, dass die Sicherheitsanforderungen jedes Unternehmens völlig unterschiedlich sind. Es gibt keinen Einheitsansatz. Da sich Ihre Organisation verändert, ist ein flexibler Ansatz entscheidend, und DefectDojo ermöglicht es Ihnen, Ihre Sicherheitstools flexibel anzubinden, um mit diesen Veränderungen Schritt zu halten.

## Scan-Upload-Methoden

Wenn DefectDojo einen Schwachstellenbericht von einem Sicherheitstool empfängt, erstellt es Befunde auf Basis der in diesem Bericht enthaltenen Schwachstellen. DefectDojo dient als zentrales Repository für diese Befunde, in dem sie von Ihnen und Ihrem Team triagiert, behoben oder anderweitig bearbeitet werden können.

Es gibt zwei Hauptwege, über die DefectDojo Befundberichte hochladen kann.

* Über den direkten **Import** in der UI
* Über den **API**-Endpunkt (ermöglicht automatisierte Datenaufnahme): siehe [API Docs](/automation/api/api-v2-docs/)

#### DefectDojo Pro-Methoden

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>-Benutzer haben drei zusätzliche Methoden, um Berichte und Daten zu verarbeiten:

* Über **Universal Importer** oder **DefectDojo CLI**, Kommandozeilen-Tools, die die DefectDojo-API nutzen: siehe [Universal Importer & DefectDojo-CLI guides](/import_data/pro/specialized_import/external_tools/)
* Über **Connectors** für bestimmte Tools, eine sofort einsatzbereite Datenintegration: siehe [Connectors Guide](/connectors/upstream/about/)
* Über **Smart Upload** für bestimmte Tools, einen Importer, der für die Verarbeitung von Infrastruktur-Scans entwickelt wurde: siehe [Smart Upload Guide](/import_data/pro/specialized_import/smart_upload/)

### Vergleich der Upload-Methoden

|  | **UI Import** | **API** | **Connectors** <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span> | **Smart Upload**  <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span>|
| --- | --- | --- | --- | --- |
| **Unterstützte Scan-Typen** | Alle: siehe [Supported Tools](/supported_tools/) | Alle: siehe [Supported Tools](/supported_tools/) | Akamai API Security, Anchore, AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, IriusRisk, JFrog Xray, Probely, Semgrep, SonarQube, Snyk, Tenable, Wiz | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **Automatisierung?** | Verfügbar über API: `/reimport`- und `/import`-Endpunkte | Ausgelöst über [CLI Tools](/import_data/pro/specialized_import/external_tools/) oder externen Code | Connectors ist naturgemäß eine automatisierte Funktion | Verfügbar über API: `/smart_upload_import`-Endpunkt |

### Produkthierarchie und Organisation

Jede dieser Methoden kann die Produkthierarchie direkt vor Ort erstellen. Produkthierarchie bezeichnet die Produkttypen, Produkte, Engagements oder Tests von DefectDojo: Objekte in DefectDojo, die dabei helfen, Ihre Daten in einem relevanten Kontext zu organisieren.

* **Schwachstellendaten können in eine bestehende Produkthierarchie importiert werden.** Produkttypen, Produkte, Engagements und Tests können alle im Voraus erstellt werden, und Daten können dann an diese Stelle in DefectDojo importiert werden.
* **Die kontextbezogene Produkthierarchie kann zum Zeitpunkt des Imports erstellt werden.** Beim Importieren eines Berichts können Sie einen neuen Produkttyp, ein neues Produkt, Engagement und/oder einen neuen Test erstellen. Dies wird von DefectDojo über die Option „auto-create context“ gesteuert. In DefectDojo OS ist diese Option nur über die API zugänglich. UI-Importe in DefectDojo OS erfordern, dass die Produkthierarchie zuerst erstellt wird.
