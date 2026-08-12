---
title: Import über die API
description: ''
aliases:
- /en/connecting_your_tools/import_scan_files/api_pipeline_modelling
---

Die API von DefectDojo ermöglicht robuste Pipeline-Lösungen, die neue Scans automatisch in Ihre Instanz einlesen. Eine solche Automatisierung kann verschiedene Formen annehmen:

* ein täglicher Import, der Ihre Umgebung jeden Tag scannt und die Ergebnisse anschließend in DefectDojo importiert (ähnlich unserer Funktion **Connectors**)
* eine CI/CD-Pipeline, die neuen Code beim Deployment scannt und die Ergebnisse als ausgelöste Aktion in DefectDojo importiert

Solche Pipelines können Sie erstellen, indem Sie unseren API-Endpunkt **/reimport** direkt mit einer angehängten Scan-Datei aufrufen, ganz ähnlich wie über unser **Formular „Import Scan“**. 

## Die API von DefectDojo

Die API von DefectDojo ist mithilfe des OpenAPI-Frameworks direkt in der Anwendung dokumentiert. Sie erreichen diese Dokumentation über das Benutzermenü in der rechten oberen Ecke unter **‘API v2 OpenAPI3’**.

\- Mit der Dokumentation können Sie API-Aufrufe mit verschiedenen Parametern testen; dabei wird das API-Token Ihres eigenen Benutzers verwendet.

Wenn Sie ein API-Token für ein Skript oder eine andere Integration benötigen, finden Sie diese Information im selben Menü unter der Option **API v2 Token**.

![image](images/api_pipeline_modelling.png)

### Allgemeine Hinweise zur API

* Unsere OpenAPI-Dokumentation beschreibt die Parameter jedes Endpunkts detailliert, setzt jedoch voraus, dass die Leser die zentralen Konzepte von DefectDojo gut kennen (Produkthierarchie, Befunde, Deduplizierung usw.).
* Benutzer, die eine funktionierende Import-Integration wünschen, aber DefectDojo insgesamt weniger gut kennen, sollten unseren **Universal Importer** in Betracht ziehen.
* Die API von DefectDojo kann manchmal unbeabsichtigt Datenobjekte erstellen, insbesondere wenn ‘Auto\-Create Context’ am Endpunkt **/import** oder **/reimport** verwendet wird.
* Glücklicherweise ist es sehr schwierig, über die API versehentlich Daten zu löschen. Die meisten Objekte lassen sich nur mit einem eigenen **DELETE**-Aufruf an den betreffenden Endpunkt entfernen.

### Besondere Hinweise zu den Endpunkten /import und /reimport

Der Endpunkt **/reimport** kann sowohl für einen ersten Import als auch für einen „Reimport“ verwendet werden, der einen Test um weitere Befunde erweitert. Sie müssen nicht zuerst mit **/import** einen Test erstellen, bevor Sie den Endpunkt **/reimport** nutzen können. Solange ‘Auto Create Context’ aktiviert ist, kann der Endpunkt /reimport einen neuen Test, ein neues Engagement, ein neues Produkt oder einen neuen Produkttyp erstellen. In nahezu allen Fällen können Sie beim Hinzufügen von Daten über die API ausschließlich den Endpunkt **/reimport** verwenden.

Der Endpunkt **/import** kann stattdessen für eine Pipeline verwendet werden, in der Sie jedes Scan-Ergebnis immer in einem eigenen Test-Objekt ablegen möchten, anstatt mit **/reimport** die Unterschiede innerhalb eines einzigen Test-Objekts zu verarbeiten. Beide Varianten sind in Ordnung; welchen Endpunkt Sie wählen, hängt von Ihrer Berichtsstruktur ab oder davon, ob Sie einen einzelnen Durchlauf einer Pipeline gesondert betrachten müssen.

### Das Feld für das Scan-Abschlussdatum (API: `scan_date`) verwenden

DefectDojo unterstützt eine Vielzahl von Scanner-Berichten, aber nicht alle enthalten die für Benutzer wichtigsten Informationen. Das Feld `scan_date` ist eine flexible, intelligente Funktion, mit der Benutzer das Abschlussdatum eines bestimmten Scan-Berichts festlegen können, das dann an alle importierten Befunde weitergegeben wird.

Dieses Feld ist **nicht** verpflichtend; der Standardwert ist das Importdatum (also der Zeitpunkt, zu dem die Anfrage verarbeitet und eine erfolgreiche Antwort zurückgegeben wird).

Es gibt die folgenden Anwendungsfälle für dieses Feld und die daraus resultierenden Werte für den Test:

1. Wenn der Bericht das Datum **nicht** setzt und `scan_date` beim Import **nicht** gesetzt wird
    - Das Befund-Datum ist der Standardwert von `scan_date`
2. Wenn der Bericht das Datum **setzt** und `scan_date` beim Import **nicht** gesetzt wird
    - Das Befund-Datum ist das im Bericht angegebene Datum
3. Wenn der Bericht das Datum **nicht** setzt und `scan_date` beim Import **gesetzt** wird
    - Das Befund-Datum ist der vom Benutzer für `scan_date` festgelegte Wert
4. Wenn der Bericht das Datum **setzt** und `scan_date` beim Import **gesetzt** wird
    - Das Befund-Datum ist der vom Benutzer für `scan_date` festgelegte Wert
