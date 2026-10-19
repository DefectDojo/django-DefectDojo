---
title: 'Asset-Hierarchie: Übersicht'
description: Organizations, Assets, Engagements, Tests und Findings verstehen
weight: 1
audience: opensource
aliases:
- /en/working_with_findings/organizing_engagements_tests/product_hierarchy
- /asset_modelling/os_hierarchy/product_hierarchy/
- /en/asset_modelling/os_hierarchy/product_hierarchy/
---

DefectDojo verwendet fünf Hauptdatenklassen zur Organisation Ihrer Arbeit: **Organizations, Assets**, **Engagements**, **Tests** und **Findings**.

DefectDojo ist so konzipiert, dass es sich flexibel an Ihr Team anpasst, anstatt Ihr Team an das Tool anzupassen. Sobald Sie verstehen, wie sich diese Datenklassen zur Organisation Ihrer Arbeit nutzen lassen, können Sie einen robusten, anpassungsfähigen Arbeitsbereich gestalten.

### Asset-Hierarchie-Diagramm
![image](images/Asset_Hierarchy_Full.png)


## **Organizations**

Die erste Datenkategorie, die Sie in DefectDojo einrichten müssen, ist eine Organisation. Organizations dienen dazu, Assets auf eine bestimmte Weise zu kategorisieren. Das kann sein:

* nach Geschäftsbereich
* nach Entwicklungsteam
* nach Sicherheitsteam

![image](images/Asset_Hierarchy_Overview.png)
*Assets werden gruppiert und unter ihrer Organization verschachtelt.*

Für Organizations können rollenbasierte Zugriffskontrollregeln (Role-Based Access Control) festgelegt werden, die einschränken, inwieweit Teammitglieder deren Daten einsehen und damit interagieren können (einschließlich aller zugrunde liegenden Assets mit Engagement-, Test- und Finding-Daten). Weitere Informationen zu Benutzerrollen finden Sie in unserem Artikel **Einführung in Rollen**.

#### Wofür kann eine Organization stehen?

* Wenn ein bestimmtes Softwareprojekt viele unterschiedliche Deployments oder Versionen hat, kann es sinnvoll sein, eine einzelne Organization anzulegen, die den gesamten Projektumfang abdeckt, wobei jede Version als eigenes Asset existiert.
​
* Sie können Organizations auch verwenden, um Phasen Ihres Softwareentwicklungsprozesses abzubilden: eine Organization für 'In Development', eine Organization für 'In Production' usw.
​
* Letztendlich liegt es bei Ihnen, wie Sie Ihre Assets organisieren möchten und wofür Ihre Organizations stehen sollen. Ihre DefectDojo-Hierarchie muss möglicherweise angepasst werden, um den Anforderungen Ihrer Sicherheitsteams gerecht zu werden.

## **Assets**

Ein **Asset** in DefectDojo steht für ein beliebiges Projekt, Programm oder eine Anwendung, das bzw. die Sie gerade testen. Das Asset enthält die gesamte Sicherheitsarbeit und den Testverlauf zum jeweiligen Ziel.

![image](images/Asset_Hierarchy_Overview_2.png)

* einen eindeutigen **Namen**
* eine **Beschreibung**
* eine **Organization**
* eine zugewiesene **SLA-Konfiguration**

Assets können in ihrem Umfang so weit gefasst oder so spezifisch sein, wie Sie möchten. Standardmäßig sind Assets vollständig eigenständige Objekte innerhalb der Hierarchie, können aber über eine **Organization** gruppiert werden.

Assets sind voneinander „abgeschottet" und interagieren nicht mit anderen Assets. Die intelligenten Funktionen von DefectDojo, wie zum Beispiel die **Deduplizierung**, gelten jeweils nur innerhalb eines einzelnen Assets.

Wie bei **Organizations** können auch für **Assets** rollenbasierte Zugriffskontrollregeln festgelegt werden, die einschränken, inwieweit Teammitglieder sie einsehen und damit interagieren können (sowie alle zugrunde liegenden Engagement-, Test- und Finding-Daten). Weitere Informationen zu Benutzerrollen finden Sie in unserem Artikel **Einführung in Rollen**.

#### Wofür kann ein Asset stehen?

Das Konzept eines „Assets" in DefectDojo entspricht nicht zwangsläufig 1:1 dem, was Ihre Organization als „Produkt" bezeichnen würde. Softwareentwicklung ist komplex, und die Sicherheitsanforderungen können selbst innerhalb einer einzelnen Software stark variieren.

Die folgenden Szenarien sind gute Gründe, ein separates DefectDojo-Asset in Betracht zu ziehen:

* „**ExampleAsset**" hat eine Windows-Version, eine Mac-Version und eine Cloud-Version
* „**ExampleAsset 1\.0**" verwendet völlig andere Softwarekomponenten als „**ExampleAsset 2\.0**", und beide Versionen werden von Ihrem Unternehmen aktiv unterstützt.
* Das Team, das für die Arbeit an „**ExampleAsset Version A**" zuständig ist, unterscheidet sich von dem Asset-Team, das für „**ExampleAsset Version B**" zuständig ist, und benötigt daher unterschiedliche zugewiesene Sicherheitsberechtigungen.

Diese Variationen innerhalb eines einzelnen Assets können auch auf Engagement-Ebene gehandhabt werden. Beachten Sie, dass Engagements nicht über eine Zugriffskontrolle verfügen wie Assets und Organizations.

## **Engagements**

Sobald ein Asset eingerichtet ist, können Sie mit dem Erstellen und Planen von Engagements beginnen. Engagements sollen Zeitpunkte abbilden, zu denen Tests stattfinden, und enthalten einen oder mehrere **Tests**.

Engagements haben immer:

* einen eindeutigen **Namen**
* geplante **Start- und Enddaten**
* einen **Status** (Not Started, In Progress, Cancelled, Completed...)
* eine zugewiesene **Testing Lead**
* ein zugehöriges **Asset**

Es gibt zwei Arten von Engagements: **Interactive** und **CI/CD**.

* Ein **Interactive Engagement** wird typischerweise von einem Engineer durchgeführt. Interactive Engagements konzentrieren sich darauf, die Anwendung während der Laufzeit zu testen, sei es durch einen automatisierten Test, einen menschlichen Tester oder jede andere Aktivität, die mit der Anwendungsfunktionalität „interagiert". Siehe [OWASPs Definition von IAST](https://owasp.org/www-project-devsecops-guideline/latest/02c-Interactive-Application-Security-Testing#:~:text=Interactive%20Application%20Security%20Testing,interacting%E2%80%9D%20with%20the%20application%20functionality.).
* Ein **CI/CD Engagement** dient der automatisierten Integration mit einer CI/CD-Pipeline. CI/CD Engagements sollen Daten als automatisierte Aktion importieren, ausgelöst durch einen Schritt im Release-Prozess.

Engagements können über die **Kalender**-Ansicht von DefectDojo verfolgt werden.

#### Wofür kann ein Engagement stehen?

Engagements sollen Gruppen zusammengehöriger Testaktivitäten abbilden. Wie Sie Ihre Testaktivitäten gruppieren möchten, hängt von Ihrem Ansatz ab.

Wenn Sie eine geplante Testaktivität terminiert haben, bietet Ihnen ein Engagement einen Ort, um alle zugehörigen Ergebnisse zu speichern. Hier ist ein Beispiel für diese Art von Engagement:

#### **Engagement:** ExampleSoftware 1\.5\.2 \- Interactive Testing Effort

*In diesem Beispiel führt ein Sicherheitsteam im Rahmen eines Software-Releases mehrere Tests am selben Tag durch.*

* **Test:** Nessus Scan Results (12. März)
* **Test:** NPM Scan Audit Results (12. März)
* **Test:** Snyk Scan Results (12. März)
​
Sie können auch CI/CD-Testergebnisse innerhalb eines Engagements organisieren. Diese Art von Engagements ist „Open-Ended", das heißt, sie haben kein Datum und erhalten stattdessen jedes Mal zusätzliche Daten, wenn die zugehörigen CI/CD-Aktionen ausgeführt werden.

#### Engagement: ExampleSoftware CI/CD Testing

*In diesem Beispiel werden bei jeder Erstellung eines neuen Software-Releases automatisch mehrere CI/CD-Scans als Tests importiert.*

* Test: 1\.5\.2 Scan Results (12. März)
* Test: 1\.5\.1 Scan Results (3. März)
* Test: 1\.5\.0 Scan Results (14. Februar)

Engagements können so organisiert werden, wie es für Ihr Team am besten funktioniert. Alle einem Asset untergeordneten Engagements können von dem Team eingesehen werden, das für die Arbeit an diesem Asset zuständig ist.

## **Tests**

Tests sind eine Gruppierung von Aktivitäten, die von Engineers durchgeführt werden, um Schwachstellen in einem Asset aufzudecken.

Tests haben immer:

* einen eindeutigen **Test Title**
* einen bestimmten **Test Type** (API Test, Nessus Scan usw.)
* eine zugehörige Test-**Umgebung**
* ein zugehöriges **Engagement**

Tests können auf unterschiedliche Weise erstellt werden. Sie können automatisch erstellt werden, wenn Scan-Daten direkt in ein Engagement importiert werden, wodurch ein neuer Test mit den Scan-Daten entsteht. Tests können auch im Vorgriff auf die Planung zukünftiger Engagements erstellt werden oder für manuell erfasste Sicherheitsbefunde, die nachverfolgt und behoben werden müssen.

### **Test Types**

DefectDojo unterstützt zwei Kategorien von Test Types:

1. **Parser-basierte Test Types**: Diese entsprechen bestimmten Sicherheitsscannern, die ihre Ausgabe in Formaten wie XML, JSON oder CSV erzeugen. Beim Importieren von Scan-Ergebnissen verwendet DefectDojo spezialisierte Parser, um die Scanner-Ausgabe in Findings umzuwandeln.

2. **Non-parser Test Types**: Diese werden für manuell erstellte Findings verwendet, die nicht aus Scan-Dateien importiert wurden. Diese Test Types nutzen die Methode [Generic Findings Import](/supported_tools/parsers/generic_findings_import/), um Findings und Metadaten darzustellen.

Die folgenden Test Types erscheinen im Dropdown-Menü „Scan Type", wenn Sie einen neuen Test erstellen.
   * API Test
   * Static Check
   * Pen Test
   * Web Application Test
   * Security Research
   * Threat Modeling
   * Manual Code Review

Non-parser Test Types sollten verwendet werden, wenn Sie manuell Findings erstellen müssen, die behoben werden müssen, aber nicht aus einer automatisierten Scanner-Ausgabe stammen.

#### **Parser-basierte Test Types**

Parser-basierte Test Types lassen sich danach kategorisieren, wie ihr Testtypname ermittelt wird:

- **Feste Testtypnamen**: Der Testtypname ist vordefiniert und vor dem Import bekannt (z. B. „ZAP Scan", „Nessus Scan").

- **Report-definierte Testtypnamen**: Der Testtypname wird zum Zeitpunkt des Imports aus dem Inhalt des Scan-Reports extrahiert.

Beispiele dafür sind:
  - **Generic Findings Import**: Erstellt Test Types basierend auf dem Feld `type` in JSON-Reports
  - **SARIF**: Erstellt Test Types basierend auf Tool-Namen im SARIF-Report (z. B. „Dockle Scan (SARIF)")
  - **OpenReports**: Erstellt für jede im Report gefundene Quelle einen separaten Test Type

**Regeln für report-definierte Testtypnamen:**
- Wenn das Feld `type` des Reports dem Scan-Typ entspricht → wird der Scan-Typ direkt verwendet (z. B. „Generic Findings Import")
- Wenn das Feld `type` des Reports abweicht → wird das Format „{type} Scan ({scan_type})" erzeugt (z. B. „Tool1 Scan (Generic Findings Import)")
- Wenn das Feld `type` des Reports bereits mit dem Suffix „ ({scan_type})" endet → wird es unverändert übernommen, sodass das Suffix nie doppelt vorkommt (z. B. bleibt „Tool1 (Generic Findings Import)" als „Tool1 (Generic Findings Import)" erhalten)
- Wenn kein Feld `type` angegeben ist → wird der Scan-Typ direkt verwendet

**Wichtige Hinweise:**
- Report-definierte Test Types werden automatisch erstellt, wenn beim Import oder Reimport ein neuer Typ erkannt wird.
- Bei Reimports muss der Testtypname exakt übereinstimmen - Abweichungen führen zu einem Validierungsfehler
- Die Deduplizierungseinstellungen (`HASHCODE_FIELDS_PER_SCANNER`) verwenden Testtypnamen als Schlüssel. Report-definierte Namen müssen daher entsprechend konfiguriert werden, wenn Sie ein individuelles Deduplizierungsverhalten wünschen

#### **Wie interagieren Tests miteinander?**

Tests fassen Ihre Testdaten zu Findings zusammen. In der Regel führen Sicherheitsteams dieselbe Testaktivität wiederholt durch, und Tests in DefectDojo ermöglichen es Ihnen, diesen Prozess elegant zu handhaben.

**Bereits importierte Tests können reimportiert werden** \- Wenn Sie denselben Testtyp innerhalb desselben Engagement-Kontexts ausführen, können Sie die Testergebnisse nach jedem abgeschlossenen Scan reimportieren. DefectDojo vergleicht die reimportierten Daten mit dem vorhandenen Ergebnis und erstellt keine neuen Findings, wenn in den Scan-Daten Duplikate vorhanden sind.

**Tests können separat importiert werden** \- Wenn Sie denselben Test für ein Asset innerhalb separater Engagements ausführen, vergleicht DefectDojo die Daten trotzdem mit vorherigen Tests, um doppelte Findings zu finden. Auf diese Weise behalten Sie den Überblick über zuvor behobene oder als Risiko akzeptierte Findings.

Wenn ein Test direkt zu einem Asset ohne Engagement hinzugefügt wird, wird automatisch ein generisches Engagement erstellt, das den Test enthält. Dies ermöglicht Ad\-hoc-Datenimporte.

**Beispiele für Tests:**

* Burp Scan vom 29.10.2015 bis 29.10.2015
* Nessus Scan vom 31.10.2015 bis 31.10.2015
* API Test vom 15.10.2015 bis 20.10.2015

## **Findings**

Sobald Daten zu einem Test hochgeladen wurden, werden die Ergebnisse dieser Daten im Test als einzelne **Findings** zur Überprüfung aufgelistet.

Ein Finding stellt eine bestimmte Schwachstelle dar, die beim Testen entdeckt wurde.

Findings haben immer:

* einen eindeutigen **Finding Name**
* das **Datum**, an dem sie entdeckt wurden
* mehrere zugehörige **Status**, wie zum Beispiel Active, Verified oder False Positive
* einen zugehörigen **Test**
* einen **Severity**-Level: Critical, High, Medium, Low und Informational (Info).

Findings können durch einen Datenimport hinzugefügt werden, aber auch manuell zu einem Test hinzugefügt werden.

**Beispiele für Findings:**

* OpenSSL ‘ChangeCipherSpec’ MiTM Potential Vulnerability
* Web Application Potentially Vulnerable to Clickjacking
* Web Browser XSS Protection Not Enabled

## **Endpoints**

Scan-Daten enthalten in der Regel Verweise auf die Hosts oder Endpoints, die von einem bestimmten Finding betroffen sind. DefectDojo aggregiert Findings automatisch pro Endpoint, sodass Sie über die Endpoint-Ansicht alle Findings einsehen können, die einen bestimmten Endpoint oder Hostnamen betreffen.

Beispiele:
-   https://www.example.com
-   https://www.example.com:8080/products
-   192.168.0.36
