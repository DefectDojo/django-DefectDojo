---
title: Assets
description: Assets in DefectDojo Pro verstehen
audience: pro
weight: 2
---

Organisationen → **ASSETS** → Engagements → Tests → Befunde

## Überblick

**Assets** stehen im Mittelpunkt der Organisation der Sicherheitsarbeit innerhalb der Objekthierarchie von DefectDojo. Assets repräsentieren jedes Projekt, Programm, jede Software oder jeden physischen Vermögenswert, den Ihr Sicherheitsteam testet, und bündeln die gesamte Sicherheitsarbeit und Testhistorie im Zusammenhang mit dem jeweiligen Testziel. Beispiele für Assets sind unter anderem:
- Software-Releases
- Software von Drittanbietern
- Virtuelle Maschinen oder Assets in der Produktion
- Eine einzelne Anwendung
- Ein Microservice
- Eine API
- Eine SaaS-Plattform
- Eine mobile App
- Ein internes System
- Ein Geschäftsservice
- Eine kundenorientierte Plattform
- Eine Cloud-Umgebung oder ein Infrastrukturbereich

Im Allgemeinen sollte ein Asset das „Ding“ repräsentieren, dessen Sicherheitslage Sie im Zeitverlauf nachverfolgen möchten. Dazu gehören die zugehörige Testhistorie, Befunde, Metriken, Zuständigkeiten, Integrationen und Behebungs-Workflows im Zusammenhang mit diesem „Ding“.

### Asset-Beispiele

Assets können je nach den Anforderungen Ihrer Organisation noch feiner granuliert werden. Beispielsweise könnten Sie in folgenden Szenarien separate DefectDojo-Assets erstellen:

- „ExampleAsset“ hat eine Windows-Version, eine Mac-Version und eine Cloud-Version
- „ExampleAsset 1.0“ verwendet völlig andere Softwarekomponenten als „ExampleAsset 2.0“, und beide Versionen werden von Ihrem Unternehmen aktiv unterstützt.
- Das Team, das an „ExampleAsset Version A“ arbeitet, unterscheidet sich von dem Asset-Team, das an „ExampleAsset Version B“ arbeitet, und benötigt infolgedessen andere Sicherheitsberechtigungen.

Sie können diese Varianten zwar auch als Engagements innerhalb eines einzelnen Assets abbilden, RBAC kann jedoch nur auf Ebene von Assets oder Organisationen festgelegt werden, was den Zugriff der Benutzer auf das passende Engagement (sowie die Tests und Befunde innerhalb dieser Engagements) einschränken kann, wenn sie so organisiert sind. Weitere Informationen zu RBAC und Berechtigungen in DefectDojo finden Sie [hier](/admin/user_management/about_perms_and_roles/).

## Asset-Daten

Assets enthalten immer die folgenden Komponenten:

- **Organisation**
- **Eindeutiger Name**
- **Beschreibung**
- **SLA-Konfiguration**
- **Priorisierungs-Engine**

Optionale Asset-Metadaten umfassen:

- **Tags**
- **Geschäftskritikalität**
- **Benutzerdatensätze** (d. h. die geschätzte Anzahl der Benutzerdatensätze im Asset)
- **Umsatz**
- **Personalinformationen** (z. B. Asset-Manager, Team-Manager, technischer Ansprechpartner usw.)
- **Vorschriften** (z. B. HIPAA, GLBA, OPPA usw.)
- **Plattform** (z. B. API, Desktop, IoT, Mobil, Web usw.)
- **Lebenszyklus** (z. B. Aufbau, Produktion, Außerbetriebnahme usw.)
- **Herkunft** (z. B. Drittanbieter-Bibliothek, Gekauft, Open Source usw.)

Diese Metadaten verbessern das Filtern, Berichten und Priorisieren in Ihrem gesamten Sicherheitsprogramm. Noch wichtiger ist jedoch, dass Assets auch alle Engagements, Tests und Befunde enthalten, die mit den Testaktivitäten rund um dieses Asset zusammenhängen. Alle Befunde aus Tests werden letztlich auf Asset-Ebene zusammengeführt, was langfristiges Tracking, Trendanalysen und Berichte ermöglicht.

## Zugriff auf Assets

Assets sind über die Seitenleiste zugänglich. Das Untermenü bietet Zugriff auf die [Asset-Hierarchie](/asset_modelling/engagements_tests/pro__assets/#asset-nesting) und Alle Assets sowie die Möglichkeit, ein neues Asset zu erstellen.

![image](images/assets_ss1.png)

### Berechtigungen

Auf Assets können rollenbasierte Zugriffskontrollregeln (RBAC) angewendet werden, die die Möglichkeit der Teammitglieder einschränken, sie anzuzeigen und mit ihnen zu interagieren.

Berechtigungen werden nach unten vererbt, das heißt, der Zugriff auf ein Asset gewährt automatisch Zugriff auf alle darin enthaltenen Objekte (z. B. Engagements, Tests und Befunde).

Weitere Informationen zu Benutzerrollen finden Sie in unserem Artikel [Einführung in Rollen](/admin/user_management/set_user_permissions/#introduction-to-permission-types).

## Asset-Ansicht

Asset-Ansichten enthalten eine Vielzahl von Tabellen und Diagrammen, mit denen sich der Status eines Assets auf einen Blick erfassen lässt. Dazu gehören:

- **Schweregrad offener Befunde**
    - Eine Liste der offenen Befunde innerhalb des Assets, gruppiert nach Schweregrad
- **Asset-Übersicht**
    - Eine Aufschlüsselung verschiedener Merkmale des Assets, einschließlich Beschreibung, Komponenten, Kontakte, [Benutzergruppen](/admin/user_management/create_user_group/
), Mitglieder, Technologien und Vorschriften.
        - Technologien: next.js, vue.js, npm v.1.2.3, Django, nginx, Hugo
- **Metadaten**
    - Einschließlich übergeordneter und untergeordneter Assets, Organisation, Geschäftskritikalität, Umsatz und weiterer Details aus den Einstellungen des Assets.
- **Service Level Agreement nach Schweregrad**
    - Wendet die SLA-Konfiguration des Assets aus den Einstellungen auf die Befunde innerhalb des Assets an.
- **Aufschlüsselung des Befund-Schweregrads**
    - Ein Diagramm der Befunde innerhalb des Assets, organisiert nach Schweregrad.
- **Befundverteilung**
    - Eine Aufschlüsselung der Befunde innerhalb des Assets, organisiert nach Status (z. B. Aktiv, Behoben, Statisch und Dynamisch)
- **Alle Engagements**
    - Eine Liste der im Asset enthaltenen Engagements.

## Arbeiten mit Assets

### Assets erstellen

Es gibt zwei Möglichkeiten, Assets zu erstellen:

- Über die Option **Neues Asset** im Seitenmenü
- Über die Schaltfläche **Neues Asset** oben in der Liste „Alle Assets“

## Assets bearbeiten

Assets können bearbeitet werden, indem Sie im Zahnrad-Menü oben rechts in der Asset-Ansicht auf **Asset bearbeiten** klicken. Auf dasselbe Menü können Sie auch über das ⋮-Kebab-Menü links neben dem Asset in der Ansicht „Alle Assets“ zugreifen.

Alle daraufhin bearbeitbaren Felder stehen auch bei der Erstellung des Assets zur Verfügung.

![image](images/assets_ss2.png)

### Assets löschen

Um ein Asset zu löschen, wählen Sie **Asset löschen** in den Einstellungen des Assets aus. Diese Aktion kann nicht rückgängig gemacht werden. Assets können nicht geschlossen und später wieder geöffnet werden.

Beim Löschen eines Assets werden außerdem folgende Elemente gelöscht:
- Alle im Asset enthaltenen Engagements und Tests
- Der gesamte zugehörige Sicherheitsverlauf, einschließlich Befunde und Integrationen
- Alle verknüpften Jira-Epics
- Alle Notizen und Datei-Uploads im Zusammenhang mit den Engagements und Tests des Assets

## Asset-Grenzen

### Deduplizierung

Assets sind „abgeschottet“ und interagieren nicht mit anderen Assets. Die intelligenten Funktionen von DefectDojo, wie zum Beispiel die Deduplizierung, gelten nur im Kontext eines einzelnen Assets. Befunde aus unterschiedlichen Assets werden nicht automatisch dedupliziert.

### Berichte und Metriken

Die meisten Berichte und Metriken aggregieren Daten auf Asset-Ebene, wodurch Assets die primäre Einheit für die Messung und Nachverfolgung von Risiken darstellen.

Infolgedessen werden viele wichtige Kennzahlen pro Asset berechnet, darunter:

- Gesamtzahl der Befunde (nach Schweregrad oder Status)
- Mittlere Behebungszeit (MTTR)
- SLA-Einhaltungs- und Verletzungsraten
- Risikotrends im Zeitverlauf

Das bedeutet, dass die Struktur der Assets die Genauigkeit und den Nutzen von Berichten direkt beeinflusst. Wenn beispielsweise mehrere nicht zusammenhängende Systeme unter einem einzigen Asset zusammengefasst werden, kann dies die Risikotransparenz verringern, während eine zu feingranulare Asset-Struktur die Berichterstattung fragmentieren und die Erkennung übergreifender Trends erschweren kann.

### Connectors

In DefectDojo Pro werden Connectors verschiedenen Assets zugeordnet, wodurch sie zum primären Integrationspunkt zwischen DefectDojo und Ihrem umfassenderen Sicherheits-Ökosystem werden.

Sobald ein Connector mit einem Asset verknüpft wurde, importiert er Scan-Ergebnisse und erstellt oder aktualisiert Engagements, Tests und Befunde innerhalb dieses Assets.

Weitere Informationen zu Connectors finden Sie [hier](/connectors/upstream/about/#main-content).

### CI/CD-Pipelines

CI/CD-Pipelines automatisieren den Import von Scan-Ergebnissen. Unabhängig von der Integrationsmethode muss jeder Scan-Import einem Asset zugeordnet sein, wodurch das Asset zum Ankerpunkt für pipeline-gesteuerte Sicherheitsdaten wird.

Wenn eine Pipeline Scan-Ergebnisse übermittelt, muss sie entweder:

- Ein bestehendes Asset angeben (und optional ein Engagement), oder
- So konfiguriert sein, dass Ergebnisse konsistent dem richtigen Asset zugeordnet werden

Alle importierten Befunde übernehmen den Kontext des Assets, einschließlich Zuständigkeit, Berechtigungen, Priorität-/Risikokonfiguration und Berichtsumfang.

In der Praxis sollten Assets so definiert werden, dass sie widerspiegeln, wie Systeme innerhalb von CI/CD aufgebaut und bereitgestellt werden, um sicherzustellen, dass Sicherheitsergebnisse konsistent der richtigen Anwendung oder dem richtigen Service zugeordnet werden.

### SLAs, Priorität und Risiko

In DefectDojo Pro übernehmen Befunde ihre SLA-Ziele, Priorität und ihr Risiko von dem Asset, das sie enthält. Asset-Metadaten (z. B. Geschäftskritikalität, Umsatz usw.) werden verwendet, um Prioritäts- und Risikowerte automatisch zu berechnen.

Das bedeutet, dass dieselbe Schwachstelle je nachdem, ob sie ein internes Entwicklungssystem oder ein Produktions-Asset betrifft, das kritische Geschäftsabläufe unterstützt, eine unterschiedliche Prioritäts- oder Risikobewertung erhalten kann.

### Jira-/Downstream-Connector-Beziehungen

Assets können direkt mit [Jira](/connectors/downstream/pro__jira_guide/#main-content)- oder [Integrators](/connectors/toolreference/downstream/#main-content)-Instanzen (z. B. GitHub, GitLab, ServiceNow usw.) verknüpft werden, die die Befunde des Assets nach außen in externe Ticketing-/Work-Management-Systeme übertragen.

Da Befunde Risiko, Priorität und Zuständigkeit von ihrem übergeordneten Asset übernehmen, bestimmt das Asset effektiv den Behebungskontext, der in Jira-Tickets und Downstream-Connector-Workflows einfließt.

Wichtig ist außerdem, dass Assets der wichtigste bestimmende Faktor für die SLA-Eigenschaften eines Befunds sind. Der SLA eines Befunds hängt daher von der SLA-Konfiguration seines übergeordneten Assets ab. Weitere Informationen zu SLA-Konfigurationen finden Sie [hier](/asset_modelling/pro_hierarchy/priority_sla/#working-with-slas).

## Asset-Verschachtelung

DefectDojo unterstützt eine übergeordnet-untergeordnet-Beziehung zwischen zwei Assets innerhalb derselben Organisation. Dies kann bei der Erstellung des Assets oder in dessen Einstellungen konfiguriert werden.

Sie können die Struktur der Assets in DefectDojo visualisieren und Beziehungen mithilfe der Option **Asset-Hierarchie** in der Seitenleiste ändern.

Nachdem Sie die zu visualisierenden Assets in der entsprechenden Tabelle ausgewählt haben, klicken Sie auf **Asset-Hierarchie anzeigen**, um ein Flussdiagramm der Beziehung zwischen den gewählten Assets zu erstellen, sofern vorhanden.

Weitere Informationen zu den Auswirkungen der Asset-Verschachtelung auf Deduplizierung, RBAC und weitere Details sowie Beispielanwendungsfälle finden Sie [hier](/asset_modelling/pro_hierarchy/asset_hierarchy/#asset-nesting-examples).
