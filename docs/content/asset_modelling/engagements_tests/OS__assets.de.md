---
title: Assets
description: Assets in DefectDojo OS verstehen
audience: opensource
weight: 2
aliases:
- /asset_modelling/engagements_tests/os__products/
- /en/asset_modelling/engagements_tests/os__products/
---

Organizations → **ASSETS** → Engagements → Tests → Befunde

## Überblick

**Assets** stehen im Zentrum der Art und Weise, wie Sicherheitsarbeit innerhalb der Objekthierarchie von DefectDojo organisiert wird. Assets repräsentieren jedes Projekt, Programm, jede Software oder jedes physische Objekt, das Ihr Sicherheitsteam testet, und beherbergen die gesamte Sicherheitsarbeit und Testhistorie im Zusammenhang mit diesem Testziel. Beispiele für Assets sind unter anderem:
- Software-Releases
- Drittanbieter-Software
- Virtuelle Maschinen oder Assets in Produktion
- Eine einzelne Anwendung
- Ein Microservice
- Eine API
- Eine SaaS-Plattform
- Eine mobile App
- Ein internes System
- Ein Geschäftsservice
- Eine kundenorientierte Plattform
- Eine Cloud-Umgebung oder Infrastrukturdomäne

Im Allgemeinen sollte ein Asset das „Ding" repräsentieren, dessen Sicherheitslage Sie im Zeitverlauf verfolgen möchten. Dazu gehören die zugehörige Testhistorie, Befunde, Kennzahlen, Zuständigkeiten, Integrationen und Remediation-Workflows im Zusammenhang mit diesem „Ding".

### Asset-Beispiele

Assets können je nach den Anforderungen Ihrer Organisation noch granularer werden. Beispielsweise könnten Sie in folgenden Szenarien in Erwägung ziehen, separate DefectDojo-Assets zu erstellen:

- „ExampleAsset" hat eine Windows-Version, eine Mac-Version und eine Cloud-Version
- „ExampleAsset 1.0" verwendet völlig andere Softwarekomponenten als „ExampleAsset 2.0", und beide Versionen werden von Ihrem Unternehmen aktiv unterstützt.
- Das Team, das an „ExampleAsset Version A" arbeitet, unterscheidet sich vom Asset-Team, das an „ExampleAsset Version B" arbeitet, und benötigt daher unterschiedliche Sicherheitsberechtigungen.

Sie können diese Varianten zwar auch als Engagements innerhalb eines einzigen Assets abbilden, RBAC lässt sich jedoch nur auf Ebene von Assets oder Organizations festlegen, was den Zugriff der Benutzer auf das jeweilige Engagement (sowie die Tests und Befunde innerhalb dieser Engagements) einschränken kann, wenn sie so organisiert sind. Weitere Informationen zu RBAC und Berechtigungen in DefectDojo finden Sie [hier](/admin/user_management/about_perms_and_roles/).

## Asset-Daten

Assets enthalten immer die folgenden Komponenten:

- **Eindeutiger Name**
- **Beschreibung**
- **Organization**
- **SLA-Konfiguration**

Optionale Asset-Metadaten umfassen:

- **Tags**
- **Personalinformationen** (z. B. Asset Manager, Team Manager, technischer Kontakt usw.)
- **Vorschriften** (z. B. HIPAA, GLBA, OPPA usw.)
- **Geschäftskritikalität**
- **Plattform** (z. B. API, Desktop, IoT, Mobil, Web usw.)
- **Lebenszyklus** (z. B. Aufbau, Produktion, Außerbetriebnahme usw.)
- **Herkunft** (z. B. Drittanbieter-Bibliothek, gekauft, Open Source usw.)
- **Benutzerdatensätze** (d. h. die geschätzte Anzahl der Benutzerdatensätze im Asset)
- **Umsatz**

Diese Metadaten verbessern das Filtern, die Berichterstattung und die Priorisierung innerhalb Ihres Sicherheitsprogramms. Noch wichtiger ist jedoch, dass Assets auch alle Engagements, Tests und Befunde enthalten, die sich auf die Testaktivitäten rund um dieses Asset beziehen. Alle Befunde aus Tests werden letztlich auf Asset-Ebene aggregiert, was langfristiges Tracking, Trendanalysen und Berichterstattung ermöglicht.

## Zugriff auf Assets

Assets sind über die Seitenleiste zugänglich. Das Untermenü bietet außerdem die Möglichkeit, ein neues Asset zu erstellen.

![image](images/asset_ss3.png)

### Berechtigungen

Auf Assets können Role-Based-Access-Control-Regeln (RBAC) angewendet werden, die die Möglichkeit der Teammitglieder einschränken, sie anzuzeigen und mit ihnen zu interagieren.

Berechtigungen werden nach unten vererbt, das heißt, der Zugriff auf ein Asset gewährt automatisch Zugriff auf alle Objekte innerhalb dieses Assets (z. B. Engagements, Tests und Befunde).

Weitere Informationen zu Benutzerrollen finden Sie in unserem [Artikel zur Einführung in Rollen](/admin/user_management/about_perms_and_roles/).

## Asset-Ansicht

Asset-Ansichten enthalten eine Vielzahl von Tabellen und Diagrammen, um den Status eines Assets auf einen Blick zu erfassen. Dazu gehören:

- **Metadaten**
    - Einschließlich Organization, Geschäftskritikalität, Umsatz und weiterer Details, die über die Asset-Einstellungen hinzugefügt wurden.
- **Metriken**
    - Eine Liste offener Befunde innerhalb des Assets, gruppiert nach Schweregrad
- **Service Level Agreement nach Schweregrad**
    - Wendet die SLA-Konfiguration des Assets aus den Einstellungen auf die Befunde innerhalb des Assets an.
- **Technologien**
    - Z. B. next.js, vue.js, npm v.1.2.3, Django, nginx, Hugo
- **Vorschriften**
- **Benchmark-Fortschritt**
- **Mitglieder**
- **Gruppen**
- **Kontakte**
- **Benachrichtigungen**
    - Schaltet Benachrichtigungen je nach bestimmten Ereignissen ein oder aus (z. B. wenn ein Engagement hinzugefügt oder geschlossen wurde)

## Arbeiten mit Assets

### Assets erstellen

Es gibt mehrere Möglichkeiten, ein neues Asset zu erstellen, unter anderem:

- Die Schaltfläche **Add Asset** in der Liste „All Assets"

![image](images/asset_ss2.png)

- Über das Dropdown-Menü der Assets-Tabelle innerhalb der Ansicht einer Organization
    - Dadurch wird das Asset automatisch innerhalb dieser Organization erstellt.

![image](images/asset_ss1.png)

- Die Schaltfläche **Add Asset** in der Seitenleiste

![image](images/asset_ss5.png)

### Assets bearbeiten

Ein Asset kann über seine Einstellungen bearbeitet werden, auf die Sie auf zwei Arten zugreifen können:

- Die Schaltfläche **Edit** im ⋮-Kebab-Menü links neben dem Asset in der Ansicht „All Assets"

![image](images/asset_ss6.png)

- Die Schaltfläche **Edit** im Dropdown-Menü **Settings** in der Ansicht des Assets

![image](images/asset_ss7.png)

### Assets löschen

Die Option zum Löschen eines Assets finden Sie unten in denselben Menüs, die im obigen Abschnitt **Assets bearbeiten** beschrieben sind. Diese Aktion kann nicht rückgängig gemacht werden. Ein Asset kann nicht geschlossen und später wieder geöffnet werden.

Beim Löschen eines Assets werden auch die folgenden Elemente gelöscht:
- Alle im Asset enthaltenen Engagements und Tests
- Der gesamte zugehörige Sicherheitsverlauf, einschließlich Befunde und Integrationen
- Alle verknüpften Jira Epics
- Alle Notizen und Datei-Uploads, die den Engagements und Tests des Assets zugeordnet sind

## Asset-Grenzen

### Deduplizierung

Assets sind „abgeschottet" und interagieren nicht mit anderen Assets. Die Smart Features von DefectDojo, wie z. B. Deduplication, gelten nur innerhalb des Kontexts eines einzelnen Assets. Befunde in unterschiedlichen Assets werden nicht automatisch dedupliziert.

### Metriken

Die meisten Berichte und Kennzahlen aggregieren Daten auf Asset-Ebene, wodurch Assets die primäre Einheit zur Messung und Verfolgung von Risiken darstellen.

Infolgedessen werden viele wichtige Kennzahlen pro Asset berechnet, darunter:

- Gesamtzahl der Befunde (nach Schweregrad oder Status)
- Mittlere Zeit bis zur Behebung (MTTR)
- SLA-Einhaltungs- und Verstoßraten
- Risikotrends im Zeitverlauf

Das bedeutet, dass die Struktur der Assets sich direkt auf die Genauigkeit und den Nutzen von Berichten auswirkt. Wenn beispielsweise mehrere nicht zusammenhängende Systeme unter einem einzigen Asset zusammengefasst werden, kann dies die Risikotransparenz beeinträchtigen, während zu granulare Asset-Strukturen die Berichterstattung fragmentieren und es erschweren können, umfassendere Trends zu erkennen.

Asset-spezifische Kennzahlen sind über die Schaltfläche **Metrics** in der oberen Leiste der Ansicht des ausgewählten Assets zugänglich.

![image](images/asset_ss8.png)

### CI/CD-Pipeline

CI/CD-Pipelines automatisieren den Import von Scan-Ergebnissen. Unabhängig von der Integrationsmethode müssen alle Scan-Importe einem Asset zugeordnet werden, wodurch das Asset zum Ankerpunkt für pipelinegesteuerte Sicherheitsdaten wird.

Wenn eine Pipeline Scan-Ergebnisse übermittelt, muss sie entweder:

- Ein bestehendes Asset (und optional ein Engagement) angeben, oder
- So konfiguriert sein, dass Ergebnisse konsistent dem richtigen Asset zugeordnet werden

Alle importierten Befunde übernehmen den Kontext des Assets, einschließlich Zuständigkeit, Berechtigungen, SLA-Konfiguration und Berichtsumfang.

In der Praxis sollten Assets so definiert werden, dass sie widerspiegeln, wie Systeme innerhalb von CI/CD gebaut und bereitgestellt werden, damit Sicherheitsergebnisse konsistent der richtigen Anwendung oder dem richtigen Service zugeordnet werden.

### Jira-Beziehungen

Assets können direkt Jira Projects zugeordnet werden, die die Befunde des Assets in eine Jira-Instanz übertragen.

Da Befunde Risiko, Priorität und Zuständigkeit von ihrem übergeordneten Asset erben, bestimmt das Asset faktisch den Remediation-Kontext, der in Jira-Tickets und Downstream-Connector-Workflows einfließt.

Wichtig ist außerdem, dass Assets auch der wichtigste Faktor für die SLA-Eigenschaften eines Befunds sind. Die SLA eines Befunds hängt daher von der SLA-Konfiguration seines übergeordneten Assets ab. Weitere Informationen zu SLA-Konfigurationen finden Sie [hier](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content).
