---
title: 📊 Liste der Pro-Funktionen
description: Liste der Pro-Funktionen in DefectDojo
draft: 'false'
weight: 4
chapter: true
exclude_search: true
audience: pro
aliases:
- /en/about_defectdojo/pro_features
---

Nachfolgend finden Sie eine Liste der zahlreichen zusätzlichen Funktionen von DefectDojo Pro, zusammen mit Links zur Dokumentation, in der Sie sie in Aktion sehen können:

## Verbesserte Benutzererfahrung

### Pro-Benutzeroberfläche

Die Benutzeroberfläche von DefectDojo wurde in DefectDojo Pro überarbeitet, um schneller, funktionaler, vollständig anpassbar zu sein und die Navigation durch Datenmengen auf Unternehmensniveau zu erleichtern.  Sie enthält außerdem einen Dark Mode.
Weitere Informationen finden Sie in unserem [Leitfaden zur Pro-Benutzeroberfläche](/get_started/about/ui_pro_vs_os/).

![image](images/enabling_deduplication_within_an_engagement_2.png)

### Globale Suche

Finden Sie jeden Befund, jedes Asset, jedes Engagement und mehr über ein einziges Suchfeld in der oberen Leiste. Die globale Suche von DefectDojo Pro durchsucht Ihre Objekte mit einer schnellen, tippfehlertoleranten Postgres-Volltextsuche.

Weitere Informationen finden Sie in unserem [Leitfaden zur globalen Suche](/navigation/pro__global_search/).

### Assets/Organisationen

DefectDojo Pro ermöglicht eine verbesserte organisatorische Visualisierung für große Listen von Repositorys oder andere Geschäftsstrukturen.  Details finden Sie in der [Dokumentation zu Assets/Organisationen](/asset_modelling/pro_hierarchy/asset_hierarchy/).

![image](images/asset_hierarchy_diagram.png)

### Befundpriorität

DefectDojo Pro kann Ihre Befunde vorab nach Priorität und Risiko triagieren, sodass Ihr Team Ihre kritischsten Probleme zuerst identifizieren und beheben kann.
Weitere Details finden Sie in unserem [Leitfaden zur Befundpriorität](/asset_modelling/pro_hierarchy/priority_sla/).

### Rules Engine

Mit der Rules Engine von DefectDojo Pro können Sie automatisierte Massenaktionen skripten und individuelle Workflows zur Handhabung von Befunden und anderen Objekten erstellen – Programmierkenntnisse sind nicht erforderlich.

Weitere Informationen finden Sie in unserem [Leitfaden zur Rules Engine](/automation/rules_engine/about).

![image](images/rules_engine_4.png)

### Sensei

**Sensei** (BETA) von DefectDojo Pro ist eine KI-gestützte Scan-and-Fix-Funktion: Verbinden Sie ein Repository über eine GitHub App, und Sensei scannt es, importiert die Befunde und erstellt Pull Requests, die diese beheben — mit einem Preview-First-Workflow, sodass nichts ausgeführt wird (und keine LLM-Kosten anfallen), bevor Sie zustimmen.

Weitere Informationen finden Sie in unserem [Sensei-Leitfaden](/sensei/about_sensei/).

### Pro-Dashboards und -Reporting

Erstellen Sie [sofortige Berichte und Metriken](/get_started/about/ui_pro_vs_os/#new-dashboards), um den Sicherheitsstatus Ihrer Anwendungen und Repositorys darzustellen, Ihre Sicherheitstools zu bewerten und die Leistung Ihres Teams bei der Behebung von Sicherheitsproblemen zu analysieren.

Die Grafiken auf der Startseite können als SVG-Dateien exportiert werden, und die zur Erstellung der Grafiken verwendeten Daten können ebenfalls als Tabelle exportiert werden.

Darüber hinaus enthält DefectDojo Pro mehrere neue [Insights-Dashboards](/metrics_reports/pro_metrics/pro__overview/), die erweiterte Metriken für verschiedene Zielgruppen Ihres Sicherheitsprogramms bieten.

### Deduplizierungs-Tuning

Erweiterte Deduplizierungseinstellungen ermöglichen es Ihnen, genau festzulegen, wie DefectDojo doppelte Befunde erkennt und verwaltet. Passen Sie die Deduplizierung innerhalb eines Tools, **toolübergreifend** und beim Reimport an, um eine präzise Zuordnung zwischen allen von Ihnen gewählten Sicherheitstools und Schwachstellenbefunden zu erreichen.

Weitere Informationen finden Sie in unserem [Leitfaden zum Deduplizierungs-Tuning](/triage_findings/finding_deduplication/pro__deduplication_tuning/).

![image](images/deduplication_tuning.png)

## Optimierter Import

### Weitere Importoptionen

DefectDojo Pro umfasst vier zusätzliche Importmethoden: [Universal Importer](/import_data/pro/specialized_import/external_tools/), [Upstream Connectors](/connectors/upstream/about/), [Universal Parser](/supported_tools/parsers/universal_parser/) und [Smart Upload](/import_data/pro/specialized_import/smart_upload/).

![image](images/pro_import_methods.png)


### Hintergrundimporte

Für Berichte auf Unternehmensniveau bietet DefectDojo Pro eine optimierte Upload-Methode, die Befunde im Hintergrund verarbeitet.

### CLI-Tools

Erstellen Sie schnell eine Kommandozeilen-Pipeline, um Daten mit unseren Anwendungen Universal Importer und DefectDojo-CLI in Ihre DefectDojo Pro-Instanz zu importieren, erneut zu importieren und zu exportieren – ohne API-Skripting (verfügbar für Windows, Macintosh oder Linux).

Weitere Informationen finden Sie in unserem [Leitfaden zu externen Tools](/import_data/pro/specialized_import/external_tools/).

### Upstream Connectors

DefectDojo kann sich sofort mit Scan-Tools auf Unternehmensniveau verbinden, um neue Befunddaten zu importieren, und erstellt so eine automatisierte Import-Pipeline, die ohne die Einrichtung von API-Aufrufen oder Cronjobs sofort einsatzbereit ist.

Weitere Informationen finden Sie in unserem [Leitfaden zu Upstream Connectors](/connectors/upstream/about/).

![image](images/add_edit_connectors_2.png)

Zu den unterstützten Tools für Upstream Connectors gehören:

* Anchore
* AWS Security Hub
* BurpSuite
* Checkmarx ONE
* Dependency-Track
* Probely
* Semgrep
* SonarQube
* Snyk
* Tenable
* Wiz

### Universal Parser (Beta)

Wenn Sie ein nicht unterstütztes oder angepasstes Scan-Tool verwenden oder sich einfach wünschen, dass DefectDojo einen Bericht etwas anders verarbeitet, nutzen Sie den Universal Parser von DefectDojo Pro, um jeden .json- oder .csv-Bericht in einen verwertbaren Satz von Befunden umzuwandeln. Ihr Parser parst und mappt die Daten genau so, wie Sie es möchten.

Weitere Informationen finden Sie in unserem [Leitfaden zum Universal Parser](/import_data/pro/specialized_import/universal_parser//).

![image](images/universal_parser_3.png)

## Verwaltung optionaler Funktionen

Viele der oben genannten Funktionen sind optional und werden hinter einem Feature-Flag ausgeliefert, sodass Sie sie übernehmen können, wenn Sie bereit dafür sind. Ein Superuser kann die meisten davon direkt unter **Settings > Feature Flags** aktivieren und deaktivieren, ohne den Support kontaktieren zu müssen.

Im Leitfaden zu [Feature Flags](/admin/feature_flags/pro__feature_flags/) erfahren Sie, wie Sie eine Funktion aktivieren und warum eine Funktion je nach Ihrem Installationstyp gesperrt oder nicht verfügbar sein könnte.

## Support

DefectDojo Pro-Abonnements beinhalten erstklassigen Support sowohl für On-Premise- als auch für Cloud-Installationen.  Unser Team steht Ihnen zur Verfügung, um Ihrer Organisation bei der Implementierung und optimalen Nutzung von DefectDojo Pro zu helfen.  Ihr Abonnement umfasst:

- **Umfassender Support**: Unbegrenzte Support-Tickets und Plätze stehen zur Verfügung, um Ihr gesamtes Team zu unterstützen.
- **Dedizierter Engineering-Fokus**: Von Benutzern gemeldete Probleme, Fehler und Funktionswünsche erhalten von unserem Engineering-Team bevorzugte Aufmerksamkeit.
- **SaaS-Management**: Wir übernehmen Monitoring, Wartung und Backups für alle SaaS-Instanzen.
