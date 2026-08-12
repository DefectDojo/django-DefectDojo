---
title: ☑️ Checkliste für neue Benutzer
description: Erste Schritte mit DefectDojo
draft: 'false'
weight: 3
audience: opensource
---

Hier ist eine kurze Referenz, mit der Sie eine erfolgreiche Implementierung sicherstellen können, von der leeren Fläche bis zu einer voll funktionsfähigen App. Dieser Artikel setzt voraus, dass Sie **DefectDojo Community Edition** installiert haben und sie in Ihrer Umgebung läuft.

Das Wesen von DefectDojo besteht darin, Sicherheitsdaten zu importieren, sie zu organisieren und sie den Personen zu präsentieren, die sie kennen müssen. Hier sind Möglichkeiten, dies in DefectDojo Open-Source zu erreichen:

### DefectDojo Open-Source

1. Open-Source-Nutzer können damit beginnen, ihren ersten [Produkttyp und Produkt](/asset_modelling/os_hierarchy/product_hierarchy/) zu erstellen. Sobald diese erstellt sind, können sie über die UI [eine Datei importieren](/import_data/import_scan_files/os__import_scan_ui/) in eines dieser Produkte.

2. Nachdem Sie nun Daten in DefectDojo haben, sollten Sie erwägen, Ihr Produktlayout zu erweitern: [Übersicht über die Produkthierarchie](/asset_modelling/os_hierarchy/product_hierarchy/). Die Produkthierarchie erstellt ein Arbeitsinventar Ihrer Apps, das Ihnen hilft, Ihre Daten in logische Kategorien zu unterteilen. Diese Kategorien können verwendet werden, um Zugriffskontrollregeln anzuwenden oder Ihre Berichte an das richtige Team zu segmentieren.

3. Verwenden Sie den [Berichts-Builder](/metrics_reports/reports/using-the-report-builder/#opening-the-report-builder), um die von Ihnen importierten Daten zusammenzufassen. Berichte können verwendet werden, um Befunde schnell mit Stakeholdern wie Produktverantwortlichen zu teilen.

Das ist das Wesen von DefectDojo - Sicherheitsdaten importieren, organisieren und den Personen präsentieren, die sie kennen müssen.

All diese Funktionen können automatisiert werden, und da DefectDojo über 500 Tools verarbeiten kann (Stand dieses Textes), sollten Sie bestens gerüstet sein, um ein funktionierendes Sicherheitsinventar Ihrer gesamten Organisation zu erstellen.

### Open-Source-Funktionen
- Verwendet Ihre Organisation Jira? Erfahren Sie, wie Sie unsere [Jira-Integration](/connectors/os_jira/os__jira_guide/) nutzen können, um Jira-Tickets aus den von Ihnen importierten Daten zu erstellen.
- Erwarten Sie, DefectDojo mit vielen Benutzern in Ihrer Organisation zu teilen? Sehen Sie sich unsere Anleitungen zur [Benutzerverwaltung](/admin/user_management/about_perms_and_roles/) an und richten Sie eine rollenbasierte Zugriffskontrolle (RBAC) ein.
- Bereit, in die Automatisierung einzusteigen? Erfahren Sie, wie Sie die [DefectDojo-API](/import_data/import_scan_files/api_pipeline_modelling/) verwenden, um automatisch neue Daten zu importieren, und bauen Sie eine robuste CI/CD-Pipeline auf.