---
title: ❓ Häufig gestellte Fragen
description: Häufig gestellte Fragen zu DefectDojo
draft: 'false'
weight: 2
chapter: true
aliases:
- /de/en/about_defectdojo/faq
---

Hier finden Sie einige häufig gestellte Fragen zur Arbeit mit DefectDojo – sowohl in DefectDojo Pro als auch in DefectDojo OS.

## Allgemeine Fragen

### Wie sollte ich meine Sicherheitstests in DefectDojo organisieren?

DefectDojo kann zwar jede Sicherheits- oder Testumgebung unterstützen, aber das Sicherheitsteam und die Abläufe sehen bei jedem anders aus, weshalb es keinen Ansatz gibt, der für alle passt. Wir haben einen sehr ausführlichen Artikel zu [gängigen Anwendungsfällen](/get_started/common_use_cases/common_use_cases/) mit Beispielen, wie verschiedene Organisationen RBAC und das Datenmodell von DefectDojo einsetzen, um ihre Anforderungen zu erfüllen.

### Welche Workflows werden für Sicherheitstests in DefectDojo empfohlen?

DefectDojo soll die zentrale verlässliche Quelle für den Sicherheitsstatus Ihrer Organisation sein und kann je nach den Anforderungen Ihrer Organisation unterschiedliche Zwecke erfüllen, zum Beispiel:

- Benutzern ermöglichen, doppelte Befunde über Scans und Tools hinweg zu identifizieren und so die Alarmmüdigkeit zu verringern.
- SLAs für Sicherheitslücken durchsetzen und sicherstellen, dass Ihre Organisation jeden Befund innerhalb eines angemessenen Zeitrahmens bearbeitet.
- [Tickets senden](/connectors/issue_tracking/) an Jira, ServiceNow oder andere Projektverfolgungssoftware, sodass Ihr Entwicklungsteam die Behebung von Problemen in seinen Standard-Release-Prozess integrieren kann, ohne ein weiteres Projektmanagement-Tool erlernen zu müssen.
- Integration in automatisierte [CI/CD-Pipelines](/import_data/import_scan_files/api_pipeline_modelling/), um Berichtsdaten aus Repositories automatisch zu übernehmen, bis hinunter auf Branch-Ebene.
- Erstellen von [Berichten](/metrics_reports/reports/) zu einer beliebigen Menge von Sicherheitslücken oder Softwarekontext, um Scan-Ergebnisse oder Statusaktualisierungen schnell mit Stakeholdern zu teilen.
- Einrichten von Akzeptanz- und Behebungs-Workflows zur Unterstützung eines formalen Risikomanagement-Trackings.


DefectDojo ist darauf ausgelegt, Ihren aktuellen Sicherheits-Workflow zu unterstützen und zu standardisieren. All diese Methoden können genutzt werden, um die Prozesse Ihres Teams zu verbessern und sich an Ihre aktuelle Arbeitsweise anzupassen.

### Welche Funktionen sind in DefectDojo Pro verfügbar?

DefectDojo Pro erweitert die oben genannten Workflows und ergänzt:

- Eine [verbesserte Benutzeroberfläche](/get_started/about/ui_pro_vs_os/), die für Geschwindigkeit und Effizienz bei der Navigation durch Datenmengen im Enterprise-Umfang ausgelegt ist. Sie enthält auch einen Dark Mode.
- Die Möglichkeit, Ihre Befunde [vorab zu triagieren](/asset_modelling/pro_hierarchy/priority_sla/) nach Priorität und Risiko, damit Ihr Team zuerst die kritischsten Probleme identifizieren und beheben kann.
- Eine [Rules Engine](/automation/rules_engine/about), um automatisierte Massenaktionen zu skripten und eigene Workflows für die Verwaltung von Befunden und anderen Objekten zu erstellen – ohne Programmiererfahrung.
- [Erweiterte Funktionen zur Erstellung von Berichten und Metriken](/get_started/about/ui_pro_vs_os/#new-dashboards), um den Sicherheitsstatus Ihrer Apps und Repos einfach zu teilen.
- [Erweiterte Deduplizierungseinstellungen](/triage_findings/finding_deduplication/pro__deduplication_tuning/), um fein abzustimmen, wie DefectDojo doppelte Befunde erkennt und verwaltet.
- Optimierte Importfunktionen, wie zum Beispiel: 
  - Eine optimierte Upload-Methode, die Befunde im Hintergrund verarbeitet.
  - Die Möglichkeit, mit unseren Universal-Importer- und DefectDojo-CLI-Anwendungen schnell eine [Kommandozeilen-Pipeline](/import_data/pro/specialized_import/external_tools/) aufzubauen, mit der Sie Daten einfach in Ihre DefectDojo-Pro-Instanz importieren, reimportieren und exportieren können.
  - Ein [Universal Parser](/import_data/pro/specialized_import/universal_parser/), um jeden .json- oder .csv-Bericht in eine verwertbare Menge von Befunden umzuwandeln, wobei DefectDojo Pro die Daten so verarbeitet, wie Sie es wünschen.
  - [Connectors](/connectors/upstream/about/), die eine sofortige Verbindung zu unterstützten Tools herstellen, um neue Befundsdaten zu importieren, sodass Sie eine automatisierte Import-Pipeline einrichten können, ohne API-Aufrufe oder Cronjobs konfigurieren zu müssen.

### Wie handhabt DefectDojo die Zugriffskontrolle?

DefectDojo kann von großen Teams genutzt werden, und die Einrichtung von [RBAC (Rule Based Access Control)](/admin/user_management/about_perms_and_roles/) wird dringend empfohlen, um sowohl den passenden Kontext für jedes Teammitglied festzulegen als auch den Zugriff auf bestimmte Teile der Infrastruktur zu steuern.

Die Zuweisung von Rollen und Berechtigungen erfolgt in der Regel auf Ebene von Produkttyp / Produkt. Jedes Teammitglied kann einem oder mehreren Produkten oder Produkttypen zugewiesen werden und erhält eine Rolle, die regelt, wie es mit den darin enthaltenen Schwachstellendaten interagieren kann (nur Lesen, Lesen/Schreiben oder volle Kontrolle). Weitere Informationen finden Sie in unserem [RBAC-Leitfaden](/admin/user_management/about_perms_and_roles/).

### Wie handhabt DefectDojo die Zugriffskontrolle für ein Team von Benutzern?

Ob Sie ein Ein-Personen-Sicherheitsteam für eine kleine Organisation sind oder als CISO eine Vielzahl von Softwareprojekten überwachen: Sie können problemlos [Role-Based Access Control (RBAC)](/admin/user_management/about_perms_and_roles/) einrichten, um für jedes Teammitglied den passenden Kontext festzulegen und den Zugriff auf bestimmte Teile der Infrastruktur zu steuern.

In der Regel erfolgt die Zuweisung von Rollen und Berechtigungen auf [Produkttyp-/Produktebene](/asset_modelling/os_hierarchy/product_hierarchy/). Jedes Teammitglied kann eine Rolle für ein oder mehrere Produkte oder Produkttypen erhalten, die regelt, wie es mit den darin enthaltenen Schwachstellendaten interagieren kann (z. B. nur Lesen, Lesen/Schreiben oder volle Kontrolle). 

## Import-Workflows

### Welche Tools werden von DefectDojo unterstützt?

DefectDojo unterstützt Berichte von [über 500](/supported_tools/) kommerziellen und Open-Source-Sicherheitstools.

Wenn Sie Ihrer Toolsammlung ein neues Tool hinzufügen möchten, finden Sie [hier](https://defectdojo.com/blog/announcing-the-defectdojo-open-source-security-awards) eine Liste empfohlener Open-Source-Tools.

### Was ist der Unterschied zwischen Import und Reimport?

Es gibt zwei verschiedene Methoden, um einen einzelnen Bericht aus einem Sicherheitstool zu importieren:

- **Import** behandelt den Bericht als einzelnen Datensatz zu einem bestimmten Zeitpunkt. Beim Importieren eines Berichts wird ein Test erstellt, der die resultierenden Befunde enthält.
- **[Reimport](/import_data/import_intro/reimport/)** wird verwendet, um einen bestehenden Test mit einem neuen Satz von Ergebnissen zu aktualisieren. Bei einem offeneren Testprozess können Sie fortlaufend die neueste Version Ihres Berichts in einen bestehenden Test reimportieren. DefectDojo vergleicht die Ergebnisse des eingehenden Berichts mit Ihren vorhandenen Daten, erfasst alle Änderungen und passt anschließend die Befunde im Test an den aktuellsten Bericht an.

Um den Unterschied zu verstehen, hilft es, sich Import als das Erfassen eines einzelnen Scan-Ereignisses vorzustellen und Reimport als das Aktualisieren eines fortlaufenden Scan-Protokolls.

Hier eine Analogie: Wären Sie Buchhalter, könnten Sie Import verwenden, um einen einzelnen Beleg zu erfassen, während Sie Reimport nutzen würden, um ein fortlaufendes Ausgabenbuch zu führen.

Beide Methoden nutzen die Deduplizierung außerdem unterschiedlich: Während zwei separate importierte Tests im selben Produkt doppelte Befunde jeweils eigenständig erkennen und kennzeichnen, erstellt Reimport innerhalb des Tests keine Befunde, die es als [Duplikate](/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport/) identifiziert.

Grundsätzlich gilt: Wenn Sie einen Bericht zu einem bestimmten Zeitpunkt benötigen, ist Import die beste Methode. Wenn Sie fortlaufend Berichte aus einem Tool ausführen und einlesen, ist Reimport die bessere Methode, um alles organisiert zu halten.

### Wie kann ich Importfehler beheben?

DefectDojo unterstützt eine große Vielfalt an Tools. Wenn Sie beim Importieren eines Berichts inkonsistentes Verhalten feststellen, empfehlen wir zu prüfen, ob die Dateistruktur den Erwartungen des Tools entspricht. In unserer [Parser-Liste](/supported_tools/) können Sie bestätigen, dass Ihr Tool unterstützt wird, und prüfen, ob das Dateiformat den Erwartungen des Tools entspricht. Sie können die Struktur auch mit unseren Unit-Tests vergleichen.

DefectDojo Pro verfügt über eine Universal-Parser-Importmethode, mit der Sie beliebige JSON-, CSV- oder XML-Dateien verarbeiten können. DefectDojo-OS-Benutzer können für denselben Zweck eigene Parser schreiben.

Schließlich ist bekannt, dass sich Berichtsformate von Drittanbietern ohne Vorwarnung ändern können: Unsere OS-Community freut sich sehr über [PRs und Beiträge](/get_started/contributing/how-to-write-a-parser/), um unsere Parser aktuell zu halten.

### Wie sollte ich große Scan-Dateien handhaben?

Das Importieren eines großen Berichts in DefectDojo kann ein langwieriger Prozess sein. Berichte mit 2MB enthalten erhebliche Datenmengen, deren Umwandlung in Befunde je nach Berichtsformat des Sicherheitstools lange dauern kann.

Wir empfehlen, große Berichte vor dem Import aufzuteilen, um unterschiedliche Teilbereiche der verfügbaren Daten abzubilden. Wenn Ihr Sicherheitstool Ergebnisse nach Softwareprojekt, Anwendung oder anderem Kontext filtern kann, erleichtert der Export kleinerer Berichte es DefectDojo, die Daten zu verarbeiten und zu kategorisieren. Das hat außerdem den Vorteil, dass Ihre Befunde proaktiv anhand der Aufteilung der Daten organisiert werden, was eine relevantere und schnellere Berichtserstellung ermöglicht.

DefectDojo Pro kann Berichte im Hintergrund verarbeiten. Dateien müssen jedoch weiterhin hochgeladen und von DefectDojo validiert werden, bevor der Prozess zur Erstellung von Befunden im Hintergrund beginnen kann.

### Wie verbinde ich eine CI/CD-Pipeline mit DefectDojo?

Viele der Kernfunktionen von DefectDojo können vollständig automatisiert werden.  CI/CD (oder jede Art von automatisiertem Import) kann durch Aufrufe der [DefectDojo REST API](/import_data/import_scan_files/api_pipeline_modelling/) abgewickelt werden.

**DefectDojo-Pro**-Benutzer haben außerdem Zugriff auf die **Universal Importer / DefectDojo CLI** [Kommandozeilen-Tools](/import_data/pro/specialized_import/external_tools/), die sich in vielen automatisierten Umgebungen installieren und ausführen lassen.

## Verwaltung von Befunden

### Was bedeutet der Status eines Befunds?

Befunde können viele Status haben. Ein Status von Aktiv oder Inaktiv ist bei einem Befund immer gesetzt, während andere Status wie Verifiziert, Falsch-positiv oder Außerhalb des Geltungsbereichs nach eigenem Ermessen angewendet werden können.

Diese Status werden ausführlicher in unserem Leitfaden [Definitionen der Befund-Status](/triage_findings/findings_workflows/finding_status_definitions/) beschrieben, zusammen mit Informationen darüber, wie sie verwendet werden können.
 
### Wie kann ich Befunde aus DefectDojo löschen?

Generell empfehlen wir, geschlossene Befunde als „Inaktiv“ beizubehalten, anstatt sie vollständig zu löschen, da es in der AppSec-Arbeit wichtig ist, historische Aufzeichnungen zu bewahren. Das Löschen eines Befunds entfernt sämtliche Notizen und die Metrik-Erfassung zu diesem Befund unwiderruflich, was zu ungenauen Berichten oder einem unvollständigen Archiv führen kann.

Befunde können auf verschiedene Arten aus DefectDojo gelöscht werden:
- Durch Ausführen einer [Massenlöschung](/triage_findings/findings_workflows/editing_findings/#bulk-delete-findings)-Aktion für die Befunde, die Sie löschen möchten
- Durch Aufrufen von `DELETE /findings/{id}` über die API
- Durch Löschen eines übergeordneten Objekts, z. B. eines Tests, Engagements, Produkttyps oder Produkts.
  - Beachten Sie, dass untergeordnete Objekte nicht unabhängig von ihrem übergeordneten Objekt erhalten bleiben: Das Löschen eines übergeordneten Objekts wie eines Produkttyps löscht alle Produkte, Engagements, Tests, Befunde und Endpunkte innerhalb dieses Produkttyps. Umgekehrt bleiben beim Löschen eines Engagements die vorangehenden Produkte und Produkttypen erhalten.

## Reporting und Jira

### Wie kann ich einen Bericht in DefectDojo erstellen?

Mit dem [Report Builder](/metrics_reports/reports/) können Sie schnell einen individuellen Bericht in DefectDojo erstellen.

DefectDojo-Pro-Benutzer haben außerdem Zugriff auf [Metrik-Dashboards auf Executive-Ebene](/get_started/about/ui_pro_vs_os/#new-dashboards), die in Echtzeit über Produkttypen, Produkte oder andere Daten berichten können.

### Wie kann ich ein Projektmanagement-Tool mit DefectDojo integrieren?

Sowohl in der Pro- als auch in der Open-Source-Edition von DefectDojo können Befunde als Issues an Jira übergeben werden, sodass Sie die Behebung von Problemen mit Ihrem Entwicklungsteam integrieren können.

DefectDojo Pro fügt Unterstützung für [Zusätzliche Projektverfolgungs-Integrationen](/connectors/issue_tracking/)** hinzu: ServiceNow, Azure DevOps, GitHub und GitLab.
