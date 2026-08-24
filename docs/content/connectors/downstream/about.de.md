---
title: Downstream Connectors
weight: 1
audience: pro
aliases:
- /de/en/share_your_findings/integrations
- /de/issue_tracking/pro_integration/integrations/
---

**Verfügbarkeit:** Downstream Connectors sind für jede DefectDojo Pro-Instanz allgemein verfügbar und aktiv, sowohl Cloud als auch On-Premise. Es gibt nichts zu aktivieren, und sie werden auf der Seite „Feature Flags" nicht mehr aufgeführt.

Mit Downstream Connectors können Sie Ihre Findings und Finding Groups an Ticket-Tracking-Systeme übertragen, um die Behebung von Sicherheitsproblemen einfach in den bestehenden Entwicklungsworkflow Ihres Teams zu integrieren.

Unterstützte Downstream Connectors:
- Azure Devops
- Bitbucket
- Freshservice
- GitHub
- GitLab Boards
- Jira
- Linear
- Opsgenie
- PagerDuty
- ServiceDesk Plus
- ServiceNow
- ServiceNow SecOps / Vulnerability Response
- Shortcut
- Zendesk

## Öffnen der Seite „Downstream Connectors"

Die Seite „Downstream Connectors" finden Sie in der Seitenleiste unter **Import > Connectors > Downstream Connectors**.

![Bild](images/integrators_3.png)

## Einrichten eines Downstream Connectors

Ein Downstream Connector wird mit drei Hauptkomponenten konfiguriert:

- **Integration Instance**: Dies ist die primäre Verbindungsmethode, die DefectDojo für ein Drittsystem verwendet. Die Instance enthält Angaben wie eine Bezeichnung, einen Speicherort und Zugangsdaten für die Verbindung sowie alle weiteren vom Anbieter benötigten Informationen.
- **Issue Tracker Mapping**: Hier werden die Mapping-Informationen gespeichert - sie legen fest, welche Details für die Verbindung zu einem bestimmten "Projekt" beim Anbieter erforderlich sind. Diese Details umfassen den Namen oder die ID des "Projekts" sowie die Zuordnung von Finding-Schweregrad und -Status zum entsprechenden Feld im "Ticket" des Anbieters. Sie können mehrere Mappings konfigurieren, wenn Sie Findings an mehrere "Projekt"-Standorte übertragen möchten.
- **Issue Tracker Assignment**: Hier werden DefectDojo-Produkte und -Engagements einem bestimmten Issue Tracker Mapping zugewiesen, mit Optionen je Produkt/Engagement, die festlegen, wie ein Finding an ein bestimmtes Anbietersystem übertragen wird.

Diese Komponenten sind hierarchisch aufgebaut: Jede **Instance** hat eine oder mehrere **Mappings**, die wiederum eine oder mehrere **Tracker Assignments** haben.

![Bild](images/integrators_2.png)

## Übertragen von Findings und Finding Groups

Sobald diese Komponenten konfiguriert sind, können Findings und Finding Groups auf zwei Arten an einen Issue Tracker gesendet werden; manuell oder automatisch.

- **Manuell**: Findings und Finding Groups in einem Produkt/Engagement mit einem zugewiesenen **Issue Tracker Mapping** verfügen über die Option "Push to Integrator". Dadurch wird im Issue Tracker ein Issue mit den entsprechenden Informationen zum Finding/zur Finding Group erstellt. Push to Integrator kann auch verwendet werden, um ein bestehendes Issue zu aktualisieren.

### Findings automatisch übertragen

Findings können auch automatisch übertragen werden, wobei das **Issue Tracker Assignment** bestimmt, wie diese Objekte übertragen werden. Es gibt vier Optionen:

- **Only Explicitly Publish Changes to Target**: Diese Option deaktiviert jedes automatische Verhalten im zugewiesenen Produkt oder Engagement. Ein Finding oder eine Finding Group kann dann nur wie oben beschrieben explizit übertragen werden.
- **Automatically Link New Finding to Target**: Wenn im zugewiesenen Produkt oder Engagement neue Findings oder Finding Groups **erstellt** werden, überträgt DefectDojo das Objekt automatisch an den Issue Tracker. Nach der Erstellung werden diese Findings oder Finding Groups nur durch eine manuelle Push-to-Integrator-Aktion aktualisiert.
- **Automatically Update Existing Link on Finding Edit**: Wenn Findings oder Finding Groups im zugewiesenen Produkt oder Engagement **aktualisiert** werden, wird das Objekt automatisch an den Issue Tracker übertragen, sofern bereits manuell eine Verknüpfung erstellt wurde.
- **Automatically Link New and Update Existing Link on Finding Edit**: Wenn Findings oder Finding Groups im zugewiesenen Produkt oder Engagement erstellt **oder** aktualisiert werden, wird das Objekt automatisch an den Issue Tracker übertragen.

#### Push-Filter

Jedes Issue Tracker Assignment kann optional eingrenzen, welche Findings **automatisch** übertragen werden:

- **Minimum Severity**: Erstellt automatisch nur Tickets für Findings mit dem ausgewählten Schweregrad oder höher. Leer lassen, um jeden Schweregrad einzubeziehen.
- **Active findings only**: Erstellt automatisch nur Tickets für aktive Findings und überspringt solche, die bereits als Mitigated, False Positive oder Risk Accepted markiert sind, wenn das Assignment sie zum ersten Mal sieht.

Diese Filter gelten nur für die automatische **Erstellung**. Aktualisierungen an einem Finding, das bereits ein verknüpftes Ticket hat, werden immer gesendet, sodass Statusänderungen (einschließlich Schließungen) weiterhin übertragen werden. Ein manueller **Push to Integrator** ignoriert die Filter immer. Belassen Sie beide bei ihren Standardwerten, bleibt das ursprüngliche Verhalten erhalten, bei dem jedes Finding übertragen wird.

#### Mehrere Produkte zuweisen

Ein Issue Tracker Assignment zielt auf ein einzelnes Produkt oder Engagement ab. Um mehrere Assets abzudecken, erstellen Sie ein Assignment pro Produkt (oder Engagement). Wenn zusätzlich anbieterspezifische Felder je Asset unterschiedlich sein sollen — etwa eine abweichende ServiceNow **Assignment group** oder **Assigned to**, oder ein anderes Jira-Projekt — erstellen Sie für jedes Asset ein eigenes Issue Tracker Mapping (mit eigenen Custom Field Mappings) und weisen Sie jedes Assignment dem passenden Mapping zu.

## Darstellung von Issue-Tracker-Tickets

Issue-Tracker-Tickets werden beim Anzeigen und Auflisten von
Findings und Finding Groups durch eine Reihe von Symbolen in der Spalte "Integrator Tickets" dargestellt

Symbole von links nach rechts:

- **Integration Type**: Der Typ des Issue Trackers, mit dem das Ticket verknüpft ist
- **Ticket ID**: Die ID des Tickets, wie vom Issue Tracker definiert
- **Ticket Link**: Der direkte Link zum Ticket, wie vom Issue Tracker definiert
- **Changelog**: Gibt an, wann das Issue-Tracker-Ticket mit einem Finding oder einer Finding Group verknüpft wurde, sowie den Zeitpunkt der letzten Änderung des Tickets durch DefectDojo

![Bild](images/integrators_1.png)

## Anbieterspezifische Anforderungen

Jeder Anbieter hat unterschiedliche Anforderungen daran, wie DefectDojo mit ihm interagieren muss. Dies kann in Form eines Authentifizierungsmechanismus, zusätzlicher Felder je "Projekt" oder Schweregrad-/Status-Zuordnungen erfolgen.

Die vollständige Liste der Anforderungen finden Sie auf den folgenden anbieterspezifischen Seiten:

- [Azure Devops](/connectors/toolreference/azure_devops_boards/)
- [Bitbucket](/connectors/toolreference/bitbucket/#downstream-connector)
- [Freshservice](/connectors/toolreference/freshservice/)
- [GitHub](/connectors/toolreference/github/#downstream-connector)
- [GitLab Boards](/connectors/toolreference/gitlab/#downstream-connector)
- [Jira](/connectors/toolreference/jira/)
- [Linear](/connectors/toolreference/linear/)
- [Opsgenie](/connectors/toolreference/opsgenie/)
- [PagerDuty](/connectors/toolreference/pagerduty/)
- [ServiceDesk Plus](/connectors/toolreference/servicedesk_plus/)
- [ServiceNow](/connectors/toolreference/servicenow/)
- [ServiceNow SecOps / Vulnerability Response](/connectors/toolreference/servicenow_secops/)
- [Shortcut](/connectors/toolreference/shortcut/)
- [Zendesk](/connectors/toolreference/zendesk/)

## Fehlerbehandlung und Debugging

Downstream Connectors können aus verschiedenen Gründen Fehler verursachen, etwa Konnektivität, Authentifizierung, Berechtigungen usw. Um die Fehlersuche
zu erleichtern, verfügt jedes Issue Tracker Mapping über eine Fehlertabelle, die anzeigt, wann der Fehler aufgetreten ist, aus welchem Grund er
aufgetreten ist, und welches Finding oder welche Finding Group nicht übertragen werden konnte.

Diese Fehler finden Sie auf der Seite „All Issue Tracker Mappings & Assignments" in der Spalte ⚠️ Total Errors.

![Bild](images/integrators_4.png)

Ein Klick auf den Eintrag Total Errors führt Sie zu einer Seite mit ausführlicheren Beschreibungen der Fehler zu diesem Downstream Connector.

### Alle Fehlschläge an einem Ort sehen

Die Fehlertabelle je Mapping deckt einen Downstream Connector ab. [Diagnostics](/admin/diagnostics/pro__diagnostics/) deckt alle davon ab, zusammen mit jedem anderen Integrationsversuch auf der Instanz — Upstream Connectors, Imports, Jira, SSO und die Rules Engine — mit derselben Filter- und Sortierfunktion über alles hinweg.

Verwenden Sie sie, wenn die Frage über ein einzelnes Mapping hinausgeht:

* ein Versuch, der **nie abgeschlossen** wurde statt fehlzuschlagen, was keine Fehlertabelle meldet, weil kein Fehler aufgetreten ist
* ob ein Fehlschlag auf eine Integration beschränkt ist oder gleichzeitig bei mehreren auftritt
* wer oder was einen Versuch ausgelöst hat, und gegen welche Konfiguration

In einem Fehler zitierte Zugangsdaten werden entfernt, bevor die Zeile gespeichert wird, und die vollständigen technischen Details sind auf Superuser beschränkt.

## Seitenlayout „Downstream Connectors"

Downstream Connectors werden in zwei Abschnitten aufgeführt, **Configured Connectors** und **Available Connectors**, jeweils alphabetisch sortiert mit einer Anzahl der angezeigten Einträge neben der Überschrift. Ein Tool kann mehrere Konfigurationen enthalten; jede ist eine eigene Kachel, betitelt mit `<Tool> - <label>`, sortiert nach Bezeichnung. Die Kachel **Request Downstream Connector** auf DefectDojo Pro Cloud wird nicht mitgezählt.
