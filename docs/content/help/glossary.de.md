---
title: Glossar
weight: 1
---

Im Folgenden finden Sie ein einfaches Glossar, das Ihnen hilft, die verschiedenen Funktionen von DefectDojo zu verstehen. Es zeigt außerdem an, ob die jeweilige Funktion in der Pro-Version von DefectDojo, der OS-Version oder in beiden verfügbar ist.

## Produkthierarchie (Beide)
Das Strukturmodell zur Organisation von Sicherheitsdaten in DefectDojo, bestehend aus Organisationen → Assets → Engagements → Tests → Befunde.
## Organisation (Beide)
Ein hierarchisches Objekt der obersten Ebene, das als übergeordnetes Objekt von Assets in DefectDojo Pro dient. Es bietet einen gemeinsamen Kontext für Governance, Zugriffskontrolle und Reporting über alle untergeordneten Assets hinweg.
## Asset (Beide)
Ein eigenständiges Objekt, das eine bereitstellbare oder logische Systemeinheit (z. B. Anwendung, Host, Umgebung) innerhalb von Organisationen darstellt. Assets unterstützen in der Pro-Version übergeordnete/untergeordnete Beziehungen und umfangreichere Geschäftsmetadaten, unterstützen jedoch in der OS-Version keine übergeordneten/untergeordneten Beziehungen.
### Asset-Hierarchie (Pro)
Ein Modell übergeordneter/untergeordneter Beziehungen zwischen Assets, das die Vererbung von Kontext und die Aggregation von Befunden ermöglicht.
## Engagement (Beide)
Eine abgegrenzte Sicherheitsaktivität, die ein Testfenster, eine Pipeline oder einen Bewertungskontext darstellt.
## Test (Beide)
Eine einzelne Ausführung eines Scanners oder einer manuellen Bewertung innerhalb eines Engagements. Tests speichern Ausführungsmetadaten und dienen als Erfassungspunkt für Befunde.
## Service (Beide)
Ein optionales Unterobjekt, mit dem Befunde einer bestimmten Komponente oder Schnittstelle innerhalb eines Assets zugeordnet werden. Services sind in OS DefectDojo am nützlichsten, da ihre Funktionalität in der Pro-Version durch die Asset-Hierarchie repliziert und erweitert wird.
## Komponenten (Beide)
Eine Bibliothek eines Drittanbieters, ein Softwaremodul oder eine externe Abhängigkeit, die in DefectDojo Pro erfasst wird. Importierte Komponenten werden aus Scandaten abgeleitet und mit Befunden verknüpft. In der Pro-Benutzeroberfläche aggregiert die Komponententabelle die Anzahl der Befunde mit dem Status Aktiv, Duplikat und die Gesamtzahl je Komponente und bleibt auch dann gefüllt, wenn alle zugehörigen Befunde den Status Behoben haben.
## Befund (Beide)
Das granularste Schwachstellenobjekt in der Produkthierarchie von DefectDojo, das ein einzelnes Sicherheitsproblem darstellt.
### Befundstatus (Beide)
Der aktuelle Lebenszyklusstatus eines Befunds (z. B. Aktiv, Verifiziert, Inaktiv/Behoben, In Prüfung, Risiko akzeptiert, Falsch-positiv, Außerhalb des Geltungsbereichs). Der Befundstatus bestimmt, ob der Befund in Metriken und Dashboards einbezogen wird.
### Befundpriorität/-risiko (Pro)
Ein berechneter oder abgeleiteter Wert, der die Dringlichkeit der Behebung darstellt, indem der Schweregrad mit Kontextfaktoren wie der Kritikalität des Assets oder der Ausnutzbarkeit kombiniert wird. Die Priorität unterscheidet sich vom reinen Schweregrad und wird für risikobasierte Entscheidungen verwendet.
### Befundgruppen (Beide)
Ein Mechanismus zum Gruppieren zusammengehöriger Befunde über Organisationen, Assets oder Tools hinweg. Befundgruppen ermöglichen eine konsolidierte Analyse und ein übergeordnetes Reporting.
## Endpunkt (Beide)
Ein über das Netzwerk erreichbarer Ort (URL, IP, Port), der einem Befund zugeordnet ist. Endpunkte liefern technischen Kontext zur Ausnutzung.
## Import (Beide)
Der Prozess der Erfassung von Scan-Ergebnissen oder manuellen Befunden in DefectDojo, in der Regel durch Hochladen einer Datei oder Übermittlung von Daten über die API. Beim Import parst, normalisiert und dedupliziert DefectDojo die Befunde und ordnet sie dem entsprechenden Asset, Engagement, Test und den zugehörigen Objekten zu.
## Reimport (Beide)
Der Vorgang, neue Scan-Ergebnisse in einen bestehenden Test zu übernehmen. Beim Reimport werden die Befundstatus basierend darauf aktualisiert, ob sie in den neuen Daten vorhanden sind oder nicht.
## Deduplizierung (Beide)
Der Prozess, bei dem eingehende Befunde mithilfe von Hashes und Abgleichlogik mit vorhandenen Befunden korreliert werden, was eine historische Nachverfolgung über mehrere Scan-Ausführungen hinweg ermöglicht.
## Falsch-positiv (Beide)
Ein Befundstatus, der anzeigt, dass das Problem ungültig oder nicht ausnutzbar ist. Falsch-positive Befunde werden zur Nachvollziehbarkeit aufbewahrt, jedoch von Risikoberechnungen ausgeschlossen.
## Risikoakzeptanz (Beide)
Ein Workflow-Status, der einen anerkannten, aber ungelösten Befund kennzeichnet. Akzeptierte Risiken bleiben sichtbar, werden jedoch von der SLA-Durchsetzung ausgeschlossen.
## Metadaten (Beide)
Wichtige Daten, die Tests oder Befunden zugeordnet werden, wie z. B. Branch-Name oder Build-ID, die in der Regel über CI/CD-Pipelines bereitgestellt werden.
## CI/CD-Integration (Beide)
Automatisierte Erfassung von Scan-Ergebnissen während Build- oder Deployment-Workflows. Integrationen basieren in der Regel auf der API und dem Importer-Framework.
## API (Beide)
Eine RESTful-Schnittstelle zur programmatischen Verwaltung von DefectDojo-Objekten. Die API ist der wichtigste Mechanismus für Automatisierung und Pipeline-Integration.
## Webhook (Pro)
Ein ausgehender HTTP-Callback, der durch bestimmte Ereignisse ausgelöst wird (z. B. die Erstellung eines Befunds). Webhooks ermöglichen die Echtzeitintegration mit externen Systemen.
## SLA-Konfiguration (Pro)
Richtliniendefinitionen, die auf Basis von Schweregrad- oder Risikoattributen Fristen für die Behebung festlegen. SLAs ermöglichen die Durchsetzung und Leistungsmessung.
## Benutzerrolle (Beide)
Ein Berechtigungssatz, der die zulässigen Aktionen innerhalb von DefectDojo festlegt. Rollen setzen die Zugriffskontrolle über Assets und Engagements hinweg durch.
## Universal Importer (Pro)
Ein flexibler Erfassungsmechanismus, der den Import von Scandaten ohne einen toolspezifischen Importer ermöglicht. Er basiert auf normalisiertem Feld-Mapping anstelle vordefinierter Scanner-Schemas.
## DefectDojo-CLI (Pro)
Eine Kommandozeilenschnittstelle zur programmatischen Interaktion mit DefectDojo. Die CLI wird häufig in CI/CD-Pipelines eingesetzt, um Scan-Uploads und die Objektverwaltung zu automatisieren.
## Connectors (Pro)
Der einheitliche Bereich der Pro-Benutzeroberfläche (unter Import) für alle Tools, mit denen DefectDojo kommuniziert. Upstream-Connectors rufen Befunde von Scannern ab; Downstream-Connectors senden Befunde an Issue-Tracker.
## Upstream-Connectors / API-Connectors (Pro)
Vorgefertigte, verwaltete Connectors, die Befunde und Asset-Inventar über deren APIs von externen Scannern und Sicherheitstools in DefectDojo importieren und so den Bedarf an individueller Skripterstellung verringern. Früher als API Connectors bezeichnet.
## Downstream-Connectors (Pro)
Verwaltete Integrationen, die Befunde und Befundgruppen aus DefectDojo in Issue-Tracking- und Ticketing-Systeme (z. B. Jira, Azure DevOps, GitHub) übertragen. Früher als Integrations bezeichnet.
## Universal Parser (Pro)
Eine generalisierte Parsing-Engine, die vom Universal Importer verwendet wird, um eingehende Scandaten zu interpretieren. Sie wendet für nicht unterstützte Formate eine einheitliche Normalisierungs- und Deduplizierungslogik an.
## Smart Upload (Pro)
Ein intelligenter Erfassungsworkflow, der automatisch bestimmt, wie Scan-Ergebnisse Assets oder Engagements zugeordnet werden sollen, wodurch die manuelle Konfiguration beim Import reduziert wird. Wenn ein gescannter Host zu mehr als einem Asset gehört, wird in jedem passenden Asset eine Kopie des Findings erstellt.
## Executive Insights (Pro)
Business-orientierte Analysen auf hoher Ebene, die für Führungskräfte konzipiert sind und sich auf Trends, Risikoexposition und den Gesamtzustand des Programms konzentrieren statt auf einzelne Befunde.
## Priority Insights (Pro)
Analytische Ansichten, die die kritischsten Risiken auf Basis der Prioritätsbewertung und nicht nur des Schweregrads hervorheben und so eine risikobasierte Behebungsplanung unterstützen.
## Program Insights (Pro)
Metriken und Visualisierungen, die die Wirksamkeit und Reife eines Sicherheitsprogramms im Zeitverlauf bewerten. Program Insights legen den Schwerpunkt auf Trends, Abdeckung und operative Leistung.
## Tool Insights (Pro)
Analysen, die sich auf die Leistung von Scannern, deren Abdeckung und ihren Beitrag zu Befunden konzentrieren und Teams dabei helfen, die Tool-Nutzung zu optimieren und Rauschen zu reduzieren.
## Rules Engine (Pro)
Ein richtliniengesteuertes Automatisierungssystem, das bedingte Logik auf Befunde während der Erfassung oder bei Lebenszyklusereignissen anwendet und so Schweregradänderungen, Zuweisungen oder Workflows automatisiert.
## Integrationen (Beide)
Verbindungen zwischen DefectDojo und externen Tools oder Plattformen zur Datenerfassung, Benachrichtigung oder Workflow-Automatisierung. Pro bietet, über einfache Importer und API-Nutzung hinaus, tiefere, verwaltete Integrationen.
