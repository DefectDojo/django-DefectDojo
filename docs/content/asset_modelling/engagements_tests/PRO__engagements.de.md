---
title: Engagements
description: Engagements in DefectDojo Pro verstehen
audience: pro
weight: 3
---

Organizations → Assets → **ENGAGEMENTS** → Tests → Findings 

## Übersicht

In der Asset-Hierarchie von DefectDojo sind Engagements zeit- oder pipelinegebundene Container, die Gruppen zusammengehöriger Tests innerhalb eines bestimmten Assets darstellen. Wenn Sie eine geplante Testaktivität vorgesehen haben, egal ob routinemäßig oder einmalig, bietet Ihnen ein Engagement einen Ort, an dem Sie alle zugehörigen Ergebnisse speichern können.

Beispiele für Engagements sind: 
- Einmalige Penetrationstests
- Wiederkehrende monatliche oder vierteljährliche Scans
- Bug-Bounty-Prüfzeiträume
- CI/CD-Pipeline-Läufe (für Teams, die jede Pipeline als eigenes Engagement betrachten)
- Code-Release-Zyklen (z. B. „Sicherheitsüberprüfung für Release v4.2“)

### Engagement-Typen 

DefectDojo unterstützt zwei Engagement-Typen: **Interactive** und **CI/CD**. Diese Typen bestimmen, wie Tests in der Regel erstellt werden und wie Scan-Ergebnisse importiert werden.

Ein Interactive Engagement wird in der Regel von einem Ingenieur durchgeführt. Interactive Engagements konzentrieren sich darauf, eine Anwendung während der Laufzeit zu testen, sei es durch einen automatisierten Test, einen menschlichen Tester oder jede andere Aktivität, die mit der Anwendungsfunktionalität „interagiert“. 

Ein CI/CD Engagement dient der automatisierten Integration mit einer CI/CD-Pipeline. CI/CD Engagements sind dafür vorgesehen, Daten als automatisierte Aktion zu importieren, die durch einen Schritt im Release-Prozess ausgelöst wird.

| **Kategorie**                | **Interactive Engagements**                             | **CI/CD Engagements**                                              |
|------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| **Primärer Anwendungsfall**   | Manuelle oder Ad-hoc-Sicherheitstests                            | Automatisierte, wiederkehrende Sicherheitstests innerhalb von Pipelines             |
| **Dauer**           | Zeitlich begrenzt und endlich                                        | Potenziell unbegrenzte Dauer                                      |
| **Häufigkeit**          | Periodisch oder einmalig                                          | Kontinuierlich oder pro Commit                                           |
| **Ablauf**           | Menschlicher Tester führt Tool aus → importiert Ergebnisse manuell            | Pipeline führt Tool aus → überträgt Ergebnisse automatisch an DefectDojo    |
| **Methode des Ergebnisimports** | Manueller Upload über UI oder CLI                                 | API-gesteuerter Import per Automatisierung (z. B. CLI, Connectors, Cron-Jobs, Pipeline-Skripte) |
| **Typischer Testtyp** | Penetrationstests, Red-Team-Übungen, manuelle Bewertungen   | Statische Analyse, Dependency-Scanning, Container-Scanning           |

### Engagement-Daten 

Als Container, die Testaktivitäten organisieren, können Engagements eine Vielzahl von Daten speichern oder verfolgen:

- Geplantes Start- und Enddatum
- Beschreibung und Hinweise zum Geltungsbereich
- Status (laufend, geplant, abgeschlossen usw.)
- Zuständiger / Verantwortlicher
- Zugehörige Tests (z. B. Scans, Penetrationstests, manuelle Tests usw.)
- Befunde und Befundtypen (z. B. aktiv, behoben, Risiko akzeptiert, Duplikat usw.) 
- Bedrohungsmodelle oder Informationen zur Risikoakzeptanz
- Tags
- Dateien und Notizen
- Jira-Projekteinstellungen
- Umgebungsdetails (z. B. Staging vs. Produktion)
- Build-IDs (bei Anbindung an CI/CD)
- Historische Daten aus früheren Tests innerhalb des Engagements 

## Zugriff auf Engagements 

Engagements sind über die Seitenleiste zugänglich. Das Untermenü bietet Zugriff auf Active Engagements und All Engagements sowie die Möglichkeit, neue Engagements zu erstellen.

![image](images/engagement_ss13.png)

Alternativ können Engagements innerhalb eines Assets im Fenster am unteren Rand der Asset-Ansicht aufgerufen werden.

![image](images/engagement_ss14.png)

### Berechtigungen 

Engagements stehen in der Objekthierarchie unterhalb von Assets und oberhalb von Tests. Der Zugriff auf ein Asset gewährt daher automatisch Zugriff auf alle Engagements innerhalb dieses Assets. Engagements verfügen über keine eigenen Zugriffskontrolllisten.

## Arbeiten mit Engagements

### Engagements erstellen 

Bevor Sie ein Engagement erstellen können, müssen Sie zunächst [ein Asset erstellt haben](/asset_modelling/engagements_tests/pro__assets/#create-assets), das es enthält. 

Es gibt mehrere Möglichkeiten, ein Engagement zu erstellen: 

- Über das Engagements-Dropdown im Bereich „Manage“ der Seitenleiste
    - Beim Ausfüllen des Formulars „New Engagement“ müssen Sie das Asset auswählen, dem das Engagement zugeordnet werden soll

![image](images/engagement_ss1.png)

- Über das Zahnradsymbol oben rechts in einer Asset-Ansicht

![image](images/engagement_ss9.png)

- Über die Schaltfläche „+ New Engagement“ in der Liste der Engagements innerhalb eines Assets

![image](images/engagement_ss2.png)

- Wenn Sie noch kein Engagement innerhalb eines Assets erstellt haben, können Sie dies auch beim Importieren eines Scans tun. 

![image](images/engagement_ss3.png)

Für jedes Engagement müssen die folgenden Felder festgelegt werden:
- Typ (Interactive oder CI/CD)
- Ein eindeutiger Name 
- Geplantes Start- und Enddatum 
    - Dies bestimmt, wie das Engagement im Kalenderbereich angezeigt wird
- Asset 
- Status 

#### Engagement-Status 

Engagements können bei der Erstellung mit unterschiedlichen Status gekennzeichnet werden. Der Status kann anschließend auch in den Einstellungen des Engagements geändert werden. 

Ein Engagement kann einen der folgenden Status haben: 
- Not Started
- Blocked
- Cancelled 
- Completed 
- In Progress 
- On Hold 
- Scheduled 
- Waiting for Resource 

Wird der Status eines Engagements auf „Completed“ geändert, sind die meisten Schreibvorgänge (z. B. das Hinzufügen von Tests, das Importieren von Scans) nicht mehr verfügbar oder ausgeblendet. Andere Status wirken sich nicht wesentlich auf die Funktionalität des Engagements aus und dienen hauptsächlich der Filterung bzw. Information.

### Engagements bearbeiten 

Engagements können bearbeitet werden, indem Sie im Zahnradmenü auf **Edit Engagement** klicken. Dasselbe Menü ist auch über das ⋮-Kebab-Menü links neben dem Asset in der Ansicht „All Assets“ zugänglich. 

Alle nachfolgend bearbeitbaren Felder stehen auch bei der Erstellung des Engagements zur Verfügung. 

![image](images/engagements_ss99.png)

### Engagements kopieren 

Sie können Engagements ganz einfach duplizieren, indem Sie in den Einstellungen des Engagements „Copy Engagement“ auswählen. Dadurch wird innerhalb des übergeordneten Assets eine exakte Kopie des ursprünglichen Engagements erstellt, einschließlich der Metadaten, Tests und Befunde darin.

### Engagements schließen 

Engagements werden geschlossen, indem Sie in den Einstellungen des Engagements **Close Engagement** auswählen. Nach dem Schließen wird der Status des Engagements auf „Completed“ geändert. Dennoch bleiben die meisten Schreibvorgänge (z. B. das Hinzufügen von Tests, das Importieren von Scans) weiterhin verfügbar.

Das Schließen eines Engagements ändert nicht den Status der Befunde innerhalb der Tests des Engagements. Befunde bleiben gemäß ihrem eigenen Lebenszyklus offen, behoben oder als Risiko akzeptiert und bleiben weiterhin für die Anzeige und Berichterstellung zugänglich.

Wenn das Engagement mit einem Jira Epic verknüpft ist (siehe **[Jira-Integration: Enable Engagement Epic Mapping](/connectors/downstream/pro__jira_guide/#enable-engagement-epic-mapping)**), löst das Schließen des Engagements eine asynchrone Aufgabe aus, die das zugehörige Jira Epic in Ihrem verbundenen Jira Space schließt.

### Engagements erneut öffnen 

Wenn ein Engagement geschlossen ist, kann es erneut geöffnet werden, indem Sie in den Einstellungen **Reopen Engagement** auswählen. Dadurch wird das Engagement wieder aktiv und sein Status kehrt zu „In Progress“ zurück. 

### Abgelaufene Engagements 

Ein Engagement läuft ab, sobald das geplante Enddatum überschritten ist.

Im Vergleich zum Schließen oder Löschen eines Engagements hat das Ablaufen eines Engagements keine direkten Auswirkungen auf dessen Funktionalität und dient in erster Linie als Überwachungs- bzw. Benachrichtigungsmechanismus.  

Nach Ablauf erscheint neben dem Engagement das Tag „Overdue“, dies schränkt jedoch keine der Funktionen des Engagements ein. Der Status des Engagements wird weiterhin als „In Progress“ angezeigt. 

Obwohl es standardmäßig nicht aktiviert ist, gibt es in den Systemeinstellungen eine Option, mit der ein Engagement automatisch geschlossen wird, nachdem es eine bestimmte Anzahl von Tagen abgelaufen ist. 

![image](images/engagement_ss15.png)

### Engagements löschen

Das Löschen eines Engagements erfolgt, indem Sie in den Einstellungen des Engagements **Delete Engagement** auswählen. Diese Aktion kann nicht rückgängig gemacht werden.

Das Löschen eines Engagements löscht auch Folgendes:
Alle mit dem Engagement verknüpften Tests
Alle Befunde innerhalb dieser Tests
Alle verknüpften Jira-Epic-Zuordnungen (das Epic selbst bleibt in Jira erhalten, aber die Verknüpfung zwischen DefectDojo und Jira wird entfernt)
Alle Notizen und Datei-Uploads, die mit dem Engagement verknüpft sind

Für Auditzwecke wird empfohlen, abgeschlossene Engagements zu schließen, anstatt sie zu löschen.

| **Vorgang** | **Ergebnisse** | **Umkehrbar** |
|----------|---------|------------|
| **Schließen** | Wird als inaktiv markiert; Daten bleiben erhalten; kann erneut geöffnet werden | Ja (erneut öffnen) |
| **Ablaufen** | Nur visueller Hinweis; optionales automatisches Schließen; Benachrichtigungen | Entfällt |
| **Löschen** | Entfernt dauerhaft Engagement, Tests, Befunde, Notizen, Dateien und alle Jira-Epic-Zuordnungen (Epics bleiben in Jira erhalten) | Nein |

## Jira-Integration

Engagements können mit einem verbundenen Jira Space verknüpft werden, sodass Befunde innerhalb des Engagements als Issues an Jira übertragen werden können. Eine vollständige Anleitung zur Einrichtung von Jira finden Sie unter **[Connecting DefectDojo to Jira](/connectors/downstream/pro__jira_guide/)**.

### Engagement-Epic-Zuordnung

Wenn **Enable Engagement Epic Mapping** in den Jira-Einstellungen eines Produkts aktiviert ist, werden Engagements als Epics an Jira übertragen. Befunde innerhalb des Engagements werden als untergeordnete Issues unterhalb des Epics übertragen, wodurch die Hierarchie „Engagement → Findings“ von DefectDojo in der Struktur „Epic → Issue“ von Jira abgebildet wird.

Weitere Informationen zu dieser Einstellung finden Sie unter **[Enable Engagement Epic Mapping](/connectors/downstream/pro__jira_guide/#enable-engagement-epic-mapping)**.

### Jira-Einstellungen auf Engagement-Ebene

Standardmäßig übernehmen Engagements ihre Jira-Einstellungen vom übergeordneten Asset (Product). Einzelne Engagements können diese Einstellungen jedoch überschreiben, um andere Jira-Konfigurationen zu verwenden. Die folgenden Einstellungen können pro Engagement angepasst werden:

- **Project Key** — leitet Befunde an einen anderen Jira Space weiter
- **Issue Template** — verwendet eine andere Vorlage für Issues, die aus diesem Engagement erstellt werden
- **Custom Fields** — wendet andere Zuordnungen benutzerdefinierter Felder an
- **Jira Labels** — versieht Issues mit engagementspezifischen Labels
- **Default Assignee** — weist Issues einem anderen Teammitglied zu

Diese Einstellungen sind über die Seite **Edit Engagement** zugänglich. Weitere Details finden Sie unter **[Engagement-Level Jira Settings](/connectors/downstream/pro__jira_guide/#engagement-level-jira-settings)**.
