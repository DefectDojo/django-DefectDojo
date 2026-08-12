---
title: Engagements
description: Engagements in DefectDojo OS verstehen
audience: opensource
weight: 3
---

Organisationen → Assets → **ENGAGEMENTS** → Tests → Befunde

## Überblick

In der Produkthierarchie von DefectDojo sind Engagements zeit- oder pipelinegebundene Container, die Gruppen zusammengehöriger Tests innerhalb eines bestimmten Produkts darstellen. Wenn Sie eine geplante Testaktivität vorgesehen haben, egal ob routinemäßig oder einmalig, bietet Ihnen ein Engagement einen Ort, an dem Sie alle zugehörigen Ergebnisse speichern können.

Beispiele für Engagements sind:
- Einmalige Penetrationstests
- Wiederkehrende monatliche oder vierteljährliche Scans
- Bug-Bounty-Prüfzeiträume
- CI/CD-Pipeline-Durchläufe (für Teams, die jede Pipeline als eigenes Engagement behandeln)
- Code-Release-Zyklen (z. B. „Sicherheitsüberprüfung für Release v4.2“)

### Engagement-Typen

DefectDojo unterstützt zwei Engagement-Typen: **Interaktiv** und **CI/CD**. Diese Typen bestimmen, wie Tests typischerweise erstellt werden und wie Scan-Ergebnisse importiert werden.

Ein interaktives Engagement wird in der Regel von einem Ingenieur durchgeführt. Interaktive Engagements konzentrieren sich darauf, eine Anwendung während des Betriebs zu testen, sei es durch einen automatisierten Test, einen menschlichen Tester oder eine andere Aktivität, die mit der Funktionalität der Anwendung „interagiert“.

Ein CI/CD-Engagement dient der automatisierten Integration mit einer CI/CD-Pipeline. CI/CD-Engagements sind dafür gedacht, Daten als automatisierte Aktion zu importieren, die durch einen Schritt im Release-Prozess ausgelöst wird.

| **Kategorie**                | **Interaktive Engagements**                             | **CI/CD-Engagements**                                              |
|------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| **Primärer Anwendungsfall**   | Manuelle oder Ad-hoc-Sicherheitstests                            | Automatisierte, wiederkehrende Sicherheitstests innerhalb von Pipelines             |
| **Dauer**           | Zeitlich begrenzt und endlich                                        | Potenziell unbegrenzte Dauer                                      |
| **Häufigkeit**          | Periodisch oder einmalig                                          | Kontinuierlich oder pro Commit                                           |
| **Workflow**           | Menschlicher Tester führt Tool aus → importiert Ergebnisse manuell            | Pipeline führt Tool aus → überträgt Ergebnisse automatisch an DefectDojo    |
| **Methode des Ergebnisimports** | Manueller Upload über UI oder CLI                                 | API-gesteuerter Import per Automatisierung (z. B. CLI, Connectors, Cron-Jobs, Pipeline-Skripte) |
| **Typischer Testtyp** | Penetrationstests, Red-Team-Übungen, manuelle Bewertungen   | Statische Analyse, Dependency-Scanning, Container-Scanning           |

### Engagement-Daten

Als die Container, die Testaktivitäten organisieren, können Engagements eine Vielzahl von Daten speichern oder nachverfolgen:

- Geplante Start- und Enddaten
- Beschreibung und Hinweise zum Umfang
- Status (laufend, geplant, abgeschlossen usw.)
- Verantwortlicher / Lead
- Zugehörige Tests (z. B. Scans, Penetrationstests, manuelle Tests usw.)
- Befunde und Befundtypen (z. B. aktiv, behoben, Risiko akzeptiert, Duplikat usw.)
- Bedrohungsmodelle oder Informationen zur Risikoakzeptanz
- Tags
- Dateien und Notizen
- Jira-Projekteinstellungen
- Umgebungsdetails (z. B. Staging vs. Produktion)
- Build-IDs (falls mit CI/CD verknüpft)
- Historische Daten aus früheren Tests innerhalb des Engagements

## Zugriff auf Engagements

Engagements sind über die Seitenleiste zugänglich. Das Untermenü bietet Zugriff auf Aktive Engagements und Alle Engagements sowie die Möglichkeit, Engagements nach Produkt, Testtypen und Umgebungen organisiert anzuzeigen.

![image](images/engagement_ss17.png)

Alternativ können Engagements innerhalb eines bestimmten Produkts über das Untermenü der Option Engagements in der oberen Leiste aufgerufen werden.

![image](images/engagement_ss18.png)

### Berechtigungen

Engagements stehen in der Objekthierarchie unterhalb von Produkten und oberhalb von Tests. Daher gewährt der Zugriff auf ein Produkt automatisch Zugriff auf alle Engagements innerhalb dieses Produkts. Engagements verfügen über keine eigenständigen Zugriffskontrolllisten.

## Arbeiten mit Engagements

### Engagements erstellen

Es gibt mehrere Möglichkeiten, ein Engagement zu erstellen. Jede Möglichkeit erfordert, dass Sie zunächst ein Produkt erstellen, das das Engagement enthalten soll.

Sobald Sie ein Produkt erstellt haben, können Sie im Bereich Engagements der Navigationsleiste des Produkts ein neues interaktives oder CI/CD-Engagement hinzufügen.

![image](images/engagement_ss4.png)

Für jedes Engagement müssen folgende Felder definiert sein:
- Typ (Interaktiv oder CI/CD)
- Ein eindeutiger Name
- Geplante Start- und Enddaten
    - Diese bestimmen, wie das Engagement im Kalenderbereich angezeigt wird
- Produkt
- Status

#### Engagement-Status

Engagements können bei der Erstellung mit verschiedenen Status versehen werden. Der Status kann anschließend auch in den Einstellungen des Engagements geändert werden.

Ein Engagement kann einen der folgenden Status haben:
- Nicht gestartet
- Blockiert
- Abgebrochen
- Abgeschlossen
- In Bearbeitung
- Angehalten
- Geplant
- Wartet auf Ressource

Wenn der Status eines Engagements auf „Abgeschlossen“ geändert wird, bedeutet dies, dass die meisten Schreibvorgänge (z. B. das Hinzufügen von Tests, der Import von Scans) nicht mehr verfügbar oder ausgeblendet sind. Andere Status wirken sich nicht wesentlich auf die Funktionalität des Engagements aus und dienen eher der Filterung bzw. Information.

### Engagements bearbeiten

Engagements können bearbeitet werden, indem Sie auf die Schaltfläche **Bearbeiten** in den Einstellungen des Engagements klicken. Alle daraufhin bearbeitbaren Felder stehen auch bei der Erstellung des Engagements zur Verfügung.

### Engagements kopieren

Sie können Engagements einfach duplizieren, indem Sie zur Liste der Engagements innerhalb eines Produkts navigieren und im ⋮-Kebab-Menü neben dem zu kopierenden Engagement auf **Kopieren** klicken. Dadurch wird eine exakte Kopie des ursprünglichen Engagements innerhalb des übergeordneten Produkts erstellt, einschließlich der Metadaten, Tests und Befunde darin.

![image](images/engagement_ss19.png)

### Engagements schließen

Engagements können geschlossen werden, indem Sie zur Liste der Engagements innerhalb eines Produkts navigieren und im ⋮-Kebab-Menü des gewählten Engagements auf „Schließen“ klicken.

![image](images/engagement_ss20.png)

Nach dem Schließen wird der Status des Engagements auf „Abgeschlossen“ geändert. Dennoch bleiben die meisten Schreibvorgänge (z. B. das Hinzufügen von Tests, der Import von Scans) weiterhin verfügbar.

Das Schließen eines Engagements ändert nicht den Status der Befunde innerhalb der Tests des Engagements. Befunde bleiben je nach ihrem eigenen Lebenszyklus offen, behoben oder risikoakzeptiert und bleiben zur Ansicht und für Berichte weiterhin zugänglich.

Wenn das Engagement mit einem Jira-Epic verknüpft ist (siehe **[Jira-Integration: Engagement-Epic-Zuordnung aktivieren](/connectors/os_jira/os__jira_guide/#enable-engagement-epic-mapping-for-products)**), löst das Schließen des Engagements eine asynchrone Aufgabe aus, die das zugehörige Jira-Epic in Ihrem verbundenen Jira-Space schließt.

### Engagements erneut öffnen

Wenn ein Engagement geschlossen ist, kann es erneut geöffnet werden, indem Sie in der Tabelle der geschlossenen Engagements im zugehörigen ⋮-Kebab-Menü auf **Erneut öffnen** klicken. Dadurch wird das Engagement wieder aktiv und sein Status kehrt zu „In Bearbeitung“ zurück.

![image](images/engagement_ss21.png)

### Abgelaufene Engagements

Ein Engagement läuft ab, sobald sein geplantes Enddatum überschritten ist.

Der Ablauf eines Engagements hat keine direkten Auswirkungen auf dessen Funktionalität und dient in erster Linie als Überwachungs- bzw. Benachrichtigungsmechanismus.

Nach Ablauf erscheint im Feld „Dauer“ des Engagements eine rote Benachrichtigung „X Tage überfällig“, dies schränkt jedoch keine der Funktionen des Engagements ein. Der Status des Engagements wird weiterhin als „In Bearbeitung“ angezeigt.

Obwohl standardmäßig nicht aktiviert, gibt es in den Systemeinstellungen eine Option, ein Engagement automatisch zu schließen, sobald es eine bestimmte Anzahl von Tagen abgelaufen ist.

![image](images/engagement_ss22.png)

### Engagements löschen

Das Löschen eines Engagements erfolgt über die Auswahl von **Löschen** in den Einstellungen des Engagements. Diese Aktion kann nicht rückgängig gemacht werden.

Das Löschen eines Engagements löscht auch Folgendes:
- Alle mit dem Engagement verbundenen Tests
- Alle Befunde innerhalb dieser Tests
- Alle verknüpften Jira-Epic-Zuordnungen (das Epic selbst bleibt in Jira erhalten, aber die Verknüpfung zwischen DefectDojo und Jira wird entfernt)
- Alle Notizen und Datei-Uploads, die mit dem Engagement verbunden sind

Aus Gründen der Nachvollziehbarkeit wird empfohlen, abgeschlossene Engagements zu schließen, anstatt sie zu löschen.

| **Vorgang** | **Ergebnisse** | **Umkehrbar** |
|----------|---------|------------|
| **Schließen** | Markiert als inaktiv; Daten bleiben erhalten; kann erneut geöffnet werden | Ja (erneut öffnen) |
| **Ablaufen** | Nur visuelle Warnung; optionales automatisches Schließen; Benachrichtigungen | N/A |
| **Löschen** | Entfernt Engagement, Tests, Befunde, Notizen, Dateien und alle Jira-Epic-Zuordnungen dauerhaft (Epics bleiben in Jira erhalten) | Nein |

## Jira-Integration

Engagements können mit einem verbundenen Jira-Space verknüpft werden, sodass Befunde innerhalb des Engagements als Issues an Jira übertragen werden können. Eine vollständige Anleitung zur Einrichtung von Jira finden Sie unter **[DefectDojo mit Jira verbinden](/connectors/os_jira/os__jira_guide/)**.

### Engagement-Epic-Zuordnung

Wenn **Engagement-Epic-Zuordnung aktivieren** in den Jira-Einstellungen eines Produkts aktiviert ist, werden Engagements als Epics an Jira übertragen. Befunde innerhalb des Engagements werden als untergeordnete Issues unter dem Epic übertragen und spiegeln damit die Hierarchie Engagement → Befunde von DefectDojo in der Struktur Epic → Issue von Jira wider.

Weitere Informationen zu dieser Einstellung finden Sie unter **[Engagement-Epic-Zuordnung aktivieren](/connectors/os_jira/os__jira_guide/#enable-engagement-epic-mapping-for-products)**.

### Jira-Einstellungen auf Engagement-Ebene

Standardmäßig übernehmen Engagements ihre Jira-Einstellungen vom übergeordneten Produkt. Einzelne Engagements können diese Einstellungen jedoch überschreiben, um abweichende Jira-Konfigurationen zu verwenden. Folgende Einstellungen können pro Engagement angepasst werden:

- **Projektschlüssel** — leitet Befunde an einen anderen Jira-Space weiter
- **Issue-Vorlage** — verwendet eine andere Vorlage für Issues, die aus diesem Engagement erstellt werden
- **Benutzerdefinierte Felder** — wendet abweichende Zuordnungen benutzerdefinierter Felder an
- **Jira-Labels** — versieht Issues mit engagementspezifischen Labels
- **Standardzuweisung** — weist Issues einem anderen Teammitglied zu

Diese Einstellungen sind über die Seite **Engagement bearbeiten** zugänglich. Weitere Details finden Sie unter **[Jira-Einstellungen auf Engagement-Ebene](/connectors/os_jira/os__jira_guide/#engagement-level-jira-settings)**.