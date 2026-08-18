---
title: Fragebögen
description: Fragebögen in OS DefectDojo verstehen
audience: opensource
weight: 2
---

In DefectDojo ist ein Fragebogen ein wiederverwendbarer Satz von Fragen, mit dem Informationen von Entwicklern, Teams sowie internen und externen Beteiligten erfasst werden. Damit lassen sich vor Beginn der Arbeit Informationen einholen, während der Arbeit die Abstimmung zwischen Personen und Teams sicherstellen und nach Abschluss der Arbeit rückblickende Analysen durchführen. 

## Fragebogenvorlagen 

Eine Fragebogenvorlage legt Struktur und Inhalt des Fragebogens fest, einschließlich Name, Beschreibung und zugehöriger Fragen. Das Erstellen einer Fragebogenvorlage macht sie nicht automatisch für Antworten verfügbar. Um Antworten zu erfassen, muss eine Fragebogenvorlage entweder als **allgemeiner Fragebogen** oder als **verknüpfter Fragebogen** bereitgestellt werden.

### Allgemeine und verknüpfte Fragebögen 

Allgemeine und verknüpfte Fragebögen unterscheiden sich in mehreren Punkten, unter anderem darin, wie sie verteilt werden, wer antworten kann und wo die Antworten gespeichert werden.

| Allgemeine Fragebögen | Verknüpfte Fragebögen |
|---|---|
| Müssen veröffentlicht werden | Müssen nicht veröffentlicht werden |
| Benötigen ein Ablaufdatum | Bleiben aktiv, solange das Engagement aktiv ist |
| Erlauben anonyme Antworten | Erlauben keine anonymen Antworten |
| Sind intern und extern teilbar | Sind nur intern teilbar |
| Erlauben kein Ändern von Antworten | Erlauben das Ändern von Antworten |
| Antworten sind erst nach Ablauf sichtbar | Antworten sind sofort sichtbar |
| Antworten sind unter „Alle Fragebögen“ sichtbar | Antworten sind im Engagement sichtbar |
| Können in ein Engagement umgewandelt werden | Sind bereits mit einem Engagement verknüpft |

#### Lebenszyklus der Fragebogen-Bereitstellung

Fragebogenvorlagen folgen je nach Art der Bereitstellung unterschiedlichen Lebenszyklen:

**Allgemeine Fragebögen** 
Vorlage → Veröffentlicht → Antworten annehmen → Ablauf → Optionale Umwandlung in ein Engagement

**Verknüpfte Fragebögen**
Vorlage → Mit Engagement verknüpft → Antworten annehmen → Bleiben aktiv, solange das Engagement aktiv ist

#### Trennung der Antworten

Eine einzelne Fragebogenvorlage kann mehrfach gleichzeitig bereitgestellt werden, sowohl als allgemeiner als auch als verknüpfter Fragebogen. Jede Bereitstellung erzeugt einen eigenen, unabhängigen Satz von Antworten.

Wenn dieselbe Fragebogenvorlage als allgemeiner Fragebogen bereitgestellt und zusätzlich mit einem Engagement verknüpft wird, werden die über die jeweilige Bereitstellung übermittelten Antworten unabhängig gespeichert und nicht zusammengeführt. So kann dieselbe Fragebogenvorlage in verschiedenen Kontexten wiederverwendet werden, während die Antwortsätze getrennt bleiben.

## Zugriff auf Fragebögen und Fragen 

Fragebögen und Fragen erreichen Sie über die Seitenleiste, indem Sie auf **Fragebögen** klicken. Das Untermenü führt zu **Alle Fragebögen** und **Alle Fragen**.

![image](images/q_ss1.png)

Der Zugriff auf die Ansichten „Alle Fragebögen“ und „Alle Fragen“ ist ausschließlich Benutzern mit Superuser-Status vorbehalten. Nur Superuser können Fragebogenvorlagen und Fragen erstellen sowie Fragebögen bereitstellen. Benutzer ohne Superuser-Status können weiterhin allgemeine Fragebögen beantworten, die mit ihnen geteilt werden, und auch die verknüpften Fragebögen von Engagements beantworten, auf die sie Zugriff haben, sie können sie jedoch nicht erstellen oder verwalten.

### Fragebögen 

Die Ansicht „Alle Fragebögen“ enthält zwei Tabellen:
- **Fragebögen**
    - Dieser Bereich enthält alle vorhandenen Fragebogenvorlagen.
- **Allgemeine Fragebögen**
    - Dieser Bereich enthält alle allgemeinen Fragebögen, die derzeit für Antworten offen sind. 

Beide Bereiche können nach Name, Beschreibung oder Aktivstatus gefiltert werden.

### Fragen 

Die Ansicht „Alle Fragen“ enthält eine Tabelle mit Fragen, die derzeit einem Fragebogen hinzugefügt werden können. Sie lässt sich außerdem nach dem Optional-Status, dem Inhalt oder dem Fragetyp (z. B. Textfrage oder Auswahlfrage) filtern.

## Fragebogenvorlagen verwalten 

### Fragebögen erstellen 

Neue Fragebögen können über die Schaltfläche „Fragebogen erstellen“ in der Ansicht „Alle Fragebögen“ angelegt werden. 

![image](images/q_ss2.png)

Nach der Eingabe von Name und Beschreibung kann der Fragebogen entweder ohne Fragen erstellt werden (diese können später hinzugefügt werden) oder es können sofort Fragen hinzugefügt werden. 

#### Fragen sofort zu einem neuen Fragebogen hinzufügen 

Wenn Fragen sofort hinzugefügt werden, wählen Sie alle passenden Fragen im daraufhin angezeigten Dropdown-Menü aus. Über das Pluszeichen rechts neben dem Dropdown-Menü können Sie auch eine neue Frage erstellen und dem Fragebogen hinzufügen. 

![image](images/q_ss12.png)

Sobald alle passenden Fragen ausgewählt sind, klicken Sie auf **Fragen des Fragebogens aktualisieren**, um alle ausgewählten Fragen dem Fragebogen hinzuzufügen. 

#### Fragen zu einem bestehenden Fragebogen hinzufügen 

Um Fragen zu einem bestehenden Fragebogen hinzuzufügen, klicken Sie in der Tabelle „Fragebögen“ auf den Namen des Fragebogens, klicken Sie auf **Fragen bearbeiten**, wählen Sie im Dropdown-Menü die neuen Fragen für den Fragebogen aus und klicken Sie dann auf **Fragen des Fragebogens aktualisieren**.

### Fragen erstellen 

Neue Fragen können über die Schaltfläche **Frage erstellen** in der Ansicht „Alle Fragen“ angelegt werden. 

![image](images/q_ss3.png)

Darüber hinaus können Fragen auch bei der Auswahl der Fragen für einen Fragebogen erstellt werden, indem Sie auf das Pluszeichen rechts neben dem Dropdown-Menü klicken. 

#### Fragetypen 

Beim Erstellen einer neuen Frage kann diese als Textfrage oder als Auswahlfrage angelegt werden, indem im Dropdown-Menü entweder **Text** oder **Choice** ausgewählt wird.

#### Mehrfachantworten und optionale Antworten zulassen 

Die maximale Anzahl zulässiger Antworten in einer Auswahlfrage beträgt sechs. Über das Kontrollkästchen **Multichoice** können mehrere Antworten ausgewählt werden (nur bei Auswahlfragen verfügbar). Fragen können über das entsprechende Kontrollkästchen außerdem als **Optional** markiert werden. 

Wie Sie einer Auswahlfrage weitere Antworten hinzufügen, erfahren Sie im Abschnitt [Fragen bearbeiten](#editing-questions). 

#### Reihenfolge der Fragen 

Legen Sie die Reihenfolge einer Frage über eine Ordnungsnummer fest. Steht im Feld „Reihenfolge“ beispielsweise 1, erscheint diese Frage über einer Frage mit 2 im Feld „Reihenfolge“. 

![image](images/q_ss13.png)

### Fragen bearbeiten

Nachdem eine Frage erstellt wurde, kann sie über das Untermenü „Alle Fragen“ bearbeitet werden, indem Sie auf die zu ändernde Frage klicken. Fragen können nicht gelöscht werden. 

Vermeiden Sie es, Fragen zu bearbeiten, die Teil aktiver Fragebögen sind. Wird ein Teil einer Frage geändert (z. B. Reihenfolge, Optional-Status, Korrektur eines Tippfehlers, Hinzufügen einer möglichen Antwort usw.) und war diese Frage Teil eines aktiven Fragebogens, für den bereits Antworten übermittelt wurden, werden alle zuvor übermittelten Antworten ungültig und müssen erneut übermittelt werden.

#### Textfragen bearbeiten

Nach der Erstellung lassen sich bei Textfragen nur die Reihenfolge, der Optional-Status und die Formulierung der Frage ändern. 

#### Auswahlfragen bearbeiten 

Die Standardanzahl möglicher Antworten auf eine Auswahlfrage beträgt sechs, kann aber nach dem Erstellen des Fragebogens erhöht werden. Klicken Sie dazu in der Ansicht „Alle Fragen“ auf die Frage, klicken Sie auf das **+** rechts neben dem Dropdown-Menü „Auswahlmöglichkeiten“, fügen Sie die neue Antwort hinzu und klicken Sie auf **Absenden**. 

![image](images/q_ss16.png)

![image](images/q_ss17.png)

Die neu erstellte Option wird dem Fragebogen nicht automatisch hinzugefügt. Klicken Sie zum Hinzufügen auf das Dropdown-Menü **Auswahlmöglichkeiten** und wählen Sie die neu hinzugefügte Option aus. Daneben erscheint ein Häkchen, das anzeigt, dass sie nun als mögliche Antwort im Fragebogen enthalten ist.

![image](images/q_ss18.png)

## Fragebögen bereitstellen 

Sobald eine Fragebogenvorlage erfolgreich erstellt wurde, kann sie bereitgestellt werden, um Antworten anzunehmen. Der Bereitstellungsvorgang unterscheidet sich je nach Fragebogentyp leicht. 

### Bereitstellung eines allgemeinen Fragebogens

So stellen Sie einen allgemeinen Fragebogen bereit: 
1. Wechseln Sie zur Ansicht „Alle Fragebögen“.
2. Klicken Sie auf das **+** rechts in der Tabelle „Allgemeine Fragebögen“.
3. Wählen Sie den bereitzustellenden Fragebogen aus.
4. Legen Sie das Ablaufdatum fest.
5. Klicken Sie auf **Fragebogen hinzufügen**. 

#### Einen allgemeinen Fragebogen teilen 

Nach der Bereitstellung kann ein allgemeiner Fragebogen geteilt werden, indem Sie in der Spalte „Aktionen“ der Tabelle „Allgemeine Fragebögen“ auf **Fragebogen teilen** klicken. Dadurch wird ein Link erzeugt, den Sie an die vorgesehenen Empfänger weitergeben können; zuvor können Sie außerdem prüfen, ob der Fragebogen wie gewünscht aufgebaut ist. 

![image](images/q_ss14.png)

Beachten Sie Folgendes: 
- Antworten auf einen allgemeinen Fragebogen sind erst nach Ablauf des Fragebogens sichtbar. 
- Nach der Veröffentlichung des Fragebogens kann das Ablaufdatum nicht mehr geändert werden. 
- Standardmäßig läuft ein Fragebogen um Mitternacht ab (ein Fragebogen mit Ablaufdatum 31. Dezember 2026 ist beispielsweise nur bis 23:59:59 an diesem Tag verfügbar). 
- Eine individuelle Ablaufzeit kann nicht festgelegt werden. 

Informationen dazu, wie Sie Antworten externer Benutzer zulassen, finden Sie unten unter [Anonyme Antworten aktivieren](#enabling-anonymous-responses). 

### Bereitstellung eines verknüpften Fragebogens

So stellen Sie einen verknüpften Fragebogen bereit:
1. Wechseln Sie zu dem Engagement, das mit dem Fragebogen verknüpft werden soll. 
2. Klicken Sie auf den Abwärtspfeil an der Tabelle **Zusätzliche Funktionen**. 
3. Klicken Sie auf das **+** rechts in der Untertabelle „Fragebögen“. 
4. Wählen Sie im Dropdown-Menü den zu verknüpfenden Fragebogen aus. 
5. Klicken Sie auf **Fragebogen hinzufügen** oder **Fragebogen hinzufügen und beantworten**.

Der verknüpfte Fragebogen ist nun für alle Benutzer aktiv, die Zugriff auf das Engagement haben. 

#### Einen verknüpften Fragebogen teilen 

Um den verknüpften Fragebogen direkt mit internen DefectDojo-Benutzern zu teilen, klicken Sie auf das Kebab-Menü ⋮ und wählen Sie im Dropdown **Fragebogen teilen**. Es erscheint ein Link, der kopiert und an den vorgesehenen Empfänger weitergeleitet werden kann.

![image](images/q_ss10.png)

Wie erwähnt können verknüpfte Fragebögen nur mit DefectDojo-Benutzern geteilt werden.

## Fragebögen beantworten 

Der Ablauf beim Beantworten unterscheidet sich leicht, je nachdem, ob es sich um einen allgemeinen oder einen verknüpften Fragebogen handelt. 

### Einen allgemeinen Fragebogen beantworten 

Um einen allgemeinen Fragebogen zu beantworten, muss Benutzern ohne Superuser-Status der Link direkt von einem Superuser mitgeteilt werden, wie [hier](#sharing-a-general-questionnaire) beschrieben. 

#### Anonyme Antworten aktivieren 

Standardmäßig sind allgemeine Fragebögen nur für DefectDojo-Benutzer zugänglich. Damit externe Personen DefectDojo-Fragebögen beantworten können, muss die Option **Anonyme Umfrageantworten zulassen** in den Systemeinstellungen eingeschaltet sein; diese finden Sie im Bereich **Konfigurationen** der Seitenleiste.

![image](images/q_ss4.png)

![image](images/q_ss5.png)

Externe Antworten erscheinen als anonym, da mit der Antwort keine DefectDojo-Benutzer-ID verknüpft ist. 

Wenn ein Fragebogen sowohl interne als auch externe Benutzer umfasst, erstellen Sie einen allgemeinen Fragebogen und geben Sie beim Erstellen den Namen des Engagements in der Beschreibung an, damit die Ergebnisse gefiltert werden können.

![image](images/q_ss8.png)

![image](images/q_ss9.png)

### Verknüpfte Fragebögen beantworten 

So beantworten Sie einen verknüpften Fragebogen: 
1. Wechseln Sie zur Engagement-Ansicht.
2. Klappen Sie die Tabelle „Zusätzliche Funktionen“ auf.
3. Klappen Sie die Untertabelle „Fragebögen“ auf.
4. Klicken Sie auf das Kebab-Menü ⋮ des verknüpften Fragebogens. 
5. Klicken Sie auf **Fragebogen beantworten**.

![image](images/q_ss15.png)

Verknüpfte Fragebögen erlauben keine externen bzw. anonymen Antworten, da für den Zugriff auf das Engagement ein DefectDojo-Zugang erforderlich ist.

## Antworten 

Wie erwähnt erzeugt jede Bereitstellung einer Fragebogenvorlage einen eigenen Antwortcontainer. Wird dieselbe Fragebogenvorlage mit mehreren Engagements verknüpft, entstehen getrennte Antwortsätze, und die Veröffentlichung eines allgemeinen Fragebogens wirkt sich nicht auf die Antwortsätze verknüpfter Fragebögen aus.

### Antworten auf allgemeine Fragebögen 

Nach Ablauf eines allgemeinen Fragebogens gilt:
- Es können keine weiteren Antworten mehr übermittelt werden.
- Alle bisherigen Antworten werden gespeichert und sichtbar.
- Der Fragebogen wird auf dem DefectDojo-Dashboard als nicht zugewiesener, beantworteter Engagement-Fragebogen aufgeführt.

Nach Schließen des Antwortzeitraums eines Fragebogens stehen drei Aktionen zur Verfügung: **Antworten anzeigen**, **Engagement erstellen** und **Benutzer zuweisen**.

#### Antworten auf Fragebögen ansehen 

Mit **Antworten anzeigen** werden alle Antworten des Fragebogens dargestellt.

#### Aus einem Fragebogen ein Engagement erstellen 

Nach Ablauf kann ein allgemeiner Fragebogen über ein Engagement mit einem Asset verbunden werden, indem Sie die Aktion **Engagement erstellen** wählen. Wählen Sie in der daraufhin angezeigten Dropdown-Liste ein Asset aus und klicken Sie auf **Engagement erstellen**. Anschließend kann ein neues Engagement erstellt und wie andere Engagements in DefectDojo mit Details wie Beschreibung, Version, Status, Tags usw. versehen werden.

![image](images/q_ss6.png)

![image](images/q_ss7.png)

#### Benutzer zuweisen 

Bei der Aktion „Benutzer zuweisen“ wählen Sie im Dropdown der verfügbaren Benutzer einen Benutzer aus. Wählen Sie einen Benutzer aus dem Dropdown-Menü und klicken Sie auf **Fragebogen zuweisen**; dadurch wird dieser Benutzer zum Eigentümer des Fragebogens.

### Antworten auf verknüpfte Fragebögen 

Verknüpfte Fragebögen bleiben verfügbar, solange das zugehörige Engagement aktiv ist. Die Antworten sind daher jederzeit einsehbar. 

Das Kebab-Menü ⋮ eines verknüpften Fragebogens enthält mehrere Funktionen zur Verwaltung des Fragebogens und der Antworten:
- **Fragebogen beantworten**: Diese Option erscheint, wenn ein Benutzer den verknüpften Fragebogen noch nicht beantwortet hat. Nach der Beantwortung erscheinen „Antworten anzeigen“ und „Antworten bearbeiten“. 
- **Antworten anzeigen**: Ermöglicht Benutzern, alle bisherigen Antworten auf den Fragebogen zu sehen. 
- **Antworten bearbeiten**: Ermöglicht einzelnen Benutzern, ihre früheren Antworten zu bearbeiten.
- **Benutzer zuweisen**: Weist den Fragebogen einem Benutzer zu. 
- **Mit einem anderen Engagement verknüpfen**: Öffnet ein Dropdown-Menü mit anderen Engagements, denen der Fragebogen zugewiesen werden kann. 
- **Fragebogen teilen**: Erzeugt einen Link, um den Fragebogen mit internen Benutzern zu teilen. 
- **Fragebogen löschen**: Hebt die Verknüpfung des Fragebogens mit dem Engagement auf und löscht alle bisher erfassten Antworten.

## Fragebögen löschen 

Das Löschen allgemeiner und verknüpfter Fragebögen hat je nach beabsichtigtem Ergebnis unterschiedliche Folgewirkungen.

### Allgemeine Fragebögen löschen 

Wenn Sie einen allgemeinen Fragebogen aus der Tabelle „Allgemeine Fragebögen“ im Bereich „Alle Fragebögen“ löschen, werden alle Antworten gelöscht, die vor dem Löschen über diese Bereitstellung erfasst wurden. Verknüpfte Fragebögen, die dieselbe Fragebogenvorlage verwenden, werden nicht gelöscht. 

### Verknüpfte Fragebögen löschen 

Beim Löschen eines verknüpften Fragebogens wird die Verknüpfung des Fragebogens mit dem Engagement aufgehoben. Alle Antworten, die vor dem Löschen innerhalb des Engagements erfasst wurden, gehen verloren. Allgemeine Fragebögen, die zuvor mit derselben Fragebogenvorlage bereitgestellt wurden, sind nicht betroffen. 

### Fragebogenvorlagen löschen

Um eine Fragebogenvorlage vollständig zu löschen, wählen Sie sie in der Tabelle „Fragebögen“ in der Ansicht „Alle Fragebögen“ aus und klicken Sie auf **Fragebogen löschen**. Dadurch werden die Fragebogenvorlage und alle zugehörigen Antworten aus allen Bereitstellungen dauerhaft gelöscht. Dieser Vorgang kann nicht rückgängig gemacht werden.
