---
title: Umfragen
description: Umfragen in DefectDojo Pro verstehen
audience: pro
weight: 2
---

In DefectDojo ist eine Umfragevorlage ein wiederverwendbarer Satz von Fragen, der dazu dient, Informationen von Entwicklern, Teams sowie internen und externen Stakeholdern zu sammeln. Sie können verwendet werden, um Input einzuholen, bevor die Arbeit beginnt, die Abstimmung zwischen Einzelpersonen und Teams während des Arbeitsfortschritts sicherzustellen und eine retrospektive Analyse nach Abschluss der Arbeit zu ermöglichen.

In DefectDojo besteht ein Umfragesystem aus drei Komponenten:
- **Umfragevorlagen**, die die Fragen gruppieren und ordnen.
- **Umfrage-Bereitstellungen**, das sind aktive Instanzen, die Antworten sammeln.
- **Antworten**, die von Benutzern übermittelten Antworten.

Das Erstellen einer Umfragevorlage macht sie nicht automatisch für Antworten verfügbar. Um Antworten zu sammeln, muss eine Umfragevorlage bereitgestellt werden.

## Berechtigungen

Der Bereich Umfragen in der Seitenleiste ist nur für Benutzer mit Superuser-Status sichtbar, und nur Superuser können Umfragevorlagen erstellen, Fragen erstellen und Umfragen bereitstellen.

Benutzer ohne Superuser-Status können weiterhin auf Umfragen antworten, die mit ihnen geteilt wurden, aber sie können diese oder die zugehörigen Fragen weder erstellen noch verwalten.

## Zugriff auf Umfragen und Fragen

Benutzer mit Superuser-Status können über die Seitenleiste durch Klicken auf die Option **Umfragen** auf Umfragen und Fragen zugreifen. Das Untermenü bietet Zugriff auf **Alle Umfragen** und **Alle Fragen** sowie die Möglichkeit, neue Umfragen und Fragen zu erstellen.

![image](images/pq_ss1.png)

### Zugriff auf Umfragen

Die Ansicht für Alle Umfragen enthält eine Tabelle mit allen Umfragevorlagen, einschließlich ihrer ID, ihres Namens, ihrer Beschreibung und ihres Aktivitätsstatus. Die Tabelle kann mithilfe von Stichwörtern gefiltert und durch Klicken auf die Kopfzeile jeder Spalte neu sortiert werden.

### Zugriff auf Fragen

Die Ansicht Alle Fragen enthält eine Tabelle mit Fragen, die einer Umfrage hinzugefügt werden können. Die Tabelle kann mithilfe von Stichwörtern gefiltert und durch Klicken auf die Kopfzeile jeder Spalte neu sortiert werden.

## Verwalten von Umfragevorlagen

### Umfragevorlagen erstellen

Umfragevorlagen können entweder durch Klicken auf **Neue Umfrage** in der Seitenleiste oder durch Klicken auf die Schaltfläche **Neue Umfrage** oben in der Ansicht Alle Umfragen erstellt werden.

![image](images/pq_ss2.png)

Der Umfragevorlage müssen ein Name und eine Beschreibung gegeben werden, und es muss mindestens eine Frage aus dem Dropdown-Menü ausgewählt werden, bevor sie erstellt werden kann.

#### Fragen zu einer bereits bestehenden Umfragevorlage hinzufügen

Um Fragen zu einer bereits bestehenden Umfragevorlage hinzuzufügen, klicken Sie auf das Kebab-Symbol ⋮ links neben der gewünschten Umfrage, klicken Sie auf **Umfrage bearbeiten**, wählen Sie im Dropdown-Menü die neuen Fragen aus, die der Umfrage hinzugefügt werden sollen, und klicken Sie dann auf **Absenden**.

Als bewährte Praxis wird dringend empfohlen, Fragen einer Umfragevorlage nicht zu ändern oder hinzuzufügen, solange diese über aktive Bereitstellungen verfügt. Das Hinzufügen neuer Fragen wirkt sich nicht auf bestehende Antworten aus, aber diese Antworten wurden übermittelt, ohne die neu hinzugefügten Fragen zu beantworten, was zu unvollständigen Daten führen kann.

### Fragen erstellen

Ähnlich wie bei Umfragevorlagen können Fragen entweder durch Klicken auf **Neue Frage** in der Seitenleiste oder durch Klicken auf die Schaltfläche **Neue Frage** oben in der Ansicht Alle Fragen erstellt werden.

#### Fragetypen

Beim Erstellen einer neuen Frage kann diese entweder als textbasierte Frage oder als Multiple-Choice-Frage formatiert werden, indem oben in der Ansicht Neue Frage **Textfrage** oder **Auswahlfrage** ausgewählt wird.

![image](images/pq_ss3.png)

#### Reihenfolge der Fragen

Die Reihenfolge einer Frage wird durch die Vergabe einer Ordnungsnummer festgelegt. Hat eine Frage beispielsweise die 1 im Feld Reihenfolge, erscheint sie oberhalb einer Frage mit der 2 im Feld Reihenfolge.

#### Optionale Antworten

Sowohl textbasierte Fragen als auch Multiple-Choice-Fragen können durch Klicken auf das entsprechende Kontrollkästchen als **Optional** gekennzeichnet werden.

#### Mehrfachantworten zulassen

Einer Multiple-Choice-Frage kann eine unbegrenzte Anzahl möglicher Antworten hinzugefügt werden. Durch Klicken auf das Kontrollkästchen **Mehrfachauswahl zulassen** können mehrere Antworten ausgewählt werden (nur für Multiple-Choice-Fragen verfügbar).

### Fragen bearbeiten

Um eine Frage zu ändern, navigieren Sie zur Ansicht Alle Fragen, klicken Sie auf das Kebab-Symbol ⋮ links neben der zu ändernden Frage, klicken Sie auf Frage bearbeiten, nehmen Sie die gewünschte Änderung vor und schließen Sie die Änderung durch Klicken auf Absenden ab. Fragen können nicht gelöscht werden.

![image](images/pq_ss4.png)

Es ist wichtig, das Bearbeiten von Fragen, die Teil aktiver Umfragen sind, sowie das Hinzufügen von Fragen zu aktiven Umfragen zu vermeiden. Dies wirkt sich nicht auf zuvor gesammelte Antworten aus, kann jedoch zu unvollständigen oder unzuverlässigen Daten führen.

## Umfragen bereitstellen

Sobald eine Umfragevorlage erfolgreich erstellt wurde, erzeugt das Bereitstellen einer Umfrage eine aktive Instanz, die Antworten entgegennimmt.

Um eine Umfrage bereitzustellen, navigieren Sie zur Ansicht Alle Umfragen, klicken Sie auf das Kebab-Symbol ⋮ links neben der bereitzustellenden Umfrage, klicken Sie auf **Umfrage öffnen**, legen Sie das Ablaufdatum fest und klicken Sie auf Absenden.

Wenn Sie dieselbe Umfrage erneut bereitstellen möchten, gehen Sie genauso vor. Alle Bereitstellungen erscheinen in der Tabelle Offene Umfrage-Instanzen in der Ansicht der Umfrage und können anhand ihrer ID, ihres Erstellungszeitpunkts und ihres Ablaufdatums unterschieden werden.

![image](images/pq_ss10.png)

Eine Umfrage schließt am gewählten Datum zur selben Uhrzeit, zu der sie bereitgestellt wurde. Wenn Sie beispielsweise eine Umfrage am 1. Februar 2026 um 8:00 Uhr bereitstellen und ihren Abschluss auf den 1. März 2026 festlegen, schließt die Umfrage am Morgen des 1. März 2026 um 8:00 Uhr.

Sobald eine Umfrage geöffnet wurde, können ihr Ablaufdatum und ihre Uhrzeit nicht mehr geändert werden. Wird ein anderer Zeitrahmen benötigt, muss eine neue Bereitstellung erstellt werden.

Sobald ein Ablaufdatum verstrichen ist, können für diese Bereitstellung der Umfrage keine Antworten mehr übermittelt werden, die Bereitstellung erscheint jedoch weiterhin in der Tabelle Offene Umfrage-Instanzen in der Ansicht der Umfrage.

#### Eine Umfrage teilen

Sobald eine Umfrage bereitgestellt wurde, kann sie mit anderen Benutzern geteilt werden, indem Sie auf das Symbol ↗ links neben der Umfrage in der Tabelle Offene Umfrage-Instanzen in der Ansicht der Umfragevorlage klicken. Dadurch wird ein für diese Bereitstellung eindeutiger Link angezeigt, der kopiert und an die vorgesehenen Empfänger weitergegeben werden kann.

![image](images/pq_ss5.png)

![image](images/pq_ss9.png)

#### Eine Umfrage schließen

Um eine Umfrage zu schließen, klicken Sie auf das rote **X** links neben der Umfrage in der Tabelle Offene Umfrage-Instanzen in der Ansicht der Umfragevorlage.

![image](images/pq_ss13.png)

Wie im späteren Abschnitt Antworten erwähnt, wird dadurch lediglich verhindert, dass weitere Antworten übermittelt werden. Zuvor übermittelte Antworten bleiben in der Tabelle Antworten unten in der Ansicht der Umfragevorlage sichtbar.

## Auf Umfragen antworten

Um auf eine Umfrage zu antworten, muss Nicht-Superusern der Link gemäß den Anweisungen im obigen Abschnitt [Eine Umfrage teilen](#sharing-a-survey) direkt zur Verfügung gestellt werden. Superuser können ebenfalls über denselben Link antworten.

#### Anonyme Antworten aktivieren

Standardmäßig sind Umfragen nur für DefectDojo-Benutzer zugänglich. Damit externe Parteien auf DefectDojo-Umfragen antworten können, stellen Sie sicher, dass die Option **Anonyme Umfrageantworten aktivieren** in den **Systemeinstellungen** aktiviert wurde. Diese finden Sie in der Seitenleiste unter **Einstellungen > System** (im Untermenü **Pro-Einstellungen** bei Instanzen, die noch das vorherige Menülayout verwenden).

![image](images/pq_ss6.png)

Externe Antworten erscheinen als anonym, da der Antwort keine DefectDojo-Benutzer-ID zugeordnet ist.

Wenn der Geltungsbereich einer Umfrage sowohl interne als auch externe Benutzer umfasst, geben Sie bei der Erstellung den Namen des Engagements in der Beschreibung an, damit die Ergebnisse gefiltert werden können.

![image](images/pq_ss7.png)

![image](images/pq_ss8.png)

## Antworten verwalten

Eine einzelne Umfragevorlage kann mehrfach gleichzeitig bereitgestellt werden. Alle Antworten auf mehrere Bereitstellungen derselben Umfragevorlage werden gemeinsam in der Tabelle Antworten unten in der Ansicht dieser Umfrage angezeigt.

![image](images/pq_ss11.png)

Auch nachdem eine Umfrage-Bereitstellung abgelaufen ist oder geschlossen wurde, bleiben ihre Antworten in der Tabelle Antworten unten in der Ansicht der Umfrage sichtbar, sofern die Umfragevorlage selbst nicht gelöscht wurde. Diese Antworten sind dauerhaft und können nicht entfernt werden.

Wie in der folgenden Abbildung gezeigt, gibt es derzeit keine offenen Umfrage-Bereitstellungen, dennoch sind Antworten aus früheren Bereitstellungen weiterhin in der Tabelle Antworten vorhanden.

![image](images/pq_ss12.png)

### Umfragevorlagen löschen

Um eine Umfragevorlage zu löschen, navigieren Sie zur Ansicht Alle Umfragen, klicken Sie auf das Kebab-Symbol ⋮ links neben der gewählten Umfrage und klicken Sie auf **Umfrage löschen**. Dadurch werden die Umfragevorlage sowie alle zugehörigen Bereitstellungen und Antworten dauerhaft gelöscht. Diese Aktion kann nicht rückgängig gemacht werden.