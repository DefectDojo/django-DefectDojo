---
title: Übermäßige Duplikate vermeiden
description: ''
weight: 4
aliases:
- /de/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport
---

Eine der Stärken von DefectDojo ist, dass das Datenmodell viele verschiedene Anwendungsfälle und Einsatzszenarien abdeckt. Wahrscheinlich werden Sie Ihr Vorgehen anpassen, sobald Sie die Software beherrschen und Möglichkeiten entdecken, Ihren Workflow zu optimieren.

Standardmäßig löscht DefectDojo keine der erstellten doppelten Befunde. Jeder Befund gilt als eigene Instanz einer Schwachstelle. **Doppelte Befunde** können daher ein Hinweis darauf sein, dass Ihr Workflow eine Prozessänderung braucht.

## Wann sind doppelte Befunde akzeptabel?

Doppelte Befunde deuten nicht immer auf ein Problem hin. In vielen Fällen ist es sinnvoll, Duplikate zu behalten. Zum Beispiel:

* Wenn Ihr Team interaktive Engagements nutzt und darüber berichtet. Wenn Sie einen eigenen Bericht speziell zu einem einzelnen Test erstellen möchten, wollen Sie wissen, ob ein Befund auftritt, der bereits früher entdeckt wurde.
* Wenn Sie Engagements haben, die inhaltlich getrennt sind (zum Beispiel, weil sie verschiedene Repositorys abdecken), möchten Sie Befunde markieren können, die an beiden Stellen auftreten.

## Auf redundante Importe prüfen

## Schritt 1: Übermäßige Duplikate aufräumen

Glücklicherweise können Sie mit den Deduplizierungseinstellungen von DefectDojo Duplikate massenweise löschen, sobald ein bestimmter Schwellenwert überschritten wurde. Diese Funktion erleichtert das Aufräumen. Mehr zu diesem Vorgang erfahren Sie in unserem Artikel zur **Befund-Deduplizierung** \<\-Link folgt hier.

### Schritt 2: Engagements auf Redundanzen prüfen

Nachdem Sie Ihre doppelten Befunde aufgeräumt haben, sollten Sie sich das Produkt ansehen, in dem sie enthalten waren, um eine klare Ursache zu finden. Möglicherweise stellen Sie fest, dass darin Engagements mit redundantem Kontext liegen.

#### Doppelte oder mehrfach genutzte Engagements

Engagements speichern einen oder mehrere Tests für einen bestimmten Testkontext. Diesen Kontext definieren letztlich Sie selbst. Wenn in Ihrem Produkt jedoch mehrere Engagements denselben Kontext haben sollten, fassen Sie sie am besten zu einem einzigen Engagement zusammen.  
​
### Fragen zur Definition des Engagement-Kontexts:

* Wenn ich einen Bericht über diese Arbeit erstellen wollte: Enthält das Engagement alle relevanten Informationen, die ich brauche?
* Erstellen wir Engagements proaktiv im Voraus, oder entstehen sie „ad\-hoc“ durch meinen Importprozess?
* Verwenden wir die richtige Art von Engagement \- **Interactive** oder **CI/CD**?
* Welcher Teil der Codebasis wird von den Tests bearbeitet: Ist jedes Repository ein eigener Kontext, oder können mehrere Repositorys einen gemeinsamen Testkontext bilden?
* Welche Stakeholder sind an dem Produkt beteiligt, und wie teile ich die Ergebnisse mit ihnen?

### Schritt 3: Auf redundante Tests prüfen

Wenn Sie feststellen, dass separate Tests erstellt wurden, die denselben Testkontext abbilden, kann das ein Hinweis darauf sein, dass diese Tests zu einem einzigen Reimport zusammengeführt werden können.

DefectDojo bietet zwei Methoden, um Testdaten zu importieren und Befunde zu erstellen: **Import** und **Reimport**. Beide Methoden sind sehr ähnlich. Der wesentliche Unterschied: **Import** erstellt immer einen neuen Test, während **Reimport** neue Daten zu einem bestehenden Test hinzufügen kann. Außerdem erstellt **Reimport** innerhalb dieses Tests keine doppelten Befunde.

Jedes Mal, wenn Sie neue Schwachstellenberichte in DefectDojo importieren, werden diese Berichte in einem Test-Objekt gespeichert. Ein Test-Objekt kann von einem Benutzer im Voraus erstellt werden, um einen künftigen **Import** aufzunehmen. Wenn ein Benutzer Daten importiert, ohne ein Test-Ziel anzugeben, wird ein neuer Test erstellt, in dem der eingehende Bericht gespeichert wird.

Tests sind flexible Objekte: Sie können zwar nur eine *Art* von Bericht aufnehmen, über die Methode **Reimport** aber mehrere Instanzen desselben Berichts verarbeiten. Mehr über Reimport erfahren Sie in unserem **[Artikel](/import_data/import_intro/reimport/)** zu diesem Thema.


## Reimport für laufende Tests verwenden

Wenn Sie eine CI/CD-Pipeline, einen täglichen Scan-Prozess oder andere regelmäßig eingehende Berichte haben, ist ein vorab eingerichteter Reimport-Prozess entscheidend, um übermäßige Duplikate zu vermeiden. Reimport fasst den Kontext und die Befunde eines wiederkehrenden Tests auf einer einzigen Test-Seite zusammen. Dort können Sie den Importverlauf einsehen und Änderungen an Schwachstellen über mehrere Scans hinweg nachvollziehen.

1. Erstellen Sie ein Engagement, in dem die CI/CD-Ergebnisse für das Objekt gespeichert werden, für das Sie CI/CD ausführen. Das kann ein Code-Repository sein, in dem CI/CD-Aktionen eingerichtet sind. In der Regel richten Sie für jede Pipeline ein eigenes Engagement ein, damit Sie schnell erkennen, woher die Befunde stammen.  
​
2. Jede CI/CD-Aktion importiert Daten in einem separaten Schritt nach DefectDojo, daher sollte jede davon einem eigenen Test zugeordnet werden. Führt jeder Pipeline-Durchlauf beispielsweise ein NPM\-audit sowie einen Abhängigkeits-Scan aus, muss jedes Scan-Ergebnis in einen Test fließen (untergeordnet zum Engagement).  
​
3. Sie müssen nicht bei jedem Durchlauf der CI/CD-Aktion einen neuen Test erstellen. Stattdessen können Sie die Daten per **Reimport** an dieselbe Test-Stelle übertragen.

### Reimport in der Praxis

DefectDojo vergleicht die eingehenden Scan-Daten mit den vorhandenen Scan-Daten und wendet dann folgende Änderungen auf die Befunde in Ihrem Test an:  
​
#### Befunde erstellen

Alle Schwachstellen, die im vorherigen Import nicht enthalten waren, werden dem Test automatisch als neue Befunde hinzugefügt.  
​
#### Bestehende Befunde ignorieren

Wenn eingehende Befunde mit bereits vorhandenen Befunden übereinstimmen, werden die eingehenden Befunde verworfen und nicht als Duplikate erfasst. Diese Befunde sind bereits erfasst \- ein neues Befund-Objekt ist nicht nötig. Auf der Test-Seite erscheinen diese Befunde als **Unverändert**.  
​
#### Befunde schließen

Wenn im Test Befunde vorhanden sind, die im eingehenden Bericht nicht auftauchen, können Sie diese Befunde automatisch auf Inaktiv und Behoben setzen lassen (unter der Annahme, dass diese Schwachstellen seit dem vorherigen Import beseitigt wurden). Auf der Test-Seite erscheinen diese Befunde als **Geschlossen**.

Wenn keine Befunde geschlossen werden sollen, können Sie dieses Verhalten beim Reimport deaktivieren:

* Deaktivieren Sie in der UI das Kontrollkästchen **Alte Befunde schließen**.
* Setzen Sie in der API **close\_old\_findings** auf **False**.  ​

#### Befunde wieder öffnen

* Wenn geschlossene Befunde bei einem Reimport erneut auftauchen, werden sie automatisch wieder geöffnet. Die Annahme ist, dass diese Schwachstellen trotz vorheriger Behebung erneut aufgetreten sind. Auf der Test-Seite werden diese Befunde als **Reaktiviert** geführt.

Wenn Sie einen Scanner ohne Triage verwenden oder geschlossene Befunde ohnehin nicht reaktiviert werden sollen, können Sie dieses Verhalten beim Reimport deaktivieren:

* Setzen Sie in der API **do\_not\_reactivate** auf **True**.
* Aktivieren Sie in der UI das Kontrollkästchen **Nicht reaktivieren**.

### Mit dem Importverlauf arbeiten

Der Importverlauf für einen Test ist auf der Seite **Test** unter der Überschrift **Test-Übersicht** aufgeführt.

Diese Tabelle zeigt jeden Import oder Reimport als einzelne Zeile mit einem **Zeitstempel** sowie den Spalten **Branch Tag, Build ID, Commit Hash** und **Version**, sofern diese angegeben wurden.

![image](images/Avoiding_Duplicates_Reimport_Recurring_Tests.png)

### Aktionen

Diese Spalte zeigt die Aktionen, die ein Import/Reimport ausgeführt hat.

* **\# created gibt die Anzahl der neuen Befunde an, die beim Import/Reimport erstellt wurden**
* **\# closed zeigt die Anzahl der Befunde, die durch einen Reimport geschlossen wurden (weil sie im eingehenden Bericht nicht vorhanden waren).**
* **\# left untouched zeigt die Anzahl der offenen Befunde, die von einem Reimport unverändert blieben (weil sie auch im eingehenden Bericht enthalten waren).**
* **\#** **reactivated** zeigt geschlossene Befunde, die durch einen eingehenden Reimport wieder geöffnet wurden.

### Warum nicht einfach Import verwenden?

Beide Methoden sind möglich, doch Import sollte für **neue Vorkommen** von Befunden und Daten reserviert bleiben, während Reimport für **weitere Iterationen** derselben Daten gedacht ist.

Wenn Ihre CI/CD-Pipeline jedes Mal einen Import ausführt und ein neues Test-Objekt erstellt, erhalten Sie mit jedem Import eine Sammlung einzelner Befunde, die Sie dann als separate Objekte verwalten müssen. Reimport entschärft dieses Problem und reduziert den „Aufräumaufwand“, wenn eine Schwachstelle behoben ist.

Mit Reimport speichern Sie jeden wiederkehrenden Bericht auf derselben Seite und behalten den zeitlichen Zusammenhang, wann dem Test neue Daten hinzugefügt wurden.

Wenn Sie dasselbe Scan-Tool jedoch an mehreren Orten oder in mehreren Kontexten einsetzen, kann es sinnvoller sein, für jeden Ort oder Kontext einen eigenen Test zu erstellen. Das hängt davon ab, wie Sie Ihre Daten organisieren möchten.
