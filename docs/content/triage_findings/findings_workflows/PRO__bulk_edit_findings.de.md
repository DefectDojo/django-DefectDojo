---
title: Massenbearbeitung von Befunden
description: Wenden Sie Metadatenänderungen, Tags, Notizen und Überprüfungen in der
  DefectDojo Pro UI gleichzeitig auf viele Befunde an
audience: pro
weight: 3
---

In der DefectDojo Pro UI können Befunde von jeder Befundliste aus in großen Mengen bearbeitet werden — der Seite **Alle Befunde** oder der Befundliste innerhalb eines Tests.

## Befunde für die Massenbearbeitung auswählen

Verwenden Sie in jeder Befundtabelle die Kontrollkästchen neben den Befunden, um sie auszuwählen. Durch die Auswahl eines oder mehrerer Befunde wird eine **Massenaktionsleiste** mit den folgenden Steuerelementen angezeigt:

* **Massenbearbeitung** — öffnet ein einzelnes Formular, in dem Sie Metadatenänderungen, Tags, Notizen und Überprüfungsanfragen auf jeden ausgewählten Befund anwenden. Dies ist die zentrale, konsolidierte Oberfläche (weiter unten beschrieben).
* **Risikoakzeptanz** — fügt die ausgewählten Befunde einer neuen oder bestehenden **vollständigen Risikoakzeptanz** hinzu.
* **Befundgruppe** — fügt die ausgewählten Befunde einer neuen oder bestehenden **Befundgruppe** hinzu oder entfernt sie aus ihrer Gruppe.
* **Zusammenführen** — führt die ausgewählten Befunde zu einem einzigen Befund zusammen.
* **Löschen** — löscht die ausgewählten Befunde (mit Bestätigung).

Ein Steuerelement ist deaktiviert, wenn die Aktion nicht auf Ihre aktuelle Auswahl angewendet werden kann — siehe [Verfügbarkeit und übersprungene Befunde](#availability-and-skipped-findings).

## Massenbearbeitung

Die Schaltfläche **Massenbearbeitung** öffnet ein Formular, das alle Massenaktionen auf Feldebene enthält. Legen Sie nur die Felder fest, die Sie ändern möchten, und lassen Sie den Rest unverändert, klicken Sie dann auf **Ausgewählte Befunde aktualisieren**, um die Änderungen anzuwenden. Die verfügbaren Aktionen sind:

* **Schweregrad** — legt den Schweregrad fest (Kritisch, Hoch, Mittel, Niedrig oder Info).
* **Status** — wendet einen der folgenden Werte an: Aktiv, Verifiziert, Falsch-positiv, Außerhalb des Geltungsbereichs, Behoben oder In Fehlerüberprüfung.
* **Datum** — legt das Entdeckungsdatum fest.
* **Geplantes Behebungsdatum** und **Geplante Behebungsversion**.
* **Einfache Risikoakzeptanz** — Risiko akzeptieren oder Risikoakzeptanz aufheben. Wird nur auf Befunde angewendet, deren Produkt die einfache Risikoakzeptanz aktiviert hat; andere werden übersprungen.
* **Tags** — fügt den ausgewählten Befunden Tags hinzu, oder verwendet den Schalter **Anhängen / Ersetzen**, um den gesamten Tag-Satz jedes Befunds zu überschreiben (**Anhängen** fügt die Tags hinzu; **Ersetzen** ersetzt alle vorhandenen Tags).
* **Bestimmten Tag ersetzen** — tauscht einen benannten Tag gegen einen anderen aus (siehe unten).
* **Notiz** — fügt jedem ausgewählten Befund eine Notiz mit optionalem Notiztyp hinzu.
* **Überprüfung** — fordert eine Überprüfung der ausgewählten Befunde an oder hebt sie auf (siehe unten).
* **An Jira senden** — stellt die ausgewählten Befunde in die Warteschlange, um sie an Jira zu senden. Wird nur angezeigt, wenn die Jira-Integration aktiviert ist.
* **An Connector senden** — sendet die ausgewählten Befunde an Ihren konfigurierten Connector. Wird nur angezeigt, wenn diese Funktion aktiviert ist.

### Bestimmten Tag ersetzen

**Bestimmten Tag ersetzen** führt einen gezielten, nicht destruktiven Tag-Austausch durch. Geben Sie den zu ersetzenden Tag unter **Zu ersetzender vorhandener Tag** und den Ersatz unter **Neuer Tag** ein. Für jeden ausgewählten Befund, der den alten Tag tatsächlich trägt, entfernt DefectDojo diesen einen Tag und fügt den neuen hinzu — alle anderen Tags bleiben erhalten, und Befunde, die den alten Tag nicht haben, bleiben unverändert.

Dies unterscheidet sich vom Feld **Tags** oben: **Tags** *fügt* entweder Tags *hinzu* (Anhängen) oder *überschreibt den gesamten Tag-Satz* (Ersetzen), während **Bestimmten Tag ersetzen** nur den einen benannten Tag ändert.

### Überprüfung

Die Aktion **Überprüfung** verwaltet die Peer-Review für alle ausgewählten Befunde:

* **Überprüfung anfordern** — wählen Sie einen oder mehrere **Prüfer** aus und geben Sie eine **Überprüfungsnotiz** ein (erforderlich). Jeder ausgewählte Befund wird auf *In Überprüfung* gesetzt (Aktiv, nicht Verifiziert), die gewählten Prüfer werden zugewiesen, eine Notiz zur Überprüfungsanfrage wird hinzugefügt, und die Prüfer werden benachrichtigt.
* **Überprüfung aufheben** — geben Sie eine **Überprüfungsnotiz** ein (erforderlich), um die ausgewählten Befunde aus dem Status *In Überprüfung* zu nehmen und ihre zugewiesenen Prüfer zu entfernen.

Als Prüfer können Sie aus den Benutzern wählen, die über Bearbeitungszugriff auf die ausgewählten Befunde verfügen.

## Risikoakzeptanz, Befundgruppe, Zusammenführen und Löschen

Die verbleibenden Massenaktions-Schaltflächen öffnen jeweils einen eigenen Dialog:

* **Risikoakzeptanz** — erstellt eine neue **vollständige Risikoakzeptanz** für die ausgewählten Befunde oder fügt sie einer bestehenden hinzu.
* **Befundgruppe** — erstellt eine neue **Befundgruppe**, fügt die Befunde einer bestehenden Gruppe hinzu oder entfernt sie aus ihrer aktuellen Gruppe. Befundgruppen können nur innerhalb eines einzelnen **Tests** erstellt werden — Befunde aus unterschiedlichen Tests, Engagements oder Produkten können sich keine Gruppe teilen.
* **Zusammenführen** — führt mehrere ausgewählte Befunde (alle vom selben Asset) zu einem zusammen.
* **Löschen** — löscht die ausgewählten Befunde nach Bestätigung in einem Popup.

## Verfügbarkeit und übersprungene Befunde

Jede Massenaktion ist nur verfügbar, wenn sie auf Ihre gesamte Auswahl angewendet werden kann:

* **Massenbearbeitung**, Tags und Überprüfung erfordern, dass jeder ausgewählte Befund von Ihnen bearbeitet werden kann.
* **Risikoakzeptanz** ist nicht verfügbar, wenn ein ausgewählter Befund nicht bearbeitbar, bereits als Risiko akzeptiert oder ein Duplikat ist.
* Das Erstellen einer **Befundgruppe** erfordert, dass jeder Befund bearbeitbar, nicht gruppiert und im selben Test ist.
* **Zusammenführen** erfordert mehr als einen Befund, alle bearbeitbar und vom selben Asset.
* **Löschen** erfordert, dass jeder ausgewählte Befund von Ihnen gelöscht werden kann.

Wenn eine Aktion ausgeführt wird, aber einige Befunde nicht aktualisiert werden können — zum Beispiel weil sie von Ihnen nicht bearbeitet werden können, sich bereits in der Überprüfung befinden oder zu einem Produkt ohne aktivierte einfache Risikoakzeptanz gehören —, wendet DefectDojo die Änderung auf die übrigen an und zeigt eine Warnung **„Ein oder mehrere Befunde übersprungen“** an, die erklärt, warum jeder übersprungen wurde.
