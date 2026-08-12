---
title: Rules Engine-Automatisierung
description: Arbeiten mit der Rules Engine-Automatisierung
weight: 1
audience: pro
aliases:
- /de/en/customize_dojo/rules_engine
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Rules Engine ist eine reine DefectDojo-Pro-Funktion.</span>

Mit der Rules Engine von DefectDojo können Sie benutzerdefinierte Workflows und Massenaktionen erstellen, um Befunde und andere Objekte zu verarbeiten.  Mit der Rules Engine können Sie automatisierte Aktionen erstellen, die ausgelöst werden, wenn ein Objekt einer Regel entspricht.

Die Rules Engine ist nur über die [Pro UI](/get_started/about/ui_pro_vs_os/) zugänglich.

**Suchen Sie den grafischen Editor?** [Rules Engine 2.0](/automation/rules_engine_2/about/) baut Automatisierung als visuelle Knotengraphen auf und fügt Verzweigungen, ausgehende Aktionen wie Tickets und Nachrichten, Spuren pro Lauf und ein Zustellungsprotokoll hinzu. Beide Engines laufen nebeneinander, und bestehende Regeln können [dorthin übertragen werden](/automation/rules_engine_2/converting_from_rules_engine/).

## Rules Engine aktivieren

Die Rules Engine befindet sich in der Beta-Phase und ist standardmäßig deaktiviert. Ein Superuser kann sie unter **Settings > Feature Flags** aktivieren, sowohl bei Cloud- als auch bei On-Premise-Instanzen. Siehe [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Aktuell können Regeln nur für Befunde erstellt werden, weitere Objekttypen werden jedoch in Zukunft unterstützt.

Regeln können manuell über die Seite **All Rules** ausgelöst oder so geplant werden, dass sie automatisch nach einem wiederkehrenden Zeitplan laufen.  Wenn eine Regel ausgelöst wird, wird sie auf alle vorhandenen Befunde angewendet, die den festgelegten Filterbedingungen entsprechen.

## Mögliche Regelaktionen
Jede Regel kann eine oder mehrere dieser Änderungen an einem Befund vornehmen, wenn sie erfolgreich ausgelöst wird (d. h. wenn die festgelegten Filterbedingungen erfüllt sind).

### Feldänderungen
* **Ein Feld festlegen** an einem Befund, einschließlich Titel, Beschreibung, Schweregrad, CVSSv3-Vektor, Aktiv, Verifiziert, Risiko akzeptiert, Falsch-positiv, Behoben
* **Text anhängen oder voranstellen** an den Titel oder die Beschreibung eines Befunds
* **Priorität festlegen** — überschreibt den berechneten Prioritätswert eines Befunds (überschreibt die automatische Prioritätsberechnung)
* **Risiko festlegen** — überschreibt die berechnete Risikostufe eines Befunds (überschreibt die automatische Risikoberechnung)
* **Addieren, Subtrahieren, Multiplizieren oder Dividieren** des Prioritätswerts eines Befunds um eine bestimmte Zahl

### Zuweisungen und Eigentümerschaft
* **Einen Benutzer zur Überprüfung festlegen** für einen Befund
* **Eine Gruppe als Eigentümer zuweisen** für einen Befund
* **Eine Mitigation-Richtlinie festlegen** an einem Befund — weist dem Befund eine vorkonfigurierte Mitigation-Richtlinie zu
* **Zur Risikoakzeptanz hinzufügen** — fügt einen Befund zu einem bestehenden Risikoakzeptanz-Datensatz hinzu (setzt risk_accepted=True, active=False, und verarbeitet die Jira-Integration sowie die Endpunkt-Status)

### Tags, Notizen und Warnungen
* **Tags hinzufügen** zu einem Befund
* **Eine Notiz hinzufügen** zu einem Befund
* **Eine Warnung erstellen** in DefectDojo mit benutzerdefiniertem Text

### Filterbedingungen
Regeln werden automatisch ausgelöst, wenn ein Befund bestimmte Filterbedingungen erfüllt. Weitere Informationen zu Filtern, die zum Erstellen von Regelaktionen verwendet werden können, finden Sie auf der Seite [Filter Index](/navigation/pro__filter_index).

## Eine neue Regel erstellen
Beginnen Sie diesen Vorgang auf der Seite Neue Regel.  Erweitern Sie in der [Pro UI](/get_started/about/ui_pro_vs_os/) unter **Manage Category** das Dropdown-Menü **Rules Engine** und klicken Sie auf **+ New Rule**.

![image](images/rules_engine_1.png)

### Schritt 1: Benennen Sie Ihre Regel
Geben Sie eine Bezeichnung als Identifikator für die neue Regel ein und klicken Sie auf Weiter.

![image](images/rules_engine_2.png)

### Schritt 2: Auslösebedingungen mit einem Filter festlegen
Sie sehen eine Tabelle mit allen Befunden (All Findings).  Legen Sie mithilfe dieser Tabelle die Filterbedingungen fest, um die Menge der Befunde einzugrenzen, auf die Ihre Regel angewendet werden soll.  Weitere Informationen zum Anwenden von Filtern auf eine Tabelle finden Sie in [unserem Leitfaden zur Pro UI](/get_started/about/ui_pro_vs_os/#navigational-changes).

Die Tabelle zeigt eine Vorschau der Liste vorhandener Befunde, die Sie gefiltert haben.

In diesem Screenshot filtern wir beispielsweise nach allen Befunden, die sich in 'Product One' befinden.  Sobald wir diesen Filter anwenden (indem wir außerhalb des Filtermenüs klicken), wird er unserer Liste der geltenden Filter hinzugefügt.

![image](images/rules_engine_3.png)

Im obigen Screenshot werden Aktionen auf alle Befunde angewendet, die sich im Produkt 'Product One' befinden.

Sobald Sie die gewünschten Filter festgelegt haben, klicken Sie auf die Schaltfläche Weiter.

### Schritt 3: Regelaktionen festlegen
Wählen Sie im Dropdown-Menü **Aktion** die Aktion aus, die Sie auf einen Befund anwenden möchten, der allen Filtern aus Schritt 2 entspricht.  Es können mehrere Aktionen angewendet werden.

Sie können zusätzliche bedingte Werte festlegen, die es Ihnen ermöglichen, weitere Aktionen auszuführen, wenn bestimmte Kriterien erfüllt sind.

![image](images/rules_engine_4.png)


Im obigen Screenshot haben wir beispielsweise 4 Regelaktionen festgelegt.  Zwei dieser Aktionen sind bedingt.

Alle Befunde, die den Filterbedingungen entsprechen, lösen diese unbedingten Aktionen aus:

* Der Befund wird der Benutzergruppe 'Group 1' zugewiesen
* Der Befund wird mit dem Tag `all_group_1` versehen

Befunde, die den Filterbedingungen sowie diesen **zusätzlichen** Bedingungen entsprechen, lösen zusätzlich zu den beiden oben aufgeführten unbedingten Aktionen diese bedingten Aktionen aus:

* **wenn der Befund den Schweregrad Kritisch hat**, wird er mit `critical_group_1` getaggt.
* **wenn der Befund den Schweregrad Hoch hat**, wird er mit `high_group_1` getaggt.

### Schritt 4 - Vorschau Ihrer Regel

Die Regelvorschau zeigt alle Befunde an, die durch diese Regel bei ihrer Ausführung geändert werden, zusammen mit einer Vorschau der ausgeführten Aktionen.  Bestätigen Sie, dass Sie mit den vorgeschlagenen Änderungen einverstanden sind, und klicken Sie auf Absenden, um Ihre Regel zu speichern.

Wenn Sie der Meinung sind, dass diese Regel nicht korrekt angewendet wurde, können Sie auf die Schaltfläche Zurück klicken und zu einem der vorherigen Schritte zurückkehren.

![image](images/rules_engine_5.png)

Im obigen Screenshot sehen wir beispielsweise eine Liste von Befunden, die von der Regel bei ihrer Ausführung betroffen sein werden.  Anhand der Spalten rechts in der Befundliste können wir erkennen, dass jedem dieser Befunde neue Tags und Eigentümer zugewiesen werden.

Sie werden erneut aufgefordert zu bestätigen, dass Ihre Regel erstellt werden soll.  Beachten Sie, dass die **Regel nicht sofort angewendet wird** und manuell ausgelöst werden muss.

## Eine Regel ausführen
Auf der Seite Alle Regeln können Sie eine Regel auswählen, die Sie ausführen möchten.  Klicken Sie auf den Titel der Regel, um weitere Details anzuzeigen.

![image](images/rules_engine_6.png)

Auf dieser Seite finden Sie unter **Metadaten** detaillierte Informationen zu dieser Regel, einschließlich Angaben dazu, wann die Regel zuletzt ausgelöst wurde.  Unter **Regelvorschau** sehen Sie außerdem eine Vorschau der Befunde, die von einer neuen Ausführung dieser Regel betroffen sein werden.

Um die Regel auszuführen, klicken Sie auf die grüne Schaltfläche Regel ausführen.  Sobald Sie bestätigt haben, dass Sie die Regel ausführen möchten, erscheint eine Meldung, dass die Regel zur Ausführung im Hintergrund eingereiht wurde.

Sobald die Regel erfolgreich ausgeführt wurde, wird die Anzahl der geänderten Elemente im Abschnitt Regel-Metadaten der Regelbeschreibung aktualisiert.

## Referenz: Regel-Metadaten
* **Regel für**: die Objekte, die von der Regel verwaltet werden.
* **Regelname**: der Name der Regel.
* **Filter**: die Anzahl der von dieser Regel angewendeten Filter.
* **Aktionen**: die Anzahl der von dieser Regel ausgeführten Aktionen.
* **Eigentümer**: der Benutzer, der diese Regel erstellt hat.
* **Status**: der Statusbericht der letzten Ausführung dieser Regel.
    'E' = 'Error', 'R' = 'Running', 'S' = 'Success'.
* **Letzter Lauf**: der Zeitstempel der letzten Ausführung dieser Regel.
* **Geänderte Elemente:** Anzahl der Objekte, die bei der letzten Regelausführung geändert wurden.
* **Übersprungene Elemente:** Anzahl der Objekte, die bei der letzten Regelausführung übersprungen wurden.  Wenn ein gefiltertes Objekt bereits dem 'Ergebnis' einer auf es angewendeten Regelaktion entspricht (wenn es zum Beispiel bereits die Tags hat, die durch eine Regelaktion angewendet würden), wird das Objekt einfach übersprungen.
