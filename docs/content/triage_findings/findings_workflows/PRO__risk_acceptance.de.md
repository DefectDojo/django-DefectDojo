---
title: Risikoakzeptanzen
description: Risikoakzeptanzen in DefectDojo Pro nutzen
audience: pro
weight: 2
aliases:
- /de/en/working_with_findings/findings_workflows/risk_acceptances/
---

**Risikoakzeptanzen** sind ein spezieller Status, der Befunden entweder über Objekte für **vollständige Risikoakzeptanz** oder den Workflow für **einfache Risikoakzeptanz** zugewiesen werden kann.  Risikoakzeptanzen dienen dazu, die Entscheidung, einen verwundbaren Befund anzuerkennen, ohne ihn sofort zu beheben, formal zu dokumentieren und operativ umzusetzen.

DefectDojo Pro bietet erweiterte Funktionen für Risikoakzeptanzen, um Risikomanagement-Entscheidungen zu skalieren, darunter:
- **Produktübergreifende Risikoakzeptanzen**: Eine einzelne Risikoakzeptanz kann auf mehrere Produkte angewendet werden, sodass Sie alle Instanzen gleicher oder ähnlicher Befunde über Ihr gesamtes Asset-Portfolio hinweg in einem einzigen Risikoakzeptanz-Objekt bündeln können.
- **Massenverwaltung von Risikoakzeptanzen**: Filtern und suchen Sie nach bestimmten Befunden oder Schwachstellen-IDs und wenden Sie die Risikoakzeptanz gleichzeitig auf alle Ergebnisse an, unabhängig vom zugehörigen Asset.

### Zugriff auf risikoakzeptierte Befunde

Die Seitenleiste enthält einen Bereich für Risikoakzeptanzen, dessen Dropdown-Menü drei Unterabschnitte umfasst:
- **Risiko akzeptierte Befunde**
    - Dieser Bereich enthält eine Tabelle aller Befunde, deren Risiko akzeptiert wurde, sei es als Teil eines Objekts für vollständige Risikoakzeptanz oder über den Workflow für einfache Risikoakzeptanz.
- **Alle Risikoakzeptanzen**
    - Dieser Bereich enthält eine chronologisch sortierte Tabelle aller Objekte für vollständige Risikoakzeptanz.
- **Neue Risikoakzeptanz**
    - Ein Klick auf diese Option in der Seitenleiste startet den Workflow zur Erstellung eines Objekts für vollständige Risikoakzeptanz.

![Seitenleiste für Risikoakzeptanzen](images/RA_image1.png)

## Risikoakzeptanzen erstellen

Wenn das Risiko eines Befunds akzeptiert wird, geschieht Folgendes:

- Der Status des Befunds ist nicht mehr „Aktiv".
- Der Status des Befunds wird auf „Risiko akzeptiert" geändert.
- Der Befund wird nicht mehr in die Metriken einbezogen, erscheint aber weiterhin innerhalb des Tests, aus dem er stammt.

Das Risiko eines Befunds kann auf zwei Arten akzeptiert werden: entweder durch Hinzufügen zu einem Objekt für vollständige Risikoakzeptanz oder über den Workflow für einfache Risikoakzeptanz.

### Vollständige Risikoakzeptanzen

Eine vollständige Risikoakzeptanz ermöglicht es Benutzern, das Risiko mehrerer Befunde zu akzeptieren und sie dabei in einem einzigen Objekt zu bündeln, unabhängig davon, aus welchem Asset, Engagement oder Test sie stammen.

Wenn die Unternehmensrichtlinie formale, dokumentierte Risikoakzeptanzen verlangt oder Benutzer möchten, dass Risikoakzeptanzen nach einem bestimmten Datum automatisch ablaufen, ist die vollständige Risikoakzeptanz die beste Wahl, da sie den internen Entscheidungsprozess erfasst und als verlässliche Quelle dienen kann.

Jede vollständige Risikoakzeptanz fügt der Risikoakzeptanz zusätzlichen Kontext hinzu, etwa:
- den Namen des Risikoakzeptanz-Objekts.
- den Eigentümer des Risikoakzeptanz-Objekts.
- die Sicherheitsempfehlung und Entscheidung zum Umgang mit dem/den Befund(en).
- jeglichen Nachweis im Zusammenhang mit der Empfehlung oder Entscheidung.
- Details zur Empfehlung oder Entscheidung.
- den Benutzer, der das mit der Entscheidung verbundene Risiko akzeptiert.
- das Ablaufdatum.
    - ob der Status des Befunds nach Ablauf wieder auf „Aktiv" zurückgesetzt wird.
    - ob die SLA nach Ablauf neu gestartet wird.

Das Ablaufdatum ist ein Merkmal, das nur Objekten für vollständige Risikoakzeptanz vorbehalten ist, und ermöglicht es, risikoakzeptierte Befunde zu einem geeigneten Zeitpunkt erneut zu prüfen. Sobald eine Risikoakzeptanz abläuft, werden alle zugehörigen Befunde wieder auf Aktiv gesetzt.

Wenn Sie kein Datum angeben, werden die Werte Standard-Risikoakzeptanz / Standard-Ablauftage für Risikoakzeptanz aus der Seite Systemeinstellungen verwendet.

#### So schließen Sie eine vollständige Risikoakzeptanz ab

Ein Objekt für vollständige Risikoakzeptanz kann auf drei verschiedene Arten erstellt werden:
- über die Schaltfläche **Neue Risikoakzeptanz** in der Seitenleiste.
- über die Schaltfläche **Risikoakzeptanz hinzufügen** bei einem einzelnen Befund.
- über die Schaltfläche **Risikoakzeptanz-Aktionen**, die erscheint, nachdem Sie einen oder mehrere Befunde in einer Tabelle ausgewählt haben.

##### Neue Risikoakzeptanz (Seitenleiste)

Ein Klick auf "Neue Risikoakzeptanz" in der Seitenleiste öffnet eine Seite, auf der der Benutzer die Daten und Details für ein neues Objekt für vollständige Risikoakzeptanz festlegen kann. Auf der zweiten Seite kann der Benutzer die diesem Objekt hinzuzufügenden Befunde filtern und auswählen.

##### Risikoakzeptanz hinzufügen (Einzeln)

Öffnen Sie einen einzelnen Befund, klicken Sie auf das Zahnradsymbol oben rechts in der Ansicht und wählen Sie **Risikoakzeptanz hinzufügen**. Von dort aus können Sie den Befund entweder einem bestehenden Objekt für vollständige Risikoakzeptanz hinzufügen oder ein neues Objekt erstellen.

![Risikoakzeptanz im Untermenü des Befunds](images/RA_image2.png)

##### Risikoakzeptanz-Aktionen (Tabelle)

Wählen Sie einen oder mehrere Befunde in einer Tabelle aus, klicken Sie auf die oben erscheinende Schaltfläche **Risikoakzeptanz-Aktionen** und wählen Sie entweder **Zu neuem Risikoakzeptanz-Objekt hinzufügen** oder **Zu bestehendem Risikoakzeptanz-Objekt hinzufügen** und füllen Sie die erforderlichen Felder aus.

Befunde können jeweils nur einer einzigen Risikoakzeptanz hinzugefügt werden.  Ist die Schaltfläche Risikoakzeptanz-Aktionen nicht klickbar, liegt das wahrscheinlich daran, dass einer der ausgewählten Befunde bereits einem Objekt für vollständige Risikoakzeptanz hinzugefügt wurde.

![Schaltfläche „Risikoakzeptanz-Aktionen"](images/RA_image5.png)

##### Vollständige Risikoakzeptanzen bearbeiten

Sobald ein Objekt für vollständige Risikoakzeptanz erstellt wurde, können Sie dessen Details bearbeiten, eine Datei mit dem Nachweis der Risikoakzeptanz hochladen oder das Objekt vollständig löschen, indem Sie auf das Zahnradsymbol oben rechts in der Objektansicht klicken.

Über dasselbe Menü können Befunde dem Objekt auch hinzugefügt oder daraus entfernt werden. Alternativ können Befunde aus dem Objekt entfernt werden, indem Sie auf das ⋮-Kebab-Menü neben einem einzelnen Befund klicken, auf **Massenaktualisierung** klicken und im Dropdown-Menü „Status der einfachen Risikoakzeptanz" **Risiko nicht mehr akzeptieren** auswählen.

Wenn Sie schließlich Befunde zu einem Objekt für vollständige Risikoakzeptanz hinzufügen und dieses Objekt anschließend löschen, wird der Status der darin enthaltenen Befunde automatisch wieder auf „Aktiv" gesetzt.

### Einfache Risikoakzeptanzen

Einfache Risikoakzeptanzen besitzen weder zugehörige Metadaten noch ein Ablaufdatum. Sie eignen sich am besten für Fälle, in denen die Nachverfolgung risikoakzeptierter Befunde aus Compliance-Gründen weiterhin erforderlich ist, aber kein zugehöriges Objekt benötigt wird, um den Status der betroffenen Befunde zu verfolgen oder zu ändern.

Die einfache Risikoakzeptanz ist standardmäßig nicht aktiviert, kann aber im Bereich „Optionale Felder" der Asset-Einstellungen umgeschaltet werden, nachdem Sie auf das Zahnradsymbol oben rechts in der Asset-Ansicht geklickt haben.

![Aktivierung der einfachen Risikoakzeptanz](images/RA_image3.png)

Sobald sie aktiviert ist, kann die einfache Risikoakzeptanz über die Tabelle der Befunde innerhalb einer Testansicht ausgeführt werden.

#### So schließen Sie eine einfache Risikoakzeptanz ab

Sie können den Workflow für die einfache Risikoakzeptanz entweder über die Tabelle „Alle Befunde" (über die Seitenleiste zugänglich) oder über die Befundtabelle innerhalb eines bestimmten Tests durchführen. Der Workflow ist in beiden Fällen identisch.

Wählen Sie die Befunde aus, deren Risiko Sie akzeptieren möchten, und klicken Sie auf die oben in der Tabelle erscheinende Schaltfläche **Massenaktualisierung**. Wählen Sie dort im Dropdown-Menü „Status der einfachen Risikoakzeptanz" **Risiko akzeptieren** aus. Da das Risiko der Befunde über die einfache Risikoakzeptanz akzeptiert wurde, gibt es kein zugehöriges Objekt für vollständige Risikoakzeptanz. Die risikoakzeptierten Befunde sind über das Menü **Risiko akzeptierte Befunde** in der Seitenleiste zugänglich.

![Risikoakzeptanz-Aktionen in der Tabelle](images/RA_image4.png)

Möchten Sie umgekehrt das Risiko für zuvor risikoakzeptierte Befunde nicht mehr akzeptieren, wählen Sie **Risiko nicht mehr akzeptieren**. Wurde das Risiko eines Befunds über die einfache Risikoakzeptanz akzeptiert, muss diese Akzeptanz zunächst aufgehoben werden, bevor der Befund einem Objekt für vollständige Risikoakzeptanz hinzugefügt werden kann.

## Berechtigungen und Sichtbarkeit für Risikoakzeptanzen

Die Sichtbarkeit von Risikoakzeptanzen wird durch eine **eigene Mindestberechtigung geregelt, die sich von der Sichtbarkeit des Befunds unterscheidet**.  Ein Benutzer, der einen Befund sehen kann, hat nicht automatisch die Berechtigung, eine Risikoakzeptanz einzusehen, die diesen Befund enthält.

### Mindestrolle für Aktionen bei Risikoakzeptanzen

| Aktion | Mindestrolle für das übergeordnete Asset (Produkt) |
| --- | --- |
| Eine Risikoakzeptanz ansehen | Writer |
| Eine Risikoakzeptanz hinzufügen oder bearbeiten | Writer |

Die vollständige Rollen- und Berechtigungstabelle, die Berechtigungen für Risikoakzeptanzen zusammen mit anderen Aktionen auf Asset-Ebene auflistet, finden Sie unter [Berechtigungstabellen für Aktionen](/admin/user_management/user_permission_chart/#role-permission-chart).

## Ablauf und Wiederherstellung einer Risikoakzeptanz

Eine abgelaufene Risikoakzeptanz wird in der Tabelle der Risikoakzeptanzen neben ihrem Ablaufdatum mit **Abgelaufen** gekennzeichnet, sodass Sie auf einen Blick erkennen können, welche ihre Befunde nicht mehr unterdrücken.

Das Zahnradmenü einer Risikoakzeptanz — in der Tabelle oder auf ihrer Detailseite — bietet je nach Fall eine der folgenden Optionen an:

- **Risikoakzeptanz ablaufen lassen**, bei einer noch aktiven Risikoakzeptanz.  Sie läuft sofort ab, statt auf ihr Ablaufdatum zu warten, und ihre Befunde werden entsprechend den Einstellungen **Abgelaufene Befunde reaktivieren** und **SLA bei Ablauf neu starten** reaktiviert.
- **Risikoakzeptanz wiederherstellen**, bei einer bereits abgelaufenen Risikoakzeptanz.  Ihre Befunde werden erneut akzeptiert, und sie läuft nach der in der Einstellung **Standard-Tage für das Risikoakzeptanz-Formular** angegebenen Anzahl von Tagen erneut ab.

Beide Aktionen erfordern dieselbe Berechtigung wie das Bearbeiten der Risikoakzeptanz und verlangen zunächst eine Bestätigung.  Um stattdessen für einen bestimmten Zeitraum statt des Standardfensters wiederherzustellen, bearbeiten Sie das Ablaufdatum, anstatt die Aktion „Wiederherstellen" zu verwenden — siehe unten.

## Wenn das Ablaufdatum einer Risikoakzeptanz geändert wird

Das Ablaufdatum einer Risikoakzeptanz kann jederzeit nach der Erstellung bearbeitet werden.  Wie DefectDojo darauf reagiert, hängt davon ab, ob die Risikoakzeptanz derzeit aktiv ist oder bereits abgelaufen ist.

### Bearbeiten des Datums bei einer aktiven Risikoakzeptanz

Ist eine Risikoakzeptanz noch nicht abgelaufen — ihr Ablaufdatum liegt in der Zukunft, oder es ist gerade erst verstrichen, aber der periodische Ablauf-Job hat es noch nicht verarbeitet —, ist das Bearbeiten des Datums unkompliziert:

- Das neue Datum wird unverändert gespeichert.  Wählt der Benutzer `2027-01-15`, speichert die Risikoakzeptanz `2027-01-15`.
- Verknüpfte Befunde bleiben risikoakzeptiert.
- Das Risikoakzeptanz-Objekt bleibt aktiv.

### Vorziehen des Datums bei einer bereits abgelaufenen Risikoakzeptanz

Ist die Risikoakzeptanz **bereits abgelaufen** — das heißt, der periodische Job hat ihren Ablauf verarbeitet, die verknüpften Befunde wurden gemäß den Ablaufeinstellungen der Risikoakzeptanz wieder auf Aktiv gesetzt, und die Risikoakzeptanz befindet sich im abgelaufenen Zustand —, löst das Ändern des Ablaufdatums auf einen zukünftigen Wert einen **Wiederherstellungs**-Workflow aus:

- Die Risikoakzeptanz wird wiederhergestellt und befindet sich nicht mehr im abgelaufenen Zustand.
- Jeder Befund, der mit der Risikoakzeptanz verknüpft war und derzeit Aktiv ist, wird erneut akzeptiert (zurückgesetzt auf Risiko akzeptiert / Inaktiv).
- Die Endpunktstatus dieser Befunde werden aktualisiert, um die erneute Akzeptanz widerzuspiegeln.
- Ein Kommentar wird zu allen verknüpften Jira-Issues hinzugefügt, der die Wiederherstellung dokumentiert.

Das von Ihnen eingegebene Datum ist das Datum, das gespeichert wird.  Die Systemeinstellung **Standard-Tage für das Risikoakzeptanz-Formular** (Standard: 180) wird nur verwendet, wenn Sie kein bestimmtes Datum angefordert haben — zum Beispiel bei Verwendung der Aktion **Wiederherstellen**, die die Risikoakzeptanz wiederherstellt, ohne ihr Ablaufdatum zu bearbeiten, und es daher auf heute + N Tage setzt.

### Zurückverschieben des Datums oder Setzen auf ein weiterhin in der Vergangenheit liegendes Datum

Das Vorziehen des Ablaufdatums auf ein früheres, aber weiterhin zukünftiges Datum hat kein besonderes Verhalten zur Folge — die Risikoakzeptanz bleibt aktiv, und das neue Datum wird gespeichert.

Das Setzen des Datums auf ein in der Vergangenheit liegendes Datum lässt die Risikoakzeptanz nicht sofort über das Bearbeitungsformular ablaufen; der nächste periodische Ablauf-Job erfasst dies und wendet das übliche Ablaufverhalten an (Befunde werden gemäß der Einstellung **Abgelaufene Befunde reaktivieren** der Risikoakzeptanz reaktiviert, ein SLA-Neustart wird angewendet, falls **SLA bei Ablauf neu starten** gesetzt ist).

### Was die API offenlegt

API-Konsumenten können den Ablaufstatus einer Risikoakzeptanz über die Felder `expiration_date`, `expiration_date_handled` und `expiration_date_warned` des Risikoakzeptanz-Objekts einsehen:

- `expiration_date` ist das konfigurierte Datum.
- `expiration_date_handled` ist `null`, solange die Risikoakzeptanz aktiv ist, und wird auf einen Zeitstempel gesetzt, sobald der periodische Job den Ablauf verarbeitet hat.  Eine Risikoakzeptanz ist genau dann „abgelaufen", wenn `expiration_date_handled` nicht null ist.
- `expiration_date_warned` wird gesetzt, wenn das System die Ablaufwarnung versendet hat.

Bei einer Wiederherstellung werden sowohl `expiration_date_handled` als auch `expiration_date_warned` wieder auf `null` zurückgesetzt, und `expiration_date` enthält das von Ihnen gesendete Datum — oder heute + N Tage, wenn die Wiederherstellung ohne neues Datum ausgelöst wurde.  Tools, die Risikoakzeptanzen auf Statusänderungen überwachen, können das Feld `expiration_date_handled` als maßgebliches Flag für „Ist diese Risikoakzeptanz derzeit abgelaufen?" verwenden.

Ablauf und Wiederherstellung sind auch direkt verfügbar, sodass Sie sie nicht über das Bearbeiten von `expiration_date` steuern müssen:

- `POST /api/v2/risk_acceptance/{id}/expire/` lässt sie sofort ablaufen.  Gibt `400` zurück, wenn sie bereits abgelaufen ist.
- `POST /api/v2/risk_acceptance/{id}/reinstate/` stellt eine abgelaufene Risikoakzeptanz wieder her und akzeptiert die davon abgedeckten Befunde erneut.  Gibt `400` zurück, wenn sie nicht abgelaufen ist.  Senden Sie `expiration_date`, um die Dauer festzulegen; lassen Sie es weg, um heute + N Tage zu verwenden.

Beide akzeptieren einen optionalen Parameter `reason`, der zusammen mit dem ausführenden Benutzer als Notiz an der Risikoakzeptanz gespeichert wird.  Beide erfordern dieselbe Berechtigung wie das Bearbeiten der Risikoakzeptanz.

## Best Practices für Risikoakzeptanzen

Es ist zwar möglich, Befunde innerhalb von Objekten für vollständige Risikoakzeptanz mithilfe des Workflows für einfache Risikoakzeptanz zu beeinflussen (und umgekehrt), es ist jedoch im Allgemeinen vorzuziehen, sich standardmäßig ausschließlich auf einen der beiden Prozesse festzulegen, anstatt beide gleichzeitig zu aktivieren.

Wenn beispielsweise Objekte für vollständige Risikoakzeptanz der Standardansatz sind und das Risiko eines Befunds über die einfache Risikoakzeptanz akzeptiert wird, kann dies für Verwirrung sorgen, wenn kein zugehöriges Objekt existiert, das den betroffenen Befund enthält. Ebenso kann es zu ähnlicher Verwirrung führen, wenn Befunde normalerweise über die einfache Risikoakzeptanz akzeptiert werden und dann einige Befunde zu einem Objekt für vollständige Risikoakzeptanz hinzugefügt werden, obwohl für die meisten anderen Befunde keine solchen Objekte existieren.
