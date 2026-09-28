---
title: Risikoakzeptanzen
description: Risikoakzeptanzen in DefectDojo OS nutzen
audience: opensource
weight: 2
---

**Risikoakzeptanzen** sind ein spezieller Status, der auf Befunde angewendet werden kann, um die Entscheidung, sie anzuerkennen, ohne sie sofort zu beheben, formal zu dokumentieren und umzusetzen.

Im Gegensatz zu DefectDojo Pro sind Risikoakzeptanzen in DefectDojo OS keine eigenständigen Objekte. Stattdessen sind Risikoakzeptanzen nur mit Engagements verknüpft. Sie können daher nur Befunde aus dem Engagement enthalten, in dem sie sich befinden. Wenn derselbe Befund in einem Test in 3 verschiedenen Engagements dreimal vorkommt, sind 3 verschiedene Risikoakzeptanzen erforderlich, um diese Befunde vollständig zu akzeptieren.

### Zugriff auf Risikoakzeptanzen

Risikoakzeptanzen enthalten Befunde, die für den bzw. die Test(s) innerhalb jedes Engagements spezifisch sind. Daher können sie über das Engagement aufgerufen werden, das den Test enthält, aus dem diese Befunde stammen.

![image](images/OS_RA_image1.png)

Eine vollständige Liste der einzelnen risikoakzeptierten Befunde ist im Untermenü **Risikoakzeptierte Befunde** des Bereichs **Befunde** in der Seitenleiste einsehbar.

![image](images/OS_RA_image2.png)

## Risikoakzeptanzen erstellen

Wenn ein Befund als Risiko akzeptiert wird, geschieht Folgendes:
- Der Status des Befunds ist nicht mehr „Aktiv“, er bleibt jedoch abfragbar, in Berichte aufnehmbar und auditierbar.
- Der Status des Befunds wird auf „Risiko akzeptiert“ geändert.
- Der Befund wird nicht mehr in die Metriken einbezogen, erscheint aber weiterhin in dem Test, aus dem er stammt.

Befunde können auf eine von zwei Arten als Risiko akzeptiert werden: Sie können entweder manuell zu einer **vollständigen Risikoakzeptanz** hinzugefügt werden, oder über den Workflow **einfache Risikoakzeptanz**.

### Vollständige Risikoakzeptanzen

Eine vollständige Risikoakzeptanz ermöglicht es Benutzern, das Risiko mehrerer Befunde innerhalb eines Engagements zu akzeptieren und sie zu einer einzigen Einheit zu bündeln. Wenn die Unternehmensrichtlinie formelle, dokumentierte Risikoakzeptanzen erfordert oder Benutzer bestimmte Aktionen auslösen möchten, sobald eine Risikoakzeptanz abläuft, sind vollständige Risikoakzeptanzen die beste Wahl, da sie den internen Entscheidungsprozess festhalten und als verlässliche Quelle dienen können.

Jede vollständige Risikoakzeptanz fügt zusätzlichen Kontext hinzu, wie zum Beispiel:
- Den Namen der Risikoakzeptanz.
- Den Eigentümer der Risikoakzeptanz.
- Die Sicherheitsempfehlung und die Entscheidung zum Umgang mit dem/den Befund(en).
- Jeden Nachweis im Zusammenhang mit der Empfehlung oder Entscheidung.
- Details zur Empfehlung oder Entscheidung.
- Den Benutzer, der das mit der Entscheidung verbundene Risiko akzeptiert.
- Das Ablaufdatum.
    - Ob der Status des Befunds bei Ablauf wieder auf „Aktiv“ zurückgesetzt wird.
    - Ob das SLA bei Ablauf neu gestartet wird.

Der Ablauf ist ein Merkmal, das nur vollständigen Risikoakzeptanzen vorbehalten ist, und ermöglicht es, alle als Risiko akzeptierten Befunde zu einem geeigneten Zeitpunkt erneut zu prüfen. Sobald eine vollständige Risikoakzeptanz abläuft, werden alle Befunde wieder auf Aktiv gesetzt. Wenn Sie kein Datum angeben, wird das Standard-Ablaufdatum für Risikoakzeptanzen von der Seite Systemeinstellungen verwendet.

Wichtig ist, dass es, da vollständige Risikoakzeptanzen auf einzelne Engagements beschränkt sind, keinen einzelnen Bereich gibt, in dem alle vollständigen Risikoakzeptanzen angezeigt werden können. Sie können nur innerhalb des jeweiligen Engagements eingesehen werden, das die Befunde enthält, die in der vollständigen Risikoakzeptanz enthalten sind.

#### So erstellen Sie eine vollständige Risikoakzeptanz

Um eine vollständige Risikoakzeptanz zu erstellen, navigieren Sie zur Engagement-Ansicht und klicken Sie auf das **+**-Symbol im Kästchen Risikoakzeptanz.

![image](images/OS_RA_image3.png)

Füllen Sie dort die Details der vollständigen Risikoakzeptanz aus und wählen Sie die einzuschließenden Befunde aus. **Akzeptierte Befunde** enthält eine Dropdown-Liste aller verfügbaren Befunde, die der Risikoakzeptanz hinzugefügt werden können. Die Liste der Befunde innerhalb des Engagements wird in absteigender Reihenfolge nach Schweregrad angezeigt (kritische Befunde oben, Befunde mit niedrigem Schweregrad unten). Wenn ein Befund zuvor bereits als Risiko akzeptiert wurde, erscheint er nicht in der Dropdown-Liste.

Nach Abschluss erscheint die vollständige Risikoakzeptanz im Kästchen Risikoakzeptanz in der Engagement-Ansicht.

Eine Risikoakzeptanz kann auch erstellt werden, indem Sie im ⋮-Kebab-Menü eines einzelnen Befunds auf die Schaltfläche **Risikoakzeptanz hinzufügen** klicken.

![image](images/OS_RA_image7.png)

#### Umgang mit vollständigen Risikoakzeptanzen

Sobald eine vollständige Risikoakzeptanz erstellt wurde, kann sie geöffnet werden, um die hinzugefügten Befunde sowie alle bei der Erstellung eingegebenen Details anzuzeigen (z. B. Datum, Eigentümer, Entscheidung, Ablauf usw.).

Um einen Befund aus einer vollständigen Risikoakzeptanz zu entfernen, klicken Sie in der Tabelle Akzeptierte Befunde auf die Schaltfläche **Entfernen**.

![image](images/OS_RA_image8.png)

Die Ansicht der vollständigen Risikoakzeptanz enthält außerdem unten eine Tabelle mit allen weiteren Befunden aus Tests innerhalb dieses Engagements. Von dort aus können Sie zusätzliche Befunde auswählen und der vollständigen Risikoakzeptanz hinzufügen.

Zusätzlich gibt es eine Notizfunktion, mit der Benutzer der vollständigen Risikoakzeptanz zusätzlichen Kontext hinzufügen können. Alle öffentlichen Notizen erscheinen in allen für die vollständige Risikoakzeptanz erstellten Berichten. Notizen, die als **Privat** gekennzeichnet sind, sind nur für ihren Verfasser und für Superuser sichtbar und werden nicht in Berichte aufgenommen.

Wichtig: Wird eine vollständige Risikoakzeptanz vollständig gelöscht, wird der Status der darin enthaltenen Befunde automatisch wieder auf „Aktiv“ zurückgesetzt.

### Einfache Risikoakzeptanzen

Während die vollständige Risikoakzeptanz standardmäßig aktiviert ist, muss die einfache Risikoakzeptanz manuell aktiviert werden, entweder bei der Erstellung eines Assets oder in dessen Einstellungen.

![image](images/OS_RA_image4.png)

Eine einfache Risikoakzeptanz kann auf eine von zwei Arten durchgeführt werden:
1. Innerhalb einer Test-Ansicht über das Menü Massenbearbeitung, das erscheint, nachdem ein oder mehrere Befunde in der Befundtabelle ausgewählt wurden.

![image](images/OS_RA_image5.png)

2. Durch Klicken auf **Risiko akzeptieren** im ⋮-Kebab-Menü eines einzelnen Befunds.

![image](images/OS_RA_image6.png)

Sobald ein Befund einfach als Risiko akzeptiert wurde, erscheint er weiterhin in der Befundtabelle des Tests, aber der Status wird auf **Inaktiv, Risiko akzeptiert** geändert. Eine vollständige Liste der einzelnen risikoakzeptierten Befunde ist im Untermenü **Risikoakzeptierte Befunde** des Bereichs **Befunde** in der Seitenleiste einsehbar.

Wenn Sie einen Befund einfach als Risiko akzeptieren und ihn später einer vollständigen Risikoakzeptanz hinzufügen möchten, muss die Risikoakzeptanz zunächst aufgehoben werden, bevor er einer vollständigen Risikoakzeptanz hinzugefügt werden kann.

## Wenn das Ablaufdatum einer Risikoakzeptanz geändert wird

Das Ablaufdatum einer vollständigen Risikoakzeptanz kann jederzeit nach der Erstellung bearbeitet werden.  Wie DefectDojo darauf reagiert, hängt davon ab, ob die Risikoakzeptanz derzeit aktiv ist oder bereits abgelaufen ist.

### Bearbeiten des Datums bei einer aktiven Risikoakzeptanz

Wenn eine Risikoakzeptanz noch nicht abgelaufen ist — ihr Ablaufdatum liegt in der Zukunft oder ist gerade erst verstrichen, wurde aber vom periodischen Ablauf-Job noch nicht verarbeitet — ist das Bearbeiten des Datums unkompliziert:

- Das neue Datum wird unverändert gespeichert.
- Verknüpfte Befunde bleiben als Risiko akzeptiert.
- Das Risikoakzeptanz-Objekt bleibt aktiv.

### Verschieben des Datums bei einer bereits abgelaufenen Risikoakzeptanz nach vorn

Wenn die Risikoakzeptanz **bereits abgelaufen ist** — das heißt, der periodische Ablauf-Job hat ihren Ablauf verarbeitet und die verknüpften Befunde wurden wieder auf Aktiv gesetzt —, löst das Ändern des Ablaufdatums auf einen zukünftigen Wert einen **Wiederherstellungs**-Workflow (reinstate) aus:

- Die Risikoakzeptanz wird wiederhergestellt und befindet sich nicht mehr im abgelaufenen Zustand.
- Jeder mit der Risikoakzeptanz verknüpfte Befund, der derzeit Aktiv ist, wird erneut akzeptiert (zurückgesetzt auf Risiko akzeptiert / Inaktiv).
- In allen verknüpften Jira-Issues wird ein Kommentar veröffentlicht, der die Wiederherstellung protokolliert.

Das von Ihnen eingegebene Datum ist das Datum, das gespeichert wird.  Die Systemeinstellung **Standardanzahl Tage für Risikoakzeptanz-Formular** (Standard: 180) wird nur verwendet, wenn Sie kein bestimmtes Datum angefordert haben — zum Beispiel wenn Sie die Aktion **Wiederherstellen** verwenden, die die Risikoakzeptanz wiederherstellt, ohne ihr Ablaufdatum zu bearbeiten, und sie daher auf heute + N Tage setzt.

### Verschieben des Datums nach hinten oder auf ein Datum, das noch in der Vergangenheit liegt

Das Verschieben des Ablaufdatums auf ein früheres, aber dennoch in der Zukunft liegendes Datum hat kein besonderes Verhalten zur Folge — die Risikoakzeptanz bleibt aktiv, und das neue Datum wird gespeichert.

Das Setzen des Datums auf ein Datum in der Vergangenheit lässt die Risikoakzeptanz nicht sofort über das Bearbeitungsformular ablaufen; der nächste periodische Ablauf-Job erfasst sie und wendet das Standard-Ablaufverhalten an.  Das gilt auch für eine **bereits abgelaufene** Risikoakzeptanz: Ein Datum in der Vergangenheit ist dennoch das von Ihnen gewählte Datum, es wird also unverändert gespeichert, und der nächste Ablauf-Durchlauf lässt die Risikoakzeptanz erneut ablaufen.

### Was die API bereitstellt

API-Konsumenten können den Ablaufstatus des Risikoakzeptanz-Objekts über die Felder `expiration_date`, `expiration_date_handled` und `expiration_date_warned` beobachten.  Eine Risikoakzeptanz ist genau dann „abgelaufen“, wenn `expiration_date_handled` nicht null ist.  Bei einer Wiederherstellung werden sowohl `expiration_date_handled` als auch `expiration_date_warned` wieder auf `null` zurückgesetzt, und `expiration_date` enthält das von Ihnen gesendete Datum — oder heute + N Tage, wenn kein Datum angefordert wurde.

Das Ablaufenlassen und Wiederherstellen ist auch direkt verfügbar, sodass Sie dies nicht über die Bearbeitung von `expiration_date` steuern müssen:

- `POST /api/v2/risk_acceptance/{id}/expire/` lässt sie sofort ablaufen.  Gibt `400` zurück, wenn sie bereits abgelaufen ist.
- `POST /api/v2/risk_acceptance/{id}/reinstate/` stellt eine abgelaufene Risikoakzeptanz wieder her und akzeptiert die von ihr abgedeckten Befunde erneut.  Gibt `400` zurück, wenn sie nicht abgelaufen ist.  Senden Sie `expiration_date`, um die Dauer festzulegen; lassen Sie es weg, um heute + N Tage zu verwenden.

Beide akzeptieren ein optionales `reason`, das zusammen mit der Angabe, wer die Aktion durchgeführt hat, als Notiz an der Risikoakzeptanz vermerkt wird.  Beide erfordern dieselbe Berechtigung wie das Bearbeiten der Risikoakzeptanz.

## Bewährte Praktiken für Risikoakzeptanzen

Als Standardpraxis ist es im Allgemeinen vorzuziehen, entweder ausschließlich vollständige Risikoakzeptanzen oder ausschließlich einfache Risikoakzeptanzen zu verwenden, anstatt beide zu nutzen.

Wenn beispielsweise vollständige Risikoakzeptanzen der Standardansatz sind und ein Befund einfach als Risiko akzeptiert wird, kann dies zu Verwirrung führen, wenn es keine zugehörige vollständige Risikoakzeptanz gibt, die den betroffenen Befund enthält. Ebenso kann es zu Verwirrung führen, wenn Befunde normalerweise einfach als Risiko akzeptiert werden und dann einige Befunde einer vollständigen Risikoakzeptanz hinzugefügt werden, obwohl es für die meisten anderen Befunde keine solchen Objekte gibt.
