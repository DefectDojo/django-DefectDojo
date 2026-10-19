---
title: 🌐 Universal Parser
description: ''
draft: 'false'
weight: 1
audience: pro
aliases:
- /en/connecting_your_tools/universal_parser
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Der Universal Parser ist nur in DefectDojo Pro verfügbar.</span>

Der Universal Parser ist für jede DefectDojo-Pro-Instanz aktiviert; es gibt nichts zu aktivieren. Weitere Informationen finden Sie in unserer [Ankündigungspräsentation](https://community.defectdojo.com/universalparser).

## Über den Universal Parser
DefectDojo verfügt über eine große, regelmäßig aktualisierte Bibliothek an Parsern, die Sicherheitsteams beim Einlesen von Daten unterstützt. Manchmal verwenden Anwender jedoch ein Tool, das von den Parsern nicht unterstützt wird, oder sie möchten Daten anders in das DefectDojo-Modell importieren, als der Parser es tut.

Der Universal Parser von DefectDojo soll Anwendern mit nicht unterstützten Berichtstypen einen Weg bieten, **beliebige JSON-, CSV- oder XML-Dateien** zu importieren und zuzuordnen.

**Der Universal Parser ist:**

* Eine schnelle Möglichkeit, Dateiformate zu unterstützen, für die es keine Community-Parser gibt, etwa Berichte interner Tools
* Ein Werkzeug, mit dem Sie Daten einlesen können, selbst wenn ein Community-Parser veraltet ist oder Befunde nicht so strukturiert, wie Sie es möchten
* Eine Alternative zu eigenen Skripten, mit denen Tool-Berichte in das CSV/JSON-Format umgewandelt werden, das der Scan-Typ „Generic Findings Import“ erwartet
* So konzipiert, dass er für jeden einfach zu bedienen ist, ohne Programmierkenntnisse und mit minimaler Konfiguration

**Der Universal Parser ist nicht:**

* Ein vollständiger Ersatz für Open-Source-Parser, Connectors oder sorgfältig aufbereitete „Generic Findings Import“-Berichte
* In der Lage, nuancierte, verzweigte Logik zur Strukturierung von Befunden zu verarbeiten

Die Konfiguration des Universal Parsers ist nur in der Pro-UI verfügbar. Sie können jedoch weiterhin Scans mit einem Universal Parser über die alte UI oder die API importieren.

## Schritt 1: Einen neuen Universal Parser erstellen

Sie können einen neuen Universal Parser erstellen, indem Sie in der Navigationsleiste im Bereich „Import“ auf die Schaltfläche „New Universal Parser“ klicken, oder über den Link auf der Seite „Add Findings“.

![image](images/universal_parser.png)

Der erste Bildschirm fragt nach einer Scan-Datei und einem Parser-Namen.

![image](images/universal_parser_2.png)

Die Datei sollte:

* Eine erkannte Dateiendung haben (siehe die unterstützten Dateiendungen unten)
* Genügend befundähnliche Objekte enthalten, um für reale Berichte repräsentativ zu sein - d. h. eine Datei, die Werte in allen optionalen Feldern enthält
* Nicht größer als etwa 1-2 MB sein - darüber hinaus dauert das Parsen der Datei in der Regel nur länger, ohne dass dies einen Vorteil bringt

Der Parser-Name wird beim Erstellen des Test_Type für diesen neuen Parser verwendet. Sie finden Ihren neu erstellten Universal Parser im Dropdown-Menü der Scan-Typen auf der Seite „Add Findings“ unter einem Namen wie „Universal Parser - MyCustomParser“. Parser-Namen müssen eindeutig sein, um Verwechslungen bei der Auswahl eines Scan-Typs für Importe zu vermeiden.

## Schritt 2: Ihre Befundfelder zuordnen

![image](images/universal_parser_3.png)

Nachdem Sie eine Beispiel-Scan-Datei hochgeladen, einen Parser-Namen ausgewählt und auf „Next“ geklickt haben, können Sie auf der folgenden Seite konfigurieren, wie dieser Universal Parser die Befundfelder beim Import mit dieser Konfiguration befüllt. Auf der rechten Seite finden Sie eine Auswahl von DefectDojo-Befundfeldern (Ausgabefelder). Über die Dropdown-Menüs links neben jedem Ausgabefeld können Sie auswählen, welche(s) Element(e) (Eingabefelder) aus der Struktur Ihrer Scan-Datei zum Befüllen verwendet werden sollen.

Beispiel:

Wenn Sie eine Scan-Datei im JSON-Format hochgeladen haben, die wie folgt aussieht:

```
{
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345",
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "LOW",
            "CVE": "CVE-2025-54321",
            ...
        },
        ...

    ]
}
```

Sie sehen eine hierarchische Darstellung der eindeutigen Felder, die wir anhand der Struktur der Eingabedatei erkannt haben, mit Symbolen, die den Typ jedes Feldes anzeigen (sofern wir diesen bestimmen können). Anschließend können Sie im Dropdown-Menü, das das Ausgabefeld „Title“ befüllt, das Eingabefeld „title“ auswählen, das Eingabefeld „description“ kann dem Ausgabefeld „Description“ zugeordnet werden, und so weiter.

Die Namen der Eingabefelder müssen nicht mit den Namen der Ausgabefelder übereinstimmen, und Ihre Scan-Datei enthält möglicherweise nicht für alle DefectDojo-Ausgabefelder ein Äquivalent.

### Zuordenbare Befundfelder

Die folgende Tabelle listet alle DefectDojo-Befundfelder (Ausgabefelder) auf, denen Sie ein Eingabefeld zuordnen können. Ihre Scan-Datei enthält nicht zwangsläufig ein Äquivalent für alle diese Felder — ordnen Sie nur das zu, was tatsächlich vorhanden ist.

* **Erforderlich** — diesem Ausgabefeld muss mindestens ein Eingabefeld zugeordnet sein, bevor Sie den Parser speichern können.
* **Akzeptiert mehrere Eingaben** — dieses Ausgabefeld kann aus mehr als einem Eingabefeld befüllt werden. Wenn Sie mehrere zuordnen, wird jeder Wert unter einer Überschrift mit dem Namen seines Eingabefelds angezeigt (siehe [Mehrfachauswahlfelder](#multi-select-fields)).

| Output field | Required | Accepts multiple inputs | Description |
|---|:---:|:---:|---|
| Title | ✅ | | Eine kurze Beschreibung der Schwachstelle. |
| Severity | ✅ | | Der Schweregrad dieser Schwachstelle (Critical, High, Medium, Low, Info). Bei unbekanntem Wert wird standardmäßig „Info“ verwendet. |
| Description | ✅ | ✅ | Ausführlichere, beschreibende Informationen zur Schwachstelle. |
| Date | | | Das Datum, an dem die Schwachstelle entdeckt wurde. |
| CWE | | | Die CWE-Nummer, die dieser Schwachstelle zugeordnet ist. |
| CVSS v3 Vector | | | Der Common Vulnerability Scoring System Version 3 (CVSSv3)-Vektor dieser Schwachstelle. |
| CVSS v4 Vector | | | Der Common Vulnerability Scoring System Version 4 (CVSSv4)-Vektor dieser Schwachstelle. |
| Mitigation | | ✅ | Text, der beschreibt, wie die Schwachstelle am besten behoben werden kann. |
| Impact | | ✅ | Text, der die Auswirkungen dieser Schwachstelle auf Systeme, Produkte, das Unternehmen usw. beschreibt. |
| References | | ✅ | Die externe Dokumentation, die für diese Schwachstelle verfügbar ist. |
| Severity Justification | | ✅ | Text, der begründet, warum dieser Schwachstelle ein bestimmter Schweregrad zugeordnet wurde. |
| Steps to Reproduce | | ✅ | Text, der die Schritte beschreibt, die zur Reproduktion der Schwachstelle/des Fehlers erforderlich sind. |
| Component Name | | | Name der betroffenen Komponente (Bibliotheksname, Teil eines Systems, ...). |
| Component Version | | | Version der betroffenen Komponente. |
| File Path | | | Identifizierte Datei(en), die die Schwachstelle enthalten. |
| Line Number | | | Quellcode-Zeilennummer des Angriffsvektors. |
| Active | | | Gibt an, ob diese Schwachstelle aktiv ist oder nicht. Standardmäßig „true“. |
| Verified | | | Gibt an, ob diese Schwachstelle manuell vom Tester verifiziert wurde. Standardmäßig „false“. |
| False Positive | | | Gibt an, ob diese Schwachstelle vom Tester als Falsch-positiv eingestuft wurde. Standardmäßig „false“. |
| Duplicate | | | Gibt an, ob diese Schwachstelle ein Duplikat anderer gemeldeter Schwachstellen ist. Standardmäßig „false“. |
| EPSS Score | | | EPSS-Score für die CVE — wie wahrscheinlich es ist, dass die Schwachstelle in den nächsten 30 Tagen ausgenutzt wird. Der Wert muss zwischen 0,0 und 1,0 liegen. |
| EPSS Percentile | | | EPSS-Perzentil für die CVE — wie viele CVEs gleich oder niedriger bewertet sind als diese. Der Wert muss zwischen 0,0 und 1,0 liegen. |
| Unique ID From Tool | | | Technische Schwachstellen-ID aus dem Quell-Tool. Ermöglicht die Nachverfolgung eindeutiger Schwachstellen. |
| Vuln ID from Tool | | | Nicht eindeutige technische ID aus dem Quell-Tool, die dem Schwachstellentyp zugeordnet ist. |
| Tags | | | String-Tags, die diesen Befund beschreiben. |
| Endpoints | | | Die Hosts/URLs innerhalb des Produkts, die für diese Schwachstelle anfällig sind. |
| Vulnerability IDs | | | Eine oder mehrere Schwachstellen-Advisory-Kennungen, die diesem Befund zugeordnet sind (am häufigsten CVEs). |

> **Hinweis:** Im obigen Beispiel würde ein `CVE`-Eingabefeld dem Ausgabefeld **Vulnerability IDs** zugeordnet werden — DefectDojo verfügt über kein Befundfeld, das wörtlich „CVE“ heißt.

### Erforderliche Felder
Die folgenden Ausgabefelder erfordern eine Zuordnung zu einem Eingabefeld:

* Title
* Severity
* Description

### Zu den Schweregraden
Ein Universal Parser akzeptiert jede Groß-/Kleinschreibungsvariante der DefectDojo-Schweregrade - „CRITICAL“, „Critical“, „cRiTiCaL“ usw. - und wendet sie auf Ihre Befunde an. Jeder Wert, der keinem DefectDojo-Schweregrad entspricht, wird durch „Info“ ersetzt. Dies entspricht der Funktionsweise von Parsern und Connectors: Unbekannte Werte werden im Allgemeinen auf „Info“ abgebildet.

### Mehrfachauswahlfelder
Manche Ausgabefelder akzeptieren mehrere Eingabefelder. Wenn Sie mehr als ein Eingabefeld auswählen, wird der Wert dieses Feldes unter einer Überschrift mit dem Namen des jeweiligen Eingabefelds angezeigt.

Beispiel

`description`

Dieser Wert stammt aus einem Feld namens „description“ in der Eingabedatei

`detailed_description`

Dieser Wert stammt aus einem Feld namens „detailed_description“ in der Eingabedatei

## Schritt 3: Vorschau Ihrer Befunde

Nachdem Sie Ihre Zuordnungen von Eingabefeldern zu Ausgabefeldern ausgewählt haben, können Sie auf die Schaltfläche „Next“ klicken, um eine Vorschau anzuzeigen, wie die Befunde aus Ihrer Eingabedatei nach dem Import in DefectDojo mit Ihrer gewählten Konfiguration aussehen werden. Bei einigen Feldern gibt es eine Schaltfläche „Expand“, mit der Sie das vollständige, gerenderte MarkDown dieses Feldes ansehen können. Wir zeigen nur eine Vorschau der ersten 25 Befunde Ihrer Eingabedatei an, Sie sehen jedoch auch, wie viele Befunde insgesamt in der Scan-Datei erkannt wurden.

Wenn die Vorschau nicht Ihren Erwartungen entspricht, können Sie über die Schaltfläche „Back“ die Zuordnungen anpassen. Sobald Sie mit Ihrer Konfiguration zufrieden sind, klicken Sie auf „Submit“, um Ihren neuen Universal Parser zu erstellen. Dabei wird kein Import automatisch durchgeführt.

Sobald Ihr Universal Parser erstellt wurde, werden Sie auf die Seite „Add Findings“ weitergeleitet, wo Sie eine Scan-Datei hochladen und importieren können, die der Struktur der in Schritt 1 bereitgestellten Beispieldatei entspricht.

## Weitere Hinweise zur Konfiguration des Universal Parsers

### Die richtigen Eingabefelder auswählen

Jeder Hersteller kann sehr unterschiedliche Scan-Berichtsformate erzeugen, von denen einige besser zum Befundmodell von DefectDojo passen als andere. Wir erlauben dabei erhebliche Flexibilität, müssen jedoch eine gewisse Struktur vorgeben, damit Befunde bei der Umwandlung von Eingabe zu Ausgabe nicht verfälscht werden. Optionale Eingabefelder können wir berücksichtigen, „globale“ Felder oder Felder, die in einer anderen Anzahl auftreten als die Befundobjekte, akzeptieren wir jedoch nicht.

#### Beispiel

```
{
    "scan_type": "MyToolScan", // <- There is only one instance of this field, which doesn't match the number of findings
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345", // <- This optional field only appears in Finding 1 - that's okay!
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "CRITICAL",
            ...  // <- While there is no "CVE" field here, we can still query for it and simply default to a null value
        },
        ... 5 more findings ...
    ],
    "global_details": [
        {
            "nested_detail": "Global detail 1"
        },
        {
            "nested_detail": "Global detail 2" // <- The number of "global_details" objects (2) does not match the number of individual finding objects (7)
        }

    ]
}
```

## Nach dem Speichern eines Universal Parsers

Sie können den mit Ihrem Universal Parser verknüpften Test_Type bearbeiten, um Folgendes zu ändern:
* Ob er „aktiv“ ist oder nicht. Wenn nicht, erscheint er nicht als Option im Dropdown-Menü „Scan Type“ auf der Seite „Add Findings“
* Ob seine Befunde als „static“ oder „dynamic“ markiert werden sollen
* Sie können die Hash-Codes für die Deduplizierung innerhalb desselben Tools und toolübergreifend sowie die Hash-Codes für den Reimport für Ihren Universal Parser unter „Enterprise Settings“ anpassen. Standardmäßig werden nur die Hash-Codes für die Deduplizierung innerhalb desselben Tools und für den Reimport mit den erforderlichen Werten Title, Severity und Description befüllt.

## Lebenszyklus: Erstellen, Deaktivieren, Reaktivieren

Der Lebenszyklus eines Universal Parsers ist **ausschließlich auf das Erstellen beschränkt** - es gibt kein Bearbeiten oder Löschen in der UI. Sobald ein Parser erstellt wurde, kann die Feldzuordnungskonfiguration nicht mehr geändert werden, und der Parser selbst kann nicht aus der UI entfernt werden — dies ist beabsichtigt, da Universal-Parser-Konfigurationen an Test_Type-Datensätze gebunden sind, auf die bestehende Findings, Tests und der Importverlauf verweisen können.

Was Sie **über die UI tun können**:

* **Deaktivieren** Sie einen Parser, um ihn beim Import aus dem Dropdown-Menü „Scan Type“ auszublenden. Öffnen Sie **Import → Universal Parser** in der Seitenleiste, um alle Ihre Universal Parser anzuzeigen, und schalten Sie „Active“ aus. (Alternativ können Sie den zugrunde liegenden Test_Type bearbeiten und „active“ deaktivieren.) Deaktivierte Parser erscheinen nicht mehr als Scan-Type-Option auf der Seite **Add Findings**, bestehende Tests, die mit diesem Parser importiert wurden, sind davon jedoch nicht betroffen und funktionieren weiterhin.
* **Reaktivieren** Sie einen Parser über denselben Bildschirm, indem Sie „Active“ wieder einschalten.
* **Bearbeiten Sie die Test_Type-Felder**, die im vorherigen Abschnitt beschrieben wurden (active/inactive, static/dynamic, Deduplizierungs-Hash-Codes).

### Empfohlener Arbeitsablauf bei Änderungen am Berichtsformat eines Scanners

Da die Feldzuordnungskonfiguration nach dem Erstellen eines Parsers gesperrt ist, besteht der Standard-Workflow bei einer Formatänderung des zugrunde liegenden Scanners darin, **zu einem neuen Parser überzugehen**, anstatt zu versuchen, den alten zu bearbeiten:

1. **Erstellen Sie einen neuen Universal Parser** anhand eines Beispiels des neuen Berichtsformats (siehe Schritt 1). Geben Sie ihm einen eindeutigen Namen — hängen Sie z. B. `v2` oder ein Datum an den ursprünglichen Namen an.
2. **Stellen Sie neue Importe um**, sodass Ihre CI/CD-Pipeline oder Ihr UI-Workflow den Scan-Typ des neuen Parsers verwendet.
3. **Deaktivieren Sie den alten Parser**, sobald Sie bestätigt haben, dass der neue die erwarteten Befunde liefert. Bereits mit dem alten Parser importierte Tests bleiben in DefectDojo erhalten und können weiterhin triagiert werden; nur neue Importe werden an den neuen Parser weitergeleitet.

Wenn Sie eine Parser-Konfiguration dauerhaft entfernen lassen möchten (zum Beispiel, weil sie sensible Feldnamen enthält), wenden Sie sich an den [DefectDojo Support](mailto:support@defectdojo.com).

## Ein Hinweis zur Zuordnung von Schweregraden

Der Universal Parser verfügt **nicht** über ein konfigurierbares Feld zur Zuordnung von Schweregraden. Der Schweregrad wird automatisch nach folgenden Regeln zugeordnet:

* Jede Groß-/Kleinschreibungsvariante eines DefectDojo-Schweregrads wird akzeptiert — `CRITICAL`, `Critical`, `cRiTiCaL`, `critical` werden alle auf **Critical** abgebildet. Dasselbe gilt für `High`, `Medium`, `Low` und `Info`.
* Jeder Wert, der **keinem** der fünf DefectDojo-Schweregrade entspricht, wird auf **Info** abgebildet.

Dieses Verhalten ist bei allen Parsern in DefectDojo gleich (integrierte Parser, Connectors und Universal Parser).

Wenn ein Scanner, dessen Daten Sie einlesen möchten, Schweregrad-Bezeichnungen verwendet, die nicht mit denen von DefectDojo übereinstimmen (z. B. „warning“, „note“ oder numerische CVSS-Werte), bildet der Universal Parser alle diese nicht übereinstimmenden Werte auf Info ab. Wenn Sie eine andere Zuordnung benötigen, besteht der derzeit beste Workaround darin, **die Schweregrad-Werte vorgelagert zu transformieren** — zum Beispiel in Ihrer CI-Pipeline vor dem Hochladen —, sodass die von DefectDojo empfangenen Werte bereits einem der fünf DefectDojo-Schweregradnamen entsprechen.
