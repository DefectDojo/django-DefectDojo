---
title: Formular „Add Findings“
description: ''
weight: 1
audience: pro
aliases:
- /de/en/connecting_your_tools/import_scan_files/import_scan_ui
---

Wenn Sie eine ganz neue DefectDojo-Instanz haben, ist das Formular „Import Scan“ ein logischer erster Schritt, um die Software kennenzulernen und Ihre Umgebung einzurichten. Über dieses Formular laden Sie eine Scan-Datei eines unterstützten Tools hoch, aus der Befunde für diese Schwachstellen erstellt werden. Beim Ausfüllen des Formulars können Sie entscheiden, ob Sie:

* diese Befunde unter einem bestehenden Produkttyp / Produkt / Engagement speichern **oder**
* einen neuen Produkttyp / ein neues Produkt / ein neues Engagement erstellen, um diese Befunde zu speichern

Ihre Produkthierarchie lässt sich in DefectDojo leicht umstellen, es ist also kein Problem, wenn Sie noch nicht wissen, wie Sie alles einrichten möchten. 

Für den Moment ist es gut zu wissen, dass **Engagements** Daten aus mehreren Tools speichern können. Das kann nützlich sein, wenn Sie im Rahmen eines einzelnen Testvorhabens mehrere Tools parallel einsetzen.

## Zugriff auf das Formular „Import Scan“ (Pro-Benutzeroberfläche)

Das Formular „Import Scan“ kann an mehreren Stellen aufgerufen werden:

1. Über den Menüpunkt **Import > Add Findings** in der Seitenleiste
2. Über das **‘⋮’ (Punkte-Menü)** eines **Produkts** in einer **Produkttabelle**
3. Über das **⚙️Zahnrad-Menü** auf einer **Produktseite**

## Das Formular „Import Scan“ ausfüllen

Das Formular „Import Scan“ erstellt einen neuen Test unterhalb eines Engagements, der für jede in Ihrer Scan-Datei enthaltene Schwachstelle einen eigenen Befund enthält.

Der Test erhält einen Namen, der der Scan-Art entspricht: Ein Tenable-Scan heißt zum Beispiel ‘Tenable Scan’.

### Formularoptionen

* **Scan File:** Über die Schaltfläche „Choose“ können Sie eine Datei von Ihrem Computer zum Hochladen auswählen.
* **Scan Date (optional):** Wenn Sie ein einheitliches Scan-Datum für alle Befunde aus diesem Import festlegen möchten, können Sie das Datum in diesem Feld auswählen.   
Wenn Sie kein Scan-Datum auswählen, verwenden die aus diesem Bericht erstellten Befunde das vom Tool angegebene Datum. Die SLAs für jeden Befund werden anhand seines Datums berechnet.
* **Scan Type:** Wählen Sie das Tool aus, mit dem diese Daten erstellt wurden.
* **Product Type / Product / Engagement Name:** Wählen Sie den Produkttyp, das Produkt und den Engagement-Namen aus, unter dem Sie einen neuen Test erstellen möchten. Sie können an dieser Stelle auch einen neuen Produkttyp, ein neues Produkt und/oder ein neues Engagement erstellen, indem Sie die Namen der Objekte eingeben, die erstellt werden sollen.
* **Environment:** Wählen Sie eine Umgebung, die zu den Daten passt, die Sie hochladen.
* **Tags:** Wenn Sie Ihre Testdaten mit Tags weiter organisieren möchten, können Sie über dieses Formular Tags hinzufügen. Geben Sie den Namen des Tags ein, das Sie erstellen möchten, und drücken Sie auf Ihrer Tastatur die Eingabetaste, um es der Liste der Tags hinzuzufügen.
* **Process Findings Asynchronously**: Dieses Feld ist standardmäßig aktiviert, kann aber bei Bedarf deaktiviert werden. Siehe Erläuterung unten.

### Befunde asynchron verarbeiten („Process Findings Asynchronously“)

Wenn dieses Feld aktiviert ist, verwendet DefectDojo einen Hintergrundprozess, um Ihren Test mit Befunden zu füllen. So können Sie in DefectDojo weiterarbeiten, während die Befunde aus Ihrer Scan-Datei erstellt werden.

Wenn dieses Feld deaktiviert ist, wartet DefectDojo, bis alle Befunde erfolgreich erstellt wurden, bevor Sie zum nächsten Bildschirm wechseln können. Abhängig von der Größe Ihrer Datei kann das viel Zeit in Anspruch nehmen.

Diese Option ist besonders relevant, wenn Sie Daten über die API importieren. Wenn Sie Daten hochladen, während Process Findings Asynchronously **deaktiviert** ist, gibt DefectDojo erst dann eine erfolgreiche Antwort zurück, wenn alle Befunde erfolgreich erstellt wurden, 

### Optionale Felder

Um die optionalen Felder zu öffnen, klicken Sie über der Schaltfläche **Submit** auf die Schaltfläche mit der Bezeichnung **„Optional Fields +“**

![image](images/import_scan_ui.png)

#### Beschreibungen der optionalen Felder
* **Minimum Severity**: Wenn Sie Befunde nur ab einem bestimmten Schweregrad erstellen möchten, können Sie hier den minimalen Schweregrad auswählen. Alle Schwachstellen mit einem geringeren Schweregrad als in diesem Feld werden ignoriert.
* **Active**: Wenn Sie alle eingehenden Befunde entweder auf Aktiv oder Inaktiv setzen möchten, können Sie das hier angeben. Andernfalls verwendet DefectDojo die Schwachstellendaten des Tools, um zu bestimmen, ob der Befund Aktiv oder Inaktiv ist. Diese Option ist relevant, wenn Ihr Team Befunde aus einem bestimmten Tool manuell triagieren und verifizieren muss.
* **Verified**: Wie bei Active können Sie die neuen Befunde standardmäßig auf Verifiziert oder Nicht verifiziert setzen. Das hängt von Ihren Workflow-Vorlieben ab. Wenn Ihr Team zum Beispiel davon ausgeht, dass Befunde verifiziert sind, solange nicht das Gegenteil belegt ist, können Sie dieses Feld auf True setzen.
* **Version, Branch Tag, Commit Hash, Build ID, Service** können alle angegeben werden, wenn Sie diese Details im Test erfassen möchten.
* **Source Code Management URI** kann ebenfalls angegeben werden. Diese Formularoption muss eine gültige URI sein.
* **Group By:** Wenn Sie aus dieser Datei Befundgruppen erstellen möchten, können Sie hier die Gruppierungsmethode angeben.

### Alte Befunde schließen („Close Old Findings“)

Beim Importieren eines Scans können Sie Befunde aus früheren Scans automatisch schließen, wenn sie im neuen Bericht nicht mehr enthalten sind. Aktivieren Sie dazu in der Benutzeroberfläche das Kontrollkästchen **Close Old Findings** oder setzen Sie in der API `close_old_findings: true`.

#### Geltungsbereich: Engagement oder Produkt

Standardmäßig schließt `close_old_findings` Befunde derselben Scan-Art innerhalb **desselben Engagements**. DefectDojo Pro bietet eine zweite Option, **Close Old Findings Within This Product**, die den Geltungsbereich auf alle Befunde derselben Scan-Art im **gesamten Produkt** erweitert, unabhängig davon, zu welchem Engagement sie gehören.

| Option | Kontrollkästchen in der Benutzeroberfläche | API-Parameter | Geltungsbereich |
|---|---|---|---|
| Alte Befunde schließen (Engagement-Bereich) | **Close Old Findings** | `close_old_findings: true` | Dasselbe Engagement |
| Alte Befunde schließen (Produkt-Bereich) | **Close Old Findings Within This Product** | `close_old_findings_product_scope: true` | Gesamtes Produkt |

`close_old_findings_product_scope` setzt voraus, dass auch `close_old_findings` aktiviert ist. `close_old_findings_product_scope` ohne `close_old_findings` zu setzen hat keine Wirkung.

> **Hinweis:** `close_old_findings_product_scope` gilt nur für den Import-Endpunkt (`/import-scan`). Auf den Reimport-Endpunkt (`/reimport-scan`) hat es keine Wirkung; dort ist der Geltungsbereich immer auf den aktuellen Test beschränkt.

Das Feld `service` wird ebenfalls berücksichtigt: Nur Befunde mit identischem Wert für `service` (oder ohne Wert für `service`, wenn beim Import keiner angegeben wurde) werden für das Schließen berücksichtigt.

### Scanner ohne Triage: Feld „Do Not Reactivate“

Manche Scanner nehmen keine Triage-Informationen in ihre Berichte auf (zum Beispiel tfsec). Sie prüfen einfach Code oder Abhängigkeiten, markieren Probleme und geben alles zurück, unabhängig davon, ob eine Schwachstelle bereits triagiert wurde oder nicht.

Für diesen Fall bietet DefectDojo beim Hochladen von Berichten (und ebenso in der Reimport-API) ein Kontrollkästchen „Do not reactivate“, damit Sie DefectDojo als maßgebliche Quelle für die Triage nutzen können, anstatt Ihre triagierten Befunde bei jedem Import bzw. Reimport erneut zu aktivieren.

### Das Feld für das Scan-Abschlussdatum (API: `scan_date`) verwenden

DefectDojo unterstützt eine Vielzahl von Scanner-Berichten, aber nicht alle enthalten die
für Benutzer wichtigsten Informationen. Das Feld `scan_date` ist eine flexible, intelligente Funktion,
mit der Benutzer das Abschlussdatum eines bestimmten Scan-Berichts festlegen können, das dann
an alle importierten Befunde weitergegeben wird. Dieses Feld ist **nicht** verpflichtend; der Standardwert
ist das Importdatum (also der Zeitpunkt, zu dem die Anfrage verarbeitet und eine erfolgreiche Antwort zurückgegeben wird).

Es gibt die folgenden Anwendungsfälle für dieses Feld:

1. Der Bericht setzt das Datum **nicht** und `scan_date` wird beim Import **nicht** gesetzt
    - Das Befund-Datum ist der Standardwert von `scan_date`
2. Der Bericht **setzt** das Datum und `scan_date` wird beim Import **nicht** gesetzt
    - Das Befund-Datum ist das im Bericht angegebene Datum
3. Der Bericht setzt das Datum **nicht** und `scan_date` wird beim Import **gesetzt**
    - Das Befund-Datum ist der vom Benutzer für `scan_date` festgelegte Wert
4. Der Bericht **setzt** das Datum und `scan_date` wird beim Import **gesetzt**
    - Das Befund-Datum ist der vom Benutzer für `scan_date` festgelegte Wert
