---
title: Formular „Import Scan“
description: ''
weight: 1
audience: opensource
---

Sobald Ihre Produkthierarchie mit mindestens einem Produkttyp, Produkt, Test und Engagement eingerichtet ist, können Sie eine Scan-Datei in DefectDojo importieren und Befunde erstellen.

Ihre Produkthierarchie lässt sich in DefectDojo leicht umstellen, es ist also kein Problem, wenn Sie noch nicht wissen, wie Sie alles einrichten möchten. 

Für den Moment ist es gut zu wissen, dass **Engagements** Daten aus mehreren Tools speichern können. Das kann nützlich sein, wenn Sie im Rahmen eines einzelnen Testvorhabens mehrere Tools parallel einsetzen.

## Zugriff auf das Formular „Import Scan“ (klassische Benutzeroberfläche / Open Source)

In DefectDojo OS können Sie dieses Formular an zwei Stellen aufrufen:

* Im Bereich „Tests“ eines Engagements:
    ![image](images/import_scan_os.png)
* Im Bereich „Findings“ der Navigationsleiste eines Produkts:
    ![image](images/import_scan_os_2.png)

## Das Formular „Import Scan“ ausfüllen

![image](images/import_scan_ui.png)
Das Formular „Import Scan“ erstellt einen neuen Test unterhalb eines Engagements, der für jede in Ihrer Scan-Datei enthaltene Schwachstelle einen eigenen Befund enthält.

Der Test erhält einen Namen, der der Scan-Art entspricht: Ein Tenable-Scan heißt zum Beispiel ‘Tenable Scan’.

### Formularoptionen

* **Scan File:** Über die Schaltfläche „Choose“ können Sie eine Datei von Ihrem Computer zum Hochladen auswählen.
* **Scan Date (optional):** Wenn Sie ein einheitliches Scan-Datum für alle Befunde aus diesem Import festlegen möchten, können Sie das Datum in diesem Feld auswählen.   
Wenn Sie kein Scan-Datum auswählen, verwenden die aus diesem Bericht erstellten Befunde das vom Tool angegebene Datum. Die SLAs für jeden Befund werden anhand seines Datums berechnet.
* **Scan Type:** Wählen Sie das Tool aus, mit dem diese Daten erstellt wurden.
* **Environment:** Wählen Sie eine Umgebung, die zu den Daten passt, die Sie hochladen.
* **Tags:** Wenn Sie Ihre Testdaten mit Tags weiter organisieren möchten, können Sie über dieses Formular Tags hinzufügen. Geben Sie den Namen des Tags ein, das Sie erstellen möchten, und drücken Sie auf Ihrer Tastatur die Eingabetaste, um es der Liste der Tags hinzuzufügen.

### Optionale Felder

* **Minimum Severity**: Wenn Sie Befunde nur ab einem bestimmten Schweregrad erstellen möchten, können Sie hier den minimalen Schweregrad auswählen. Alle Schwachstellen mit einem geringeren Schweregrad als in diesem Feld werden ignoriert.
* **Active**: Wenn Sie alle eingehenden Befunde entweder auf Aktiv oder Inaktiv setzen möchten, können Sie das hier angeben. Andernfalls verwendet DefectDojo die Schwachstellendaten des Tools, um zu bestimmen, ob der Befund Aktiv oder Inaktiv ist. Diese Option ist relevant, wenn Ihr Team Befunde aus einem bestimmten Tool manuell triagieren und verifizieren muss.
* **Verified**: Wie bei Active können Sie die neuen Befunde standardmäßig auf Verifiziert oder Nicht verifiziert setzen. Das hängt von Ihren Workflow-Vorlieben ab. Wenn Ihr Team zum Beispiel davon ausgeht, dass Befunde verifiziert sind, solange nicht das Gegenteil belegt ist, können Sie dieses Feld auf True setzen.
* **Version, Branch Tag, Commit Hash, Build ID, Service** können alle angegeben werden, wenn Sie diese Details im Test erfassen möchten.
* **Source Code Management URI** kann ebenfalls angegeben werden. Diese Formularoption muss eine gültige URI sein.
* **Group By:** Wenn Sie aus dieser Datei Befundgruppen erstellen möchten, können Sie hier die Gruppierungsmethode angeben.

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
