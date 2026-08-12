---
title: Dateien anhängen
description: Laden Sie Screenshots, Berichte oder andere unterstützende Dateien zu
  einem Befund, Engagement oder Test in DefectDojo OS hoch
audience: opensource
weight: 3
aliases:
- /triage_findings/findings_workflows/add_files/
---

Sie können Dateien an einen **Befund**, ein **Engagement** oder einen **Test** anhängen, um unterstützenden Kontext bereitzustellen — zum Beispiel einen Proof-of-Concept-Screenshot, einen unbearbeiteten Scanner-Bericht, ein Netzwerkdiagramm oder eine Tabelle, die ein Ergebnis belegt.

Jedes Objekt verwaltet seinen eigenen Satz an Dateien, und Sie können **bis zu 10 Dateien** an ein einzelnes Objekt anhängen.

## Unterstützte Dateitypen

Standardmäßig werden folgende Dateiendungen akzeptiert:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Administratoren können diese Liste über die Umgebungsvariable `DD_FILE_UPLOAD_TYPES` ändern.
Das Hochladen einer Datei, deren Endung nicht in der Liste enthalten ist, wird vom Formular abgelehnt.

Bilddateien (wie `.png` und `.jpeg`) werden als Miniaturvorschau dargestellt, während andere
Dateitypen mit einem generischen Dateisymbol angezeigt werden. In beiden Fällen lädt ein Klick
auf die Datei sie herunter.

## So hängen Sie eine Datei an einen Befund an

1. Öffnen Sie den Befund, an den Sie eine Datei anhängen möchten.
2. Öffnen Sie das Aktionsmenü (die Schaltfläche **☰** oben rechts im Befund) und klicken Sie auf
   **Manage Files**.

   ![Manage Files im Aktionsmenü des Befunds](images/OS_manage_files_menu.png)

3. Geben Sie auf der Seite **Add files** einen **Title** für die Datei ein und wählen Sie die
   Datei von Ihrem Computer aus. Sie können bis zu drei Dateien gleichzeitig hinzufügen;
   speichern Sie und kehren Sie bei Bedarf zurück, um weitere hinzuzufügen.

   ![Das Upload-Formular von Manage Files](images/OS_manage_files_form.png)

4. Klicken Sie auf **Save**.

Die Datei wird anschließend im Panel **Files** des Befunds aufgeführt. Bilddateien erscheinen als
Miniaturansicht:

![Files-Panel an einem Befund mit angehängtem Screenshot](images/OS_finding_files_panel.png)

## Dateien an Engagements und Tests anhängen

Engagements und Tests verwenden denselben **Manage Files**-Workflow:

- Öffnen Sie auf der Detailseite eines **Engagement** oder **Test** das Panel **Files** und
  klicken Sie auf dessen Bearbeiten-Schaltfläche (Stift), um dann Dateien genau wie bei einem
  Befund hinzuzufügen.

Wie bei Befunden werden Bildanhänge als Miniaturansicht dargestellt, und andere Dateitypen
zeigen ein generisches Dateisymbol.

## Dateien ansehen und herunterladen

Angehängte Dateien erscheinen im Panel **Files** auf der Detailseite des Objekts. Klicken Sie auf
eine beliebige Datei, um sie herunterzuladen. Der Zugriff wird über Berechtigungen geprüft: Ein
Benutzer benötigt die Berechtigung **view** für den übergeordneten Befund, das Engagement oder
den Test, um dessen Dateien herunterzuladen.

## Dateien löschen

Um eine Datei zu entfernen, öffnen Sie **Manage Files** für das Objekt, aktivieren Sie das
Kontrollkästchen **Delete** unter der zu entfernenden Datei und klicken Sie auf **Save**.
