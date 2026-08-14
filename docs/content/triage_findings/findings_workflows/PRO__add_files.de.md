---
title: Dateien anhängen
description: Laden Sie Screenshots, Berichte oder andere unterstützende Dateien zu
  einem Befund, Engagement oder Test in DefectDojo Pro hoch
audience: pro
weight: 3
---

Sie können Dateien an einen **Befund**, ein **Engagement** oder einen **Test** anhängen, um
unterstützenden Kontext bereitzustellen — zum Beispiel einen Proof-of-Concept-Screenshot, einen rohen
Scanner-Bericht, ein Netzwerkdiagramm oder eine Tabelle, die ein Ergebnis belegt.

Jedes Objekt behält seinen eigenen Satz an Dateien, und Sie können **bis zu 10 Dateien** an ein einzelnes
Objekt anhängen.

## Unterstützte Dateitypen

Standardmäßig werden folgende Erweiterungen akzeptiert:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Administratoren können diese Liste über die Umgebungsvariable `DD_FILE_UPLOAD_TYPES` ändern.
Das Hochladen einer Datei, deren Erweiterung nicht in der Liste enthalten ist, wird abgelehnt.

## So hängen Sie eine Datei an einen Befund an

1. Öffnen Sie den Befund, an den Sie eine Datei anhängen möchten.
2. Klicken Sie oben rechts im Befund auf das **Zahnrad-Menü (⚙)** und wählen Sie **Datei hinzufügen**.
3. Geben Sie einen **Titel** für die Datei ein, wählen Sie die Datei von Ihrem Computer aus und speichern Sie.

   ![Die Aktion „Datei hinzufügen“ im Zahnrad-Menü des Befunds, mit dem Reiter „Dateien“ darunter](images/PRO_attach_files_menu.png)

Dasselbe Zahnrad-Menü ist auf den Seiten **Engagement** und **Test** verfügbar, sodass Dateien auf dieselbe
Weise an jedes dieser Objekte angehängt werden können.

## Dateien anzeigen und herunterladen

Angehängte Dateien werden im Reiter **Dateien** der **Befundübersicht** aufgeführt (sowie im
entsprechenden Bereich bei Engagements und Tests). Klicken Sie auf den Titel einer Datei, um sie herunterzuladen.

![Der Reiter „Dateien“ an einem Befund mit einer aufgelisteten angehängten Datei](images/PRO_finding_files_tab.png)

Der Zugriff wird auf Berechtigungen geprüft: Ein Benutzer muss über die Berechtigung **Anzeigen** für den übergeordneten Befund,
das Engagement oder den Test verfügen, um dessen Dateien herunterzuladen.

## Dateien löschen

Um eine Datei zu entfernen, öffnen Sie das Zeilenmenü der Datei (das Symbol **⋮**) im Reiter **Dateien** und wählen Sie
**Datei löschen**. Dasselbe Menü bietet auch **Dateiname bearbeiten**, um einen Anhang umzubenennen.
