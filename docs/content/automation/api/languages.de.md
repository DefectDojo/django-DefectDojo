---
title: Sprachen und Codezeilen
description: Daten zur Sprachzusammensetzung für ein Produkt mit dem Werkzeug cloc
  importieren
weight: 3
audience: opensource
aliases:
- /de/en/open_source/languages
---

DefectDojo kann eine Aufschlüsselung der Programmiersprachen und Codezeilen für ein Produkt anzeigen, die durch den Import eines Berichts des Werkzeugs [cloc](https://github.com/AlDanial/cloc) (Count Lines of Code) über die API gefüllt wird.

## Den cloc-Bericht erzeugen

Führen Sie `cloc` mit dem Flag `--json` gegen Ihre Codebasis aus, um eine JSON-Datei im richtigen Format zu erzeugen:

```bash
cloc --json /path/to/your/project > cloc-report.json
```

## Import über die API

Laden Sie den JSON-Bericht über die API in DefectDojo hoch. Beim Import werden alle vorhandenen Sprachdaten des Produkts durch den Inhalt der neuen Datei ersetzt.

Der Import-Endpunkt ist in der [Dokumentation zur DefectDojo API v2](../api-v2-docs/) beschrieben.

## Ergebnisse ansehen

Nach dem Import wird die Sprachaufschlüsselung auf der linken Seite der Produktdetailseite angezeigt, mit jeder Sprache und ihrer Zeilenanzahl. Die Farben der einzelnen Sprachen werden durch Einträge in der Tabelle `Language_Type` definiert, die mit Daten von GitHub vorbelegt ist.

## Sprachfarben aktualisieren

GitHub aktualisiert die Sprachfarben regelmäßig, wenn neue Sprachen entstehen. Um die neuesten Farbdaten zu übernehmen, führen Sie den folgenden Management-Befehl aus:

```bash
./manage.py import_github_languages
```

Dieser liest aus [ozh/github-colors](https://github.com/ozh/github-colors) und ergänzt neue Sprachen oder aktualisiert vorhandene Farben.
