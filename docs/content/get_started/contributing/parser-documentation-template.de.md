---
title: Vorlage für Parser-Dokumentation
toc_hide: true
weight: 2
audience: opensource
aliases:
- /en/open_source/contributing/parser-documentation-template
---

Diese Vorlage dient dazu, einen neuen oder bestehenden Parser zu dokumentieren. Ergänzen Sie sie gerne um weitere Informationen, die anderen Sicherheitsfachleuten helfen können.

* Kopieren Sie diese .md-Datei und fügen Sie sie im GitHub-Repository unter `/docs/content/supported_tools/file` ein.
* Passen Sie den Titel an den Namen Ihres neuen oder bestehenden Parsers an.
* Füllen Sie alle unten aufgeführten Abschnitte aus. Entfernen Sie bitte alle Hinweise und Beispiele, die in den einzelnen Abschnitten enthalten sind.

### Dateitypen
_Geben Sie alle Dateitypen an, die Ihr Parser akzeptiert (z. B. CSV, JSON, XML)._
_Beschreiben Sie, wie das akzeptierte Dateiformat mit dem zugehörigen Sicherheitswerkzeug erzeugt oder exportiert wird._

### Gesamtzahl der Felder in [Dateiformat]
Datenfelder insgesamt:  _Gesamtzahl der Felder in der Exportdatei des Sicherheitswerkzeugs._
Geparste Datenfelder insgesamt:  _Gesamtzahl der Felder, die in den DefectDojo-Befund geparst werden._
NICHT geparste Datenfelder insgesamt: _Gesamtzahl der Felder, die NICHT in den DefectDojo-Befund geparst werden._

_Beschreiben Sie im folgenden Format kurz jedes Feld und wie es auf das Datenmodell von DefectDojo abgebildet wird._
_Führen Sie alle Felder aus der Exportdatei des Sicherheitswerkzeugs in der Reihenfolge ihres Auftretens auf und kennzeichnen Sie Felder, die nicht geparst werden._

Felder in der Reihenfolge ihres Auftretens:
1. **Feld 1** - _Beschreibung, wie dieses Feld abgebildet wird (z. B. auf den Titel des Befunds oder den Host des Endpunkts.)_
2. **Feld 2** - _Beschreibung, wie dieses Feld abgebildet bzw. nicht abgebildet wird._
3. **Feld 3** - _Beschreibung, wie dieses Feld abgebildet bzw. nicht abgebildet wird._
4. **Feld 4** - _Beschreibung, wie dieses Feld abgebildet bzw. nicht abgebildet wird._
_(für jedes Feld in der Datei fortsetzen.)_

### Details zur Feldzuordnung
_Beschreiben Sie für jeden erzeugten Befund, wie der Parser bestimmte Daten verarbeitet. Zum Beispiel:_
- Wie Endpunkte erzeugt werden (z. B. durch Kombination der Felder IP, Domain, Port und Protokoll).
- Wie Vorkommen behandelt werden (z. B. `nb_occurences` standardmäßig auf 1 gesetzt, bei Duplikaten erhöht).
- Wie die Deduplizierung erfolgt (z. B. über einen Hash aus Schweregrad + Titel + Beschreibung).
- Beschreibt den Standard-Schweregrad, wenn keine Zuordnung zutrifft.

### Beispiel-Scandaten oder Unit-Tests
_Fügen Sie einen Link zum Ordner mit den Unit-Tests oder den Beispiel-Scandaten im GitHub-Repository hinzu. Zum Beispiel:_
- [Ordner mit Beispiel-Scandaten](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/[parser-name])

### Link zum Tool
_Geben Sie einen Link zum Scanner oder Tool selbst an (z. B. GitHub-Repository, Anbieter-Website oder Dokumentation). Zum Beispiel:_
- [Tool-Name](https://www.example.com/)
