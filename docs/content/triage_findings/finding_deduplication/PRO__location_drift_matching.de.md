---
title: Standort-Drift-Zuordnung
description: Verfolgen Sie Befunde, während sich deren Standorte über mehrere Reimporte
  hinweg ändern — Zeilenverschiebungen, Dateiumbenennungen, URL-Änderungen und Abhängigkeits-Versionssprünge
  schließen und erzeugen Befunde nicht mehr neu
weight: 6
audience: pro
---

**Standort-Drift-Zuordnung** ermöglicht es dem Reimport, einen Befund, dessen *Standort* sich verändert hat, als **denselben Befund** zu erkennen. Ohne diese Funktion gleicht der Reimport Befunde anhand eines exakten Identitäts-Hashs ab, der Standortfelder einschließt — sodass jede Standortänderung den alten Befund schließt und einen identischen neuen erzeugt:

- Ein Commit verschiebt Code, und die **Zeilennummer** des Befunds ändert sich.
- Ein Refactoring **benennt die Datei um oder verschiebt sie**.
- Die **URL, der Port oder der Host** einer Webanwendung ändert sich zwischen DAST-Scans.
- Ein **Versionssprung** einer Abhängigkeit ändert die von einem SCA-Tool gemeldete verwundbare Paketversion.

Jeder dieser Fälle erzeugte bisher einen geschlossenen Befund plus einen »neuen« Befund — wodurch Status, Notizen, SLA-Uhr, Risikoakzeptanz und JIRA-Verknüpfung des Originals verloren gingen und falscher Lärm in Form von »neuer kritischer Befund« entstand. Mit aktivierter Standort-Drift-Zuordnung bleibt ein Befund an Ort und Stelle erhalten: sein Standort wird anhand des aktuellsten Scans aktualisiert, und seine Historie bleibt erhalten.

> Standort-Drift-Zuordnung ist eine DefectDojo-Pro-Funktion. Sie ist **standardmäßig deaktiviert** und wird pro Sicherheitstool aktiviert.

## Standortverfolgung aktivieren

Die Standortverfolgung wird pro Tool konfiguriert unter:
**Settings > Finding Workflow > Reimport Deduplication** (**Settings > Pro Settings > Deduplication Settings > Reimport Deduplication** auf Instanzen, die noch das vorherige Menülayout verwenden)

1. Wählen Sie das **Security Tool** aus.
2. Setzen Sie den **Deduplication Algorithm** auf **Hash Code**. Die Standortverfolgung gilt nur für den Hash-Code-Algorithmus — Tools mit einer verlässlichen **Unique ID From Tool** verfolgen Verschiebungen bereits über ihre stabilen IDs und benötigen sie nicht.
3. Aktivieren Sie **Track findings as locations change**.

Das Speichern der Einstellung löst automatisch ein Hintergrund-Neuberechnen der Hashes für die bestehenden Befunde des Tools aus (siehe [Aktivieren bei vorhandenen Daten](#enabling-on-existing-data-upgrades) unten), sodass vor dem Umschalten importierte Befunde sofort einbezogen werden.

## So funktioniert die Zuordnung

Bei aktivierter Verfolgung läuft der Reimport-Abgleich in zwei Stufen ab:

1. **Stabile Identität.** Der Reimport-Hash wird *ohne* die volatilen Standortfelder berechnet (Zeile, Dateipfad, Beschreibung, Komponentenname/-version, Endpunkte) — sodass die Identität eines Befunds erfasst, *was* der Befund ist, nicht *wo* er sich gerade befindet. Befunde, die sich nicht verschoben haben, werden weiterhin zuerst exakt zugeordnet und nie gestört.
2. **Nachweisbasierte Paarung.** Innerhalb jeder Gruppe von Befunden mit gemeinsamer stabiler Identität ordnet ein Standort-Matcher eingehende Befunde bestehenden anhand von Standortnachweisen zu, in deterministischen Durchläufen vom stärksten zum schwächsten Nachweis. Ein Befund wird anhand der von ihm mitgeführten Standortdaten genau einem Matcher zugewiesen.

### Code-Befunde (SAST)

| Durchlauf | Paart, wenn | Hinweise |
|------|-----------|-------|
| Exakt | Gleiche Datei und Zeile | Gewinnt immer; ein verschobener Nachbar kann einem unverschobenen Befund niemals die Zuordnung »stehlen« |
| Datenfluss | Gleiche Quell-/Senken-Objekte (`sast_source_object` / `sast_sink_object`) | Für Tools, die Datenfluss melden; unempfindlich gegenüber Zeilen-Neunummerierung |
| Nächstgelegene Zeile | Gleiche Datei, nächstgelegene Zeilennummer | Gierig, nächstgelegene zuerst; nur innerhalb derselben Datei |
| Dateiumbenennung | Andere Datei | Nur wenn genau **ein** eingehender und **ein** bestehender Befund übrig bleiben — bei Mehrdeutigkeit erfolgt keine Zuordnung |

### URL-Befunde (DAST)

| Durchlauf | Paart, wenn |
|------|-----------|
| Exakt | Identischer Endpunktsatz |
| Endpunktsatz-Abweichung | Überlappende Endpunktsätze (Endpunkte hinzugefügt/entfernt) |
| Port-Wechsel | Gleicher Host und Pfad, anderer Port |
| Pfad-Abweichung | Gleicher Host, ähnlicher Pfad (beste gegenseitige Segmentähnlichkeit) |
| Host-Wechsel | Anderer Host — nur als eindeutige 1×1-Paarung, mit einer Wildcard-DNS-Absicherung |

### Abhängigkeitsbefunde (SCA)

| Durchlauf | Paart, wenn |
|------|-----------|
| Exakt | Gleiches Paket, gleiche Version und gleiches Manifest |
| Versionssprung | Gleiches Paket, andere Version |
| Manifest-Wechsel | Gleiches Paket, anderer Lockfile-/Manifestpfad |

Erscheint dasselbe verwundbare Paket in **mehreren Manifesten**, wird der Befund jedes Manifests unabhängig verfolgt — ein Versionssprung in einer Lockfile schluckt niemals den Befund einer anderen.

### Neubewertungen des Schweregrads

Sicherheitstools bewerten Schweregrade neu, wenn sich ihre Regel-Engines weiterentwickeln. Bei aktivierter Verfolgung spaltet eine vom Tool gemeldete Schweregradänderung die Identität eines Befunds **nicht** auf: der Befund wird zugeordnet, und sein Schweregrad wird aus dem Scan aktualisiert — es sei denn, eine Person hat den Schweregrad manuell neu triagiert; in diesem Fall gewinnt stets der menschliche Wert (siehe unten).

## Was erhalten bleibt, was aktualisiert wird

Ein per Drift zugeordneter Befund behält alles, was für seinen Lebenszyklus wichtig ist: Status, Notizen, Risikoakzeptanz, SLA-Daten, JIRA-Verknüpfung und seine Befund-ID.

Seine **Standortfelder** (Dateipfad, Zeile, Datenflussfelder, Endpunkte, Komponentenversion) werden anhand des eingehenden Scans aktualisiert.

Seine **beschreibenden Felder** (Titel, Beschreibung, Schweregrad, Komponentenversion) werden nur dann aus dem Scan aktualisiert, *wenn der Scan sie weiterhin »besitzt«*: DefectDojo speichert für jedes Feld einen Digest, der beim letzten Schreiben durch Import/Reimport erstellt wurde. Stimmt der aktuelle Wert noch mit diesem Digest überein, hat das Tool ihn geschrieben, und der Scan darf ihn aktualisieren; hat eine Person das Feld seither bearbeitet, bleibt der menschliche Wert dauerhaft erhalten. Befunde, die vor Einführung dieser Funktion erstellt wurden, besitzen keine Digests und gelten als »menschlich verwaltet« — der Reimport überschreibt ihre beschreibenden Felder nie. Die einzige Ausnahme ist die **Komponentenversion**, die Scan-Telemetrie darstellt und von Menschen praktisch nie manuell bearbeitet wird: sie wird auch ohne Digest aktualisiert, sodass migrierte SCA-Befunde weiterhin Versionsaktualisierungen erhalten.

### Die Identität folgt stets der Meldung des Tools

Wenn ein zugeordneter Befund aktualisiert wird, werden seine gespeicherten Identitäts-Hashes **aus den Werten des eingehenden Scans übernommen** — niemals aus den aktuellen Feldern des Befunds neu berechnet. Diese Unterscheidung ist wichtig: Die Felder eines Befunds sind nach einer Aktualisierung eine *Zusammenführung* aus Scan-Werten und menschlichen Bearbeitungen, und ein aus dieser Zusammenführung berechneter Hash würde Werte enthalten, die kein Scan je wieder melden wird — was jeden künftigen Reimport dieses Befunds stillschweigend zerstören würde. Die Übernahme garantiert, dass eine Person, die einen Befund umbenennt, seinen Schweregrad neu triagiert oder seine Beschreibung bearbeitet, dessen Fähigkeit, dem nächsten Scan zugeordnet zu werden, niemals beeinträchtigen kann.

## Standort-Historie

Unter **Locations** (Beta) zeichnet jede Drift-Zuordnung auf, wo der Befund zuvor lebte: der abgelöste Quellcode-Standort, die URL oder die Abhängigkeitsversion wird als Referenz am Befund gespeichert, versehen mit dem Zeitpunkt und Grund der Verschiebung. Die Standort-Zeitleiste des Befunds — »dieser Befund lebte bei `auth.py:42`, dann bei `auth.py:57`, dann bei `session.py:31`« — ist auf der Befundseite sichtbar. Siehe [Source Code Locations](/asset_modelling/locations/pro__source_code_locations/).

Die Standort-Drift-Zuordnung selbst funktioniert **mit oder ohne** die Locations-Funktion: Die Zuordnung paart anhand der eigenen Felder und Endpunkte des Befunds, sodass Befunde eine Verschiebung so oder so überstehen. Locations fügt darüber hinaus die aufgezeichnete, sichtbare Historie hinzu. Die Aufzeichnung der Historie beginnt in dem Moment, in dem Locations aktiviert wird — frühere Verschiebungen wurden angewendet, aber nicht aufgezeichnet.

## Aktivieren bei vorhandenen Daten (Upgrades)

Die Funktion ist so konzipiert, dass sie sich selbst migriert:

- **Nichts ändert sich, bis Sie sich dafür entscheiden.** Bei deaktiviertem Schalter werden Reimport-Hashes exakt wie zuvor berechnet.
- **Das Speichern des Schalters berechnet die Hashes bestehender Befunde neu.** Der Hintergrundjob berechnet die gespeicherten Reimport-Hashes des Tools mit der neuen (standortfreien) Identität neu und erstellt alle fehlenden Pro-Befunddatensätze für aus Open Source migrierte Daten. Sobald der Job abgeschlossen ist, sprechen alte und neue Befunde dieselbe Identitätssprache — ein vor Monaten importierter Befund wird genauso verfolgt wie einer, der gestern importiert wurde.
- **Zwischen Scan-Läufen auf großen Instanzen aktivieren.** Das Neuberechnen ist ein Hintergrundjob über die gesamte Befundmenge des Tools. Ein Reimport, der eintrifft, während dieser Job noch läuft, kann eine Mischung aus alten und neuen Hashes sehen und den noch nicht verarbeiteten Teil einmalig durchwirbeln. Schalten Sie die Funktion zu einer ruhigen Zeit um, und lassen Sie den Job abschließen, bevor der nächste geplante Reimport läuft.
- **Manuell bearbeitete Titel.** Das optionale Neuberechnen erfolgt anhand der aktuellen Datenbankwerte. Jedes häufig bearbeitete Feld ist von der verfolgten Identität ausgeschlossen — Schweregrad-Bearbeitungen werden durch das Neuberechnen sogar tatsächlich *geheilt* — aber wenn eine Person den **Titel** eines Befunds umbenannt hat (und der Titel für dieses Tool ein Hash-Feld ist), wird genau dieser Befund bei seinem nächsten Reimport einmal durchwirbeln, bevor er sich stabilisiert.

## Hash-Felder für verfolgte Tools auswählen

Die Standortverfolgung entfernt die volatilen Standortfelder automatisch aus dem Reimport-Hash — Sie müssen `line` oder `file_path` nicht selbst aus der Hash-Konfiguration eines Tools entfernen. Zwei Konfigurationen verdienen besondere Aufmerksamkeit:

- **Vollständig volatile Konfigurationen.** Wenn die Hash-Felder eines Tools *ausschließlich* aus Standortfeldern bestehen (zum Beispiel nur `file_path` + `line`), bleibt nach deren Entfernung nichts übrig, und der Hash fällt auf die alte Titel+CWE-Identität zurück. Die Zuordnung funktioniert weiterhin — die Nachweisdurchläufe liefern die Unterscheidung —, aber die Identität ist deutlich gröber. Bevorzugen Sie Konfigurationen, die mindestens ein stabiles Inhaltsfeld beibehalten.
- **In stabilen Feldern eingebetteter Standort.** Feldausschlüsse helfen nicht, wenn sich Standortdaten *innerhalb* eines Felds verbergen, das im Hash bleiben muss. Ein Tool, das Befunde mit Titeln wie »SQL Injection in queries.py:42« versieht, ändert seinen Titel bei jeder Zeilenverschiebung — die Identität spaltet sich auf, und die Verfolgung kann die Paarung nicht erkennen. Wählen Sie für solche Tools Hash-Felder, die das durchsickernde Feld vermeiden; **CWE + Content Fingerprint** ist die stärkste Kombination (siehe [Content Fingerprint](/triage_findings/finding_deduplication/pro__deduplication_tuning/#content-fingerprint)).

## Zusammenspiel mit der Deduplizierung

Die Standortverfolgung ist eine **Reimport**-Funktion: Same Tool und Cross Tool Deduplication bleiben unverändert — ihre Hashes werden exakt wie zuvor berechnet, und die Ausschlüsse gelten für sie nie. Zwei bewusste Integrationen:

- **Versionssprünge blockieren die Abhängigkeits-Deduplizierung nicht mehr.** Die Standort-Schranke der Deduplizierung verlangt normalerweise, dass zwei SCA-Befunde auf die *identische* Paketversion verweisen. Für Tools mit aktivierter Verfolgung genügt eine gemeinsame Paketidentität (Ökosystem + Paketname, wobei der Namespace verglichen wird, sofern beide Seiten einen mitführen) — im Einklang damit, dass der Reimport einen Versionssprung als denselben Befund behandelt. Dies gilt nur für Same-Tool-Deduplizierung unter Locations.
- **Saubere Identitäts-Eingaben.** Da zugeordnete Befunde vom Scan gemeldete Hashes übernehmen, spiegeln die von der Deduplizierung verwendeten Werte stets wider, was das Tool zuletzt gemeldet hat — menschliche Bearbeitungen können sie nicht mehr verfälschen.

## Historisches Hin-und-Her konsolidieren

Instanzen, die jahrelang ohne Verfolgung liefen, sammeln Ketten aus Schließen-und-Neuerstellen an: derselbe Befund wurde bei jeder Verschiebung geschlossen und als neuer Datensatz wiedereröffnet. Ein Management-Befehl findet diese Ketten (Schritt für Schritt durch dieselben Matcher verknüpft, mit einer Lebensdauer-Überlappungssicherung, damit Befunde, die tatsächlich gleichzeitig existierten, niemals zusammengeführt werden) und konsolidiert jede Kette auf ihren jüngsten Befund, wobei die älteren Kopien als Duplikate des überlebenden Befunds markiert werden:

```bash
# Dry run — reports what would be consolidated, changes nothing
./manage.py consolidate_location_churn --product <id>

# Apply, with a confirmation prompt
./manage.py consolidate_location_churn --product <id> --apply
```

Der Befehl läuft standardmäßig als Trockenlauf, wird nie automatisch ausgeführt und kann mit `--test` oder `--product` eingegrenzt werden. Unter Locations wird die Standort-Historie des überlebenden Befunds aus der Kette rekonstruiert.

## Absicherungen und Grenzen

- **Exakte Übereinstimmungen gewinnen immer.** Ein unverschobener Befund wird exakt zugeordnet, bevor ein unscharfer Durchlauf läuft; verschobene Befunde können ihm seine Zuordnung nie stehlen.
- **Mehrdeutigkeit führt zu keiner Zuordnung.** Dateiumbenennungen und Host-Wechsel paaren nur, wenn auf jeder Seite genau ein Kandidat übrig bleibt. Zwei Befunde, die beide verschwanden, während zwei neue erschienen, bleiben unzugeordnet, statt geraten zu werden.
- **Sehr große Gruppen degradieren kontrolliert.** Überschreitet ein einzelner Identitätsblock die Paarungsobergrenze (40.000 Vergleiche), degradiert die Zuordnung für diesen Block auf reinen Exakt-Abgleich, statt unbegrenzt Zeit zu verbrauchen.
- **Akzeptierter Kompromiss:** Die 1×1-Durchläufe für Umbenennung/Host-Wechsel können eine falsche Kontinuität erzeugen, wenn ein Befund verschwindet und ein nicht verwandter Befund mit derselben stabilen Identität im selben Reimport erscheint. Dies ist der bewusste Preis für die Verfolgung von Umbenennungen; die stabile Identität (gleiches Tool, Titel, CWE, Schweregrad ...) begrenzt, wie falsch die Paarung ausfallen kann.

## Standortaktualisierung ohne den Schalter

Unabhängig von der Standortverfolgung hält der Reimport den Standort jedes zugeordneten Befunds bei **allen** Algorithmen aktuell: Ein per Unique ID From Tool (oder einem beliebigen anderen Algorithmus) zugeordneter Befund aktualisiert seine Felder `line`, `file_path`, Datenflussfelder und `component_version` aus dem eingehenden Bericht, und gemeldete Endpunkte werden angehängt, während verschwundene als behoben markiert werden. Werte, die ein Scan auslässt, überschreiben nie vorhandene Daten, und eine von einem Menschen fixierte Komponentenversion bleibt erhalten. Dies schließt die seit langem bestehende Lücke, bei der uid-zugeordnete SAST-Befunde für immer die Zeilennummer ihres ersten Imports anzeigten. Es kann instanzweit mit `DD_REIMPORT_REFRESH_LOCATION_FIELDS=False` deaktiviert werden.
