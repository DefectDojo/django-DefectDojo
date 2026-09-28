---
title: Diagnostics
description: 'Lesen Sie das subsystemübergreifende Logbuch der Integrationsversuche:
  was aufgezeichnet wird, wie Sie es filtern, wie Zugangsdaten ferngehalten werden
  und wer die technischen Details sehen kann'
weight: 1
audience: pro
---

Diagnostics ist ein einziges Logbuch für jeden Versuch, den DefectDojo unternimmt, um mit einem System außerhalb von sich selbst zu kommunizieren – und für die Versuche anderer Systeme, mit DefectDojo zu kommunizieren. Wenn ein Ticket nie erschienen ist, ein Scan nie importiert wurde oder sich ein Benutzer nicht anmelden konnte, ist dies die Seite, die zeigt, was passiert ist, wann es passiert ist, welche Konfiguration betroffen war und wer es ausgelöst hat.

Diagnostics ist eine **DefectDojo Pro**-Funktion. Sie finden es unter **Connect > Diagnostics**.

![Das Diagnostics-Logbuch, Ansicht „Fehler“](images/diagnostics_errors.png)

## Was aufgezeichnet wird

Pro Versuch wird eine Zeile geschrieben, aus jedem Subsystem, das über DefectDojo hinausreicht:

| Quelle | Was Zeilen erzeugt |
| --- | --- |
| **Connector** | Discover- und Sync-Läufe von Upstream-Connectors |
| **Downstream-Integrator** | Pushes an Jira, GitHub, GitLab, ServiceNow und die anderen Downstream-Connectors |
| **Jira** | Die klassische Jira-Integration: Pushes, Kommentare und Vorschauen |
| **SSO (OIDC/OAuth2)** | Anmeldeversuche über einen OAuth-Provider |
| **SAML** | SAML-Assertions, einschließlich Signatur- und Attributfehlern |
| **LDAP** | LDAP-Binds und -Lookups |
| **Import / Reimport** | Scan-Uploads, ob über UI, API oder Zeitplan |
| **Regel-Engine** | Regelauswertungen und die dabei versuchten Aktionen |
| **Planung** | Geplante Läufe, einschließlich solcher, die nie gestartet sind |
| **Sensei** | Repository-Scans und Fix-Läufe |
| **Benachrichtigung** | Ausgehende Benachrichtigungszustellung |
| **System** | Instanzweite Aktivität, die zu keinem Produkt gehört |

Zeilen werden *neben* dem Subsystem geschrieben, niemals an dessen Stelle. Jeder Adapter ist an den Ursprungsdatensatz angehängt und bewusst fail-safe: Wenn das Schreiben einer Diagnosezeile einen Fehler auslöst, wird dieser Fehler abgefangen und der ursprüngliche Vorgang läuft weiter. Diagnostics kann daher niemals der Grund dafür sein, dass ein Push, Import oder Login fehlschlägt.

Da Zeilen anhand des Datensatzes indiziert werden, der sie erzeugt hat, aktualisiert ein erneutes Speichern eines Ursprungsdatensatzes die vorhandene Diagnosezeile, anstatt ein Duplikat hinzuzufügen. Ein Versuch ist während seines gesamten Lebenszyklus eine Zeile, von `Queued` über `Running` bis zu seinem Ergebnis.

### Felder einer Zeile

| Feld | Bedeutung |
| --- | --- |
| **Wann** | Wann die Zeile aufgezeichnet wurde; **Gestartet**, **Beendet** und **Dauer** beschreiben den Versuch selbst |
| **Quelle** | Das Subsystem, aus der obigen Tabelle |
| **Anbieter** | Das konkrete Tool oder der Provider innerhalb dieser Quelle (`jira`, `github`, `okta`, ein Scanner-Name) |
| **Vorgang** | Was versucht wurde (`push`, `sync`, `login`, `reimport`, `rule_run`) |
| **Status** | `Queued`, `Running`, `Success`, `Failed`, `Timed out`, `Skipped` oder `Dry run` |
| **Schweregrad** | `Info`, `Warning`, `Error` oder `Critical` |
| **Zusammenfassung** | Ein einzeiliges Ergebnis, das sich auf einen Blick erfassen lässt |
| **Auslöser** | Was den Versuch ausgelöst hat: `UI`, `API`, `Scheduled`, `Webhook`, `Automatic`, `Command line` oder `System` |
| **Ausgelöst von** | Der verantwortliche Benutzer, oder `System` bei unbeaufsichtigten Vorgängen |
| **Asset** | Das Produkt, zu dem der Versuch gehört; leer bedeutet instanzweit |
| **Zugehöriges Objekt** | Der Befund, das Engagement oder ein anderer Datensatz, um den es bei dem Versuch ging |
| **Konfiguration** | Welche Konfiguration verwendet wurde, anhand ihrer Bezeichnung |
| **Externe Referenz** | Die vom anderen System zurückgegebene Kennung, etwa der Schlüssel eines erstellten Issues |
| **Korrelations-ID** | Verknüpft Zeilen desselben logischen Vorgangs |
| **Gemeldete Details** und **Kontext** | Die vollständigen technischen Details (eingeschränkt, siehe [Wer sieht was](#who-sees-what)) |

## Die vier Ansichten

Die Tabs oberhalb der Tabelle sind gespeicherte Ausgangspunkte, keine Filter, die Sie jedes Mal neu aufbauen müssen:

* **Fehler** – Fehlschläge und Zeitüberschreitungen. Diese Ansicht sollten Sie zuerst öffnen.
* **Erfolge** – der Nachweis, dass eine funktionierende Integration tatsächlich funktioniert; nützlich, wenn jemand meldet, dass „nichts synchronisiert wird“.
* **Nie abgeschlossen** – Versuche, die noch `Queued` oder `Running` sind, obwohl sie längst hätten fertig sein sollen. Das sind die stillen Fälle: Nichts ist fehlgeschlagen, also wurde auch nichts gemeldet – aber es ist auch nichts angekommen.
* **Alle Ereignisse** – alles, ungefiltert.

![Alle Ereignisse, mit allen Quellen](images/diagnostics_all_events.png)

Die aktive Ansicht ist Teil der Seiten-URL, sodass eine Ansicht verlinkbar ist und einen Refresh übersteht.

## Die Liste eingrenzen

* **Zeitraum** – 24 Stunden, 7 Tage, 30 Tage oder 90 Tage, über die Schaltflächen im Kopfbereich.
* **Quellenzähler** – die farbigen Zähler unter den Übersichtskarten sind ebenfalls Schnellfilter. Klicken Sie auf einen, um nur diese Quelle anzuzeigen; klicken Sie erneut darauf (oder auf **Quellfilter zurücksetzen**), um zurückzukehren. Es ist immer höchstens einer aktiv.
* **Filter und Sortierung pro Spalte** – jede Spalte lässt sich filtern und sortieren, einschließlich Schweregrad und Quelle. Schweregrad sortiert nach Schwere (`Critical` → `Info`) statt alphabetisch, und Quelle sortiert nach der angezeigten Bezeichnung statt nach dem intern gespeicherten Wert.
* **Stichwortsuche** – durchsucht alle Textfelder gleichzeitig.
* **Spalteneinstellungen** – die Spaltenauswahl und die gespeicherten Layouts verhalten sich wie bei jeder anderen Pro-Liste.

![Ein Quellenzähler, der als Schnellfilter verwendet wird](images/diagnostics_chip_filter.png)

Klicken Sie auf die Lupe am Anfang einer Zeile, um den gesamten Versuch zu öffnen:

![Ein einzelnes Ereignis, einschließlich des Hinweises zur Schwärzung](images/diagnostics_detail.png)

## Zugangsdaten werden entfernt, bevor die Zeile geschrieben wird

Integrationsfehler zitieren die fehlgeschlagene Anfrage, und diese Zitate enthalten Geheimnisse: einen `Authorization`-Header, ein Token in einem Query-String, ein Passwort innerhalb einer Verbindungs-URL. Diagnostics entfernt diese **auf dem Weg hinein**, sodass der ursprüngliche Wert niemals in der Datenbank landet und auch kein späterer Sinneswandel ihn offenlegen kann.

Zwei Dinge werden bereinigt:

* **Werte unter Schlüsseln, die wie Zugangsdaten aussehen** – alles, dessen Schlüssel wie ein Geheimnis aussieht (`password`, `token`, `secret`, `api_key`, `authorization`, `private_key` und Ähnliches, unabhängig von Groß-/Kleinschreibung oder mit Bindestrichen oder Leerzeichen). Eine kleine Gruppe von Schlüsseln ist ausgenommen, weil nur ihr *Vorhandensein* zählt, niemals ihr Inhalt.
* **Werte, die überall dort wie Zugangsdaten aussehen, wo sie auftauchen** – Bearer- und Basic-Authorization-Header, JWTs, in URLs eingebettete Zugangsdaten (`https://user:pass@host`), erkennbare Anbieter-Token-Präfixe und PEM-Blöcke.

Jeder Wert wird durch `[redacted]` ersetzt. Die umgebende Meldung bleibt erhalten, sodass der Fehler lesbar bleibt:

```text
401 Unauthorized: Authorization: [redacted]
upload rejected: https://svc:[redacted]@sftp.example/out/…
```

Lange Werte werden gekürzt, und tief verschachtelter Kontext wird abgeflacht, damit eine einzelne riesige Payload die Tabelle nicht aufblähen kann.

Wenn aus einer Zeile etwas entfernt wurde, wird dies in der Zeile vermerkt, anstatt Sie im Unklaren zu lassen, ob das Feld leer war oder geleert wurde.

> **Die Schwärzung ist bewusst als Best-Effort-Mechanismus ausgelegt.** Die Bereinigung erkennt *Muster* von Zugangsdaten. Ein Geheimnis, das wie gewöhnlicher Fließtext aussieht, unter einem Schlüssel, der nicht sensibel wirkt, kann trotzdem aufgezeichnet werden. Behandeln Sie Diagnostics als Betriebsprotokoll, nicht als einen Ort, an dem garantiert keine Geheimnisse vorkommen – und beschränken Sie die technischen Details auf die Personen, die sie wirklich benötigen.

## Wer sieht was

Diagnostics ist gestaffelt, denn die Zusammenfassung eines Fehlschlags ist für einen Produktverantwortlichen nützlich, die rohe Anfrage dahinter dagegen nicht.

| | Superuser | Alle anderen |
| --- | --- | --- |
| Zeilen für Produkte, für die sie autorisiert sind | Ja | Ja |
| Instanzweite Zeilen (kein Produkt) | Ja | Nein |
| Zusammenfassung, Quelle, Status, Schweregrad, Zeiten, Konfiguration | Ja | Ja |
| **Gemeldete Details**, **Kontext**, **Remote-IP** | Ja | Zurückgehalten, und als zurückgehalten gekennzeichnet |

Ein Nicht-Superuser sieht, dass ein Detail existiert und zurückgehalten wird, statt eines leeren Felds, das wie fehlende Daten wirkt. Instanzweite Zeilen – SSO, SAML, LDAP und andere Aktivitäten, die zu keinem Produkt gehören – sind nur für Superuser sichtbar, da es keine Produktmitgliedschaft gibt, die Zugriff darauf gewähren könnte.

## Wie lange Datensätze aufbewahrt werden

Ein geplanter Task kürzt das Logbuch, damit es nicht unbegrenzt wächst:

| Schweregrad | Aufbewahrungsdauer |
| --- | --- |
| `Info` | 30 Tage |
| `Warning`, `Error`, `Critical` | 180 Tage |

Beide Zeiträume lassen sich über die Einstellungen `DIAGNOSTIC_EVENT_INFO_RETENTION_DAYS` und `DIAGNOSTIC_EVENT_RETENTION_DAYS` konfigurieren. Das Löschen erfolgt in Batches, sodass eine große Bereinigung keine lange Transaktion offen hält.

## API

Das Logbuch ist über die API unter `/api/v2/diagnostic_events/` nur lesbar:

| Endpunkt | Rückgabe |
| --- | --- |
| `GET /api/v2/diagnostic_events/` | Die Liste, mit den unten aufgeführten Filtern |
| `GET /api/v2/diagnostic_events/{id}/` | Ein Ereignis |
| `GET /api/v2/diagnostic_events/summary/` | Die Zähler hinter den Übersichtskarten, einschließlich der Werte pro Quelle |
| `GET /api/v2/diagnostic_events/choices/` | Die gültigen Werte für `source`, `status`, `severity` und `trigger` |

Nützliche Parameter:

| Parameter | Wirkung |
| --- | --- |
| `source`, `status`, `severity`, `trigger` | Akzeptieren mehrere kommagetrennte Werte gleichzeitig |
| `failures_only=true` | Fehlschläge und Zeitüberschreitungen |
| `unresolved_only=true` | Versuche, die noch in der Warteschlange sind oder laufen |
| `product_name` | Filtert nach Produktname |
| `object_model` | Filtert nach der Art des Datensatzes, um den es bei dem Versuch ging |
| `o=` | Sortierung, mit vorangestelltem `-` zum Umkehren (`o=-created_at`) |

Es gelten dieselben Zugriffsregeln: Ein Nicht-Superuser erhält produktbezogene Zeilen, bei denen die eingeschränkten Felder zurückgehalten werden.

## Herausfinden, was schiefgelaufen ist

* **Ein Ticket ist nie erschienen.** Filtern Sie Quelle nach dem Integrator (oder Jira) und prüfen Sie dann Status. `Failed` liefert Ihnen den Grund in Zusammenfassung; `Queued` lange nach dem erwarteten Zeitpunkt bedeutet, dass der Job nie gelaufen ist – das ist eher ein Worker- oder Planungsproblem als ein Problem mit den Zugangsdaten.
* **Ein Benutzer kann sich nicht anmelden.** Filtern Sie Quelle nach SSO, SAML oder LDAP und lesen Sie den Fehlschlag zu seinem Versuch – eine ungültige Assertion-Signatur, ein abgelehnter Bind, ein nicht übereinstimmendes Attribut. Diese Zeilen sind instanzweit und daher nur für Superuser sichtbar.
* **Ein Scan ist nicht aufgetaucht.** Filtern Sie Quelle nach Import / Reimport. Schauen Sie sich Auslöser an, um einen unbeaufsichtigten geplanten Upload von einem manuellen zu unterscheiden, und Ausgelöst von, um zu sehen, wen Sie fragen müssen.
* **Etwas versucht es endlos erneut.** Sortieren Sie nach Korrelations-ID oder filtern Sie danach, um alle Versuche desselben logischen Vorgangs gemeinsam zu sehen.
* **„Nichts funktioniert.“** Öffnen Sie zuerst Erfolge für denselben Zeitraum. Eine gesunde Liste dort macht aus einem vagen Ausfall einen konkreten.

## Verwandte Themen

* [Feature Flags](/admin/feature_flags/pro__feature_flags/) – optionale Pro-Funktionen ein- und ausschalten
* [Connectors](/connectors/upstream/about/) – Befunde einholen
* [Pro Integrations](/connectors/downstream/about/) – Befunde weitergeben
* [Single Sign-On](/admin/sso/) – die Identity-Provider, deren Anmeldeversuche hier erscheinen
