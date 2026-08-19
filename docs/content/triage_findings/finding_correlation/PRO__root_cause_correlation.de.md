---
title: Root-Ursachen-Korrelation
description: Gruppieren Sie Befunde, die eine gemeinsame Ursache teilen -- dieselbe
  verwundbare Komponente, CVE, Infrastrukturressource oder Schwachstelle an einer
  URL --, sodass sich eine Behebung auf jeden Befund zurückverfolgen lässt, den sie
  löst
weight: 1
audience: pro
---

Eine verwundbare Bibliothek, die in vierzig Services eingebunden ist, erzeugt vierzig Befunde. Jeder
ist real, jeder wird separat bearbeitet, und jeder wird durch dasselbe einzelne Versions-Update behoben. Die **Ursachenkorrelation**
macht diesen Zusammenhang explizit: DefectDojo Pro gruppiert Befunde, die eine gemeinsame Ursache teilen, in eine nach Rang
geordnete Liste von **Ursachen**, sodass Sie die eine Behebung sehen können und alles, was sie beseitigt.

Die Korrelation ist **additiv und nicht destruktiv**. Jeder Befund bleibt unabhängig sichtbar,
behält seinen eigenen Status und wird genau wie zuvor bearbeitet. Die Korrelation fügt lediglich Verknüpfungen zwischen
Befunden hinzu, die Cluster-Knoten, zu denen diese Verknüpfungen zusammengefasst werden, sowie die Belege, die jede Verknüpfung erzeugt haben.

> **Korrelation ist keine Deduplizierung.** Die [Deduplizierung](/triage_findings/finding_deduplication/)
> entscheidet, dass zwei Berichte denselben Befund beschreiben, und markiert einen davon als Duplikat. Die Korrelation
> stellt einen Zusammenhang zwischen *unterschiedlichen* Befunden her, die zufällig eine Ursache teilen, und markiert niemals etwas als
> Duplikat. Beide laufen unabhängig voneinander und können gleichzeitig aktiviert werden.

## Aktivieren der Ursachenkorrelation

Die Ursachenkorrelation befindet sich in der **Beta**-Phase, ist hinter einem Feature-Flag verborgen und ist **standardmäßig deaktiviert**.
Ein Superuser kann sie sowohl auf Cloud- als auch auf On-Premise-Instanzen unter **Settings > Feature Flags** aktivieren.
Siehe [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Solange das Flag deaktiviert ist, leistet die Engine überhaupt keine Arbeit: Es werden keine Cluster erstellt, keine
Verknüpfungen angelegt, und nach einem Import wird nichts ausgelöst.

Nachdem Sie das Flag aktiviert haben, werden bestehende Befunde **nicht** rückwirkend korreliert, bis sie entweder
erneut importiert werden oder Sie einen Backfill durchführen (siehe
[Bestehende Befunde nachträglich korrelieren](#backfilling-existing-findings)).

## Was korreliert wird

Die Korrelation gruppiert anhand von vier Signalen. Drei davon sind **exakt** -- eine Verknüpfung wird nur dort erstellt, wo
zwei Befunde tatsächlich dasselbe benennen --, und eines ist eine gekennzeichnete Heuristik.

| Ursachentyp | Befunde werden gruppiert, wenn sie... | Beispiel | Übereinstimmung |
|---|---|---|---|
| **Komponente** | dieselbe Softwarekomponente in derselben Version referenzieren | `log4j-core 2.14.1` | Exakt |
| **CVE** | denselben CVE-Bezeichner referenzieren | `CVE-2021-44228` | Exakt |
| **Ressource** | dasselbe Infrastrukturobjekt benennen | `aws_s3_bucket.logs` | Exakt |
| **Endpunkt** | dieselbe Schwachstellenklasse an derselben URL melden | `CWE-79 at example.com/search` | Heuristisch |

Ein Befund tritt **jedem** Cluster bei, der auf ihn zutrifft, nicht nur einem. Ein SCA-Befund für
`log4j-core 2.14.1`, der drei CVEs trägt, tritt vier Ursachen bei: seinem Komponenten-Cluster und je einem
Cluster pro CVE. Das ist es, was es einem Container-Image-Befund, der nur eine CVE meldet, ermöglicht, mit dem
SCA-Befund zu korrelieren, der die Komponente meldet.

### Abgleich von Komponenten

Wo das Locations-Datenmodell verwendet wird, werden Komponenten anhand der **Package URL (purl)** identifiziert,
wobei Qualifier und Unterpfade entfernt werden, sodass dasselbe Paket, das für verschiedene Distributionen
oder Architekturen gemeldet wird, ein einziges Cluster statt mehrerer bildet. Befunde, die nur die veralteten
`component_name`-/`component_version`-Felder tragen, werden stattdessen anhand dieser identifiziert.

Befunde ohne verwertbare Komponente werden übersprungen statt gruppiert: Eine fehlende Version oder der
Platzhalter `unknown-package`, den manche SBOM-Formate ausgeben, würde sonst jede
komponentenlose Zeile zu einem bedeutungslosen Cluster zusammenfassen.

### Abgleich von CVEs

CVE-Bezeichner werden in Großbuchstaben umgewandelt und getrimmt, sodass `cve-2021-44228` und `CVE-2021-44228` im
selben Cluster landen. Es werden nur CVE-Bezeichner abgeglichen — GHSA-, GO-, RUSTSEC- und andere Advisory-Präfixe werden
an anderer Stelle in DefectDojo als Schwachstellen-IDs erkannt, bilden aber noch keine Ursachen.

### Abgleich von Ressourcen

Cloud-Posture-Tools (CSPM) und Infrastructure-as-Code-Tools (IaC) melden eine **Ressource** statt eines
Pakets: einen S3-Bucket, einen Kubernetes-Namespace, einen Terraform-Ressourcenblock. Diese Befunde tragen einen
Namen, aber keine Version, sodass sie keine Softwarekomponenten sind und auch nicht als solche abgeglichen werden.

Der Ressourcenabgleich gruppiert sie anhand des Ressourcenbezeichners, wobei die Groß-/Kleinschreibung ignoriert wird, sodass Tools,
die ihn unterschiedlich schreiben, trotzdem übereinstimmen. Es handelt sich um eine exakte Verknüpfung, und sie ermöglicht es, dass ein IaC-Befund zu
`aws_s3_bucket.logs` in derselben Ursache landet wie der CSPM-Laufzeitbefund zum bereitgestellten
Bucket.

Es werden nur qualifizierte Bezeichner abgeglichen -- ein Ressourcenname enthält ein Typ- oder Pfadtrennzeichen
(`.`, `/`, `:`). Ein einzelnes Wort ohne Trennzeichen wird ignoriert, sodass ein Befund, dessen Scanner lediglich die
Komponentenversion ausgelassen hat, nicht in ein Ressourcen-Cluster gerät, mit dem er nichts zu tun hat.

### Abgleich von Endpunkten

Zwei DAST-Tools, die dieselbe Anwendung scannen, melden häufig beide dieselbe Schwachstelle an derselben
URL. Der Endpunktabgleich gruppiert diese: Die Ursache ist eine **Schwachstellenklasse an einem Ort**, zum
Beispiel `CWE-79 at example.com/search`.

Dies ist das einzige **heuristische** Signal, und es wird überall dort, wo es auftritt, entsprechend gekennzeichnet. Eine gemeinsame
purl oder CVE ist eine Identität; „dieselbe CWE, dieselbe URL“ ist eine Einschätzung, und ein Prüfer sollte sie
anders gewichten können. Die Cluster-Detailansicht kennzeichnet jedes Mitglied mit seinem Übereinstimmungstyp.

Die CWE ist erforderlich. Eine URL für sich genommen ist ein Ort, keine Ursache -- jeden Befund unter
`/search` zu gruppieren, unabhängig davon, was daran falsch ist, würde große, bedeutungslose Cluster erzeugen.

Query-Strings, Fragmente und Ports werden beim Vergleich von URLs ignoriert, sodass `/search?q=a` und
`/search?q=b` derselbe Ort sind, ebenso wie derselbe Dienst auf 443 und 8443.

> **Dies korreliert SAST nicht mit DAST.** Statische Befunde identifizieren eine Quelldatei, und dynamische
> Befunde identifizieren eine URL; die Zuordnung zwischen beiden erfordert eine Routenzuordnung, über die DefectDojo nicht verfügt.
> Der Endpunktabgleich stellt einen Zusammenhang zwischen dynamischen Befunden untereinander her.

### Wenn eine CVE bereits durch eine Komponente abgedeckt ist

Ein Befund tritt sowohl seiner Komponenten-Ursache *als auch* jeder seiner CVE-Ursachen bei, sodass ein SCA-Befund für
`log4j-core 2.14.1` mit zwei CVEs drei Ursachen erzeugt. Unbehandelt konkurrieren alle drei
um die Spitze der Rangliste — aber nur eine davon ist tatsächlich zu erledigende Arbeit. Die Aktualisierung von `log4j-core`
auf eine behobene Version beseitigt beide CVEs direkt; es gibt keine separate Maßnahme „CVE-2021-44228 beheben“.

Daher wird eine CVE-Ursache als **abgedeckt** markiert, wenn *jeder* ihrer aktiven Mitglieds-Befunde auch
ein aktives Mitglied einer einzelnen Komponenten- oder Ressourcen-Ursache ist. Abgedeckte Ursachen werden standardmäßig auf der
Ursachen-Seite ausgeblendet, sodass die Liste auf Dinge beschränkt bleibt, bei denen Sie tatsächlich handeln können.

Sobald **ein** Mitglied außerhalb dieser Komponente liegt, steht die CVE wieder für sich allein. Das ist
der Container-Image-Befund, der nur eine CVE ohne zugehörige Komponente meldet: Keine Komponentenbehebung
erreicht ihn, sodass die CVE tatsächlich eine eigenständige Aufgabe ist. Genau diesen bereichsübergreifenden Fall
soll die Korrelation sichtbar machen, und er wird nie ausgeblendet.

Aktivieren Sie **Show covered CVEs** oberhalb der Tabelle, um sie anzuzeigen. Jede ist mit der Ursache gekennzeichnet,
die sie abdeckt, sodass klar ist, welche Behebung sie beseitigt. Abgedeckte Ursachen werden nur aus der
Standardliste ausgeblendet — sie behalten ihre Mitglieder, Belege und Rückmeldungen, sie bleiben über das
Ursachen-Panel eines Befunds erreichbar, und ein gespeicherter Link zu einer solchen Ursache öffnet sich weiterhin.

Die Abdeckung wird bei jedem Lauf in beide Richtungen neu bewertet: Eine CVE hört auf, abgedeckt zu sein, sobald
ein nicht abgedeckter Befund auftaucht, und wird wieder abgedeckt, sobald dieser Befund behoben oder aus der Bearbeitung entfernt
wird. Das Ablehnen einer Verknüpfung entfernt dieses Mitglied ebenfalls aus der Berechnung, da Sie angegeben haben, dass es nicht
dazugehört.

Komponenten- und Ressourcen-Ursachen werden nie als abgedeckt markiert, selbst wenn sich ihre Mitglieder mit denen
einer anderen überschneiden. Jede hat ihre eigene Version zu aktualisieren, also ist jede reale Arbeit.

### Welche Befunde infrage kommen

Es werden nur aktive, umsetzbare Befunde korreliert. Ein Befund wird ausgeschlossen, solange er inaktiv,
Behoben, ein Duplikat, Falsch-positiv, Außerhalb des Geltungsbereichs oder Risiko akzeptiert ist. Befunde fallen aus
ihren Clustern heraus, sobald sie bearbeitet werden, sodass die Zählungen einer Ursache stets ausstehende Arbeit beschreiben.

## Die Ursachen-Seite lesen

Öffnen Sie **Root Causes** im Abschnitt **Manage** der Seitenleiste. Die Seite listet jede Ursache auf,
auf die Sie Zugriff haben, nach Rang geordnet, sodass die größten, riskantesten zuerst erscheinen.

| Spalte | Was sie Ihnen sagt |
|---|---|
| **Ursache** | Die Komponente und Version oder die CVE |
| **Typ** | Komponente, CVE, Ressource oder Endpunkt |
| **Fix** | Die Version, die das Problem behebt, wenn sich die Mitglieder des Clusters auf eine einigen |
| **CVEs** | Jede CVE, die über die Mitglieder des Clusters hinweg gesehen wurde (Komponenten-Cluster) |
| **Aktive Befunde** | Wie viele ausstehende Befunde auf diese eine Ursache zurückgehen |
| **Produkte** | Blast Radius — wie viele Produkte betroffen sind |
| **Risiko** | Aggregiertes Risiko, summiert aus den Schweregraden der aktiven Mitglieder |
| **Stummgeschaltet** | Ob das Cluster stummgeschaltet wurde |

CVE-Ursachen, die bereits vollständig von einer Komponenten- oder Ressourcen-Ursache abgedeckt werden, werden ausgeblendet, es sei denn,
**Show covered CVEs** ist aktiviert; siehe
[Wenn eine CVE bereits durch eine Komponente abgedeckt ist](#when-a-cve-is-already-covered-by-a-component).

Die Auswahl einer Zeile öffnet das Cluster und listet jeden Mitglieds-Befund mit seinem Schweregrad, Produkt,
seiner Domäne, seinem **Übereinstimmungstyp** und dem **Beleg** auf, der ihn verknüpft. Belege werden pro Verknüpfung erfasst, sodass sich
ein Cluster stets selbst erklären kann: Eine Komponenten-Verknüpfung erfasst die purl, auf die sie abgestimmt wurde, eine CVE-Verknüpfung
erfasst den Bezeichner, eine Endpunkt-Verknüpfung erfasst die URL und die CWE. Die Spalte **Match** zeigt
`exact` für Komponenten-, CVE- und Ressourcen-Verknüpfungen und `heuristic` für Endpunkt-Verknüpfungen, sodass eine Einschätzung
niemals als Identität dargestellt wird.

Das aggregierte Risiko ist eine deterministische Summe über die Schweregrade der aktiven Mitglieder (Kritisch 100, Hoch
70, Mittel 40, Niedrig 10, Info 1). Es hängt nicht davon ab, ob die Priorisierungs-Engine aktiviert ist.

**Fix** wird aus den eigenen Fix-Versionen der Mitglieder übernommen und wird nur angezeigt, wenn jedes Mitglied, das eine
meldet, dieselbe meldet. Scanner sind sich uneinig, und ein CVE-Cluster kann Komponenten umfassen, die jeweils in
einer anderen Version behoben sind. Wo es also keine eindeutige Antwort gibt, bleibt die Spalte
leer, statt eine auszuwählen.

### Was Sie sehen, ist auf Ihren Zugriff beschränkt

Mitglieder, Zählungen und Blast Radius werden auf die Befunde gefiltert, für die Sie berechtigt sind, und die
Rangfolge wird nach dieser Filterung berechnet. Zwei Benutzer mit unterschiedlichem Produktzugriff sehen daher
unterschiedliche Zählungen für dieselbe Ursache, und ein Cluster, dessen Mitglieder Sie nicht sehen können, erscheint
für Sie überhaupt nicht.

## Wo Korrelation sonst noch erscheint

### Bei einem Befund

Die eigene Seite eines Befunds enthält ein **Root Causes**-Panel, das jedes Cluster auflistet, dem er angehört, aufgeteilt
in die verwundbare Komponente (oder Ressource) und die CVEs, die er teilt. Das ist meist der Ort, an dem die
Korrelation am nützlichsten ist: Sie bearbeiten bereits einen Befund, und sie zeigt Ihnen, dass die Behebung
gemeinsam ist. Verknüpfungen, die Sie abgelehnt haben, erscheinen dort nicht erneut.

### Bei der Befundpriorität

Eine Ursache, die viele Produkte umfasst, macht jeden ihrer Mitglieds-Befunde dringlicher, da die
eine Behebung alle davon beseitigt. Die Priorität steigt daher mit dem **Blast Radius der breitesten
Ursache, der ein Befund angehört**:

- Ein auf ein Produkt beschränktes Cluster trägt nichts bei -- es gibt keine Geschichte von „eine Behebung beseitigt viele“.
- Jedes zusätzlich betroffene Produkt trägt etwas mehr bei, bis zu einer Obergrenze, sodass ein sehr breites Cluster
  den Schweregrad nicht aufwiegen kann.
- Das breiteste Cluster zählt, nicht die Summe aller, sodass ein Befund nicht allein deshalb höher eingestuft wird, weil er
  viele CVE-IDs trägt.
- Verknüpfungen, die Sie **abgelehnt** haben, zählen nicht mehr. Ein **stummgeschaltetes** Cluster zählt weiterhin: Das Stummschalten blendet es
  aus der Rangliste aus, es besagt nicht, dass die Befunde nicht zusammenhängen.

Die Gewichtung ist pro Produkt als **Correlation**-Multiplikator in der Priorisierungs-Engine einstellbar,
neben Severity, Exploitability, Endpoints und Reachability. Der gesamte Term entfällt, wenn das
Feature-Flag deaktiviert ist, sodass sich die Scores auf einer Instanz, die keine Korrelation verwendet, nicht ändern.

### Auf einem Dashboard

**Top Root Causes** ist als Dashboard-Widget verfügbar und listet die am höchsten eingestuften Cluster mit
ihrer Anzahl an Befunden, den betroffenen Produkten und dem Risiko auf. Fügen Sie es über die Widget-Auswahl hinzu; es erscheint dort
nur, solange die Funktion aktiviert ist. Seine Zählungen sind auf Ihren Zugriff beschränkt, genauso wie
bei der Seite.

## Rückmeldung zu einem Cluster geben

Korrelation ist eine Einschätzung Ihrer Daten, daher können Sie sie korrigieren.

- **Confirm** Sie ein Mitglied, um festzuhalten, dass die Verknüpfung korrekt ist.
- **Reject** Sie ein Mitglied, um festzuhalten, dass sie es nicht ist, wodurch es aus der Liste der aktiven
  Mitglieder des Clusters entfernt wird.
- **Mute** Sie eine ganze Ursache, damit sie nicht mehr um Aufmerksamkeit in der Rangliste konkurriert. **Unmute**
  stellt sie wieder her.

Rückmeldungen sind dauerhaft. Gewöhnliche Schwankungen durch erneuten Import — ein Befund, der behoben wird und später
wieder aktiv wird — löschen weder eine Bestätigung noch eine Ablehnung, und ein stummgeschaltetes Cluster wird nie bereinigt, selbst wenn es
vorübergehend keine Mitglieder hat. Nur Verknüpfungen, die das System eigenständig erstellt hat, werden entfernt, sobald
sie nicht mehr zutreffen.

## Wie und wann die Korrelation läuft

Die Korrelation läuft **automatisch und asynchron nach jedem Import und Reimport**, über die
Befunde, die dieser Import betroffen hat. Sie arbeitet nach bestem Bemühen: Ein Fehler innerhalb der Korrelation wird protokolliert und
verworfen und lässt den Import, der ihn ausgelöst hat, niemals fehlschlagen.

Da sie idempotent ist, konvergiert ein erneuter Lauf über dieselben Befunde zum selben Ergebnis,
statt etwas zu duplizieren. Wenn sich Befunde ändern, gleicht die Engine ebenfalls ab: Ein Versions-Update einer Komponente
verschiebt den Befund in das neue Cluster und entfernt das alte, sobald es leer ist.

### Bestehende Befunde nachträglich korrelieren

Um Befunde zu korrelieren, die vor der Aktivierung der Funktion entstanden sind, führen Sie den Management-Befehl aus. Lassen Sie
das Argument weg, um das gesamte Portfolio neu zu berechnen, oder beschränken Sie es auf ein einzelnes Produkt:

```bash
python manage.py recompute_correlations
python manage.py recompute_correlations --product-id 42
```

## Was die API bereitstellt

Ursachen sind über die Standard-API lesbar, sodass Sie sie in einen Bericht einbinden, daraus Tickets
eröffnen oder sie als Kennzahl verfolgen können, ohne die UI zu verwenden.

- `GET /api/v2/root_causes/` listet sie auf, in derselben Rangfolge wie auf der Seite.
- `GET /api/v2/root_causes/{id}/` gibt eine Ursache sowie ihre Mitglieds-Befunde zurück, jeweils mit dem
  Beleg, der sie verknüpft, und ob die Übereinstimmung exakt oder heuristisch war.

Beide sind schreibgeschützt. Bestätigen, Ablehnen und Stummschalten erfolgen vorerst über die UI; diese werden
absichtlich nicht veröffentlicht, solange sich die Funktion in der Beta-Phase befindet, damit ein späteres Hinzufügen nichts
beeinträchtigen kann, was Sie bereits darauf aufgebaut haben.

Filter für die Liste: `cause_type` (`exact` oder `in`), `muted`, `identity_key` (`exact` oder
`icontains`) und `display_name__icontains`.

Zwei Verhaltensweisen, die Sie kennen sollten, bevor Sie dagegen skripten:

- **Zählungen sind auf den Zugriff des Tokens beschränkt**, genau wie in der UI. Zwei Tokens mit
  unterschiedlichem Produktzugriff melden für dieselbe Ursache unterschiedliche Werte für `active_member_count`, `product_count` und
  `risk_score`. Das ist beabsichtigt -- die Zahlen beschreiben, was *dieser* Aufrufer
  sehen kann -- behandeln Sie sie also nicht als portfolioweite Gesamtsummen.
- **Abgedeckte CVE-Ursachen werden aus der Liste ausgelassen**, sind aber immer über die ID abrufbar. Übergeben Sie
  `?include_subsumed=true`, um sie einzuschließen; eine zuvor gespeicherte Ursachen-ID funktioniert weiterhin
  über `GET /api/v2/root_causes/{id}/`, selbst nachdem sie abgedeckt wurde. Jede abgedeckte Ursache
  trägt `subsumed_by_id` und `subsumed_by_name`, sodass Sie sehen können, welche Behebung sie beseitigt.

Wenn das Feature-Flag deaktiviert ist, geben beide Endpunkte **403** zurück, nicht 404 -- der Endpunkt existiert,
er ist lediglich nicht aktiviert.

## Zusammenspiel mit der globalen Komponenten-Deduplizierung

Die [globale Komponenten-Deduplizierung](/triage_findings/finding_deduplication/pro__global_component_deduplication/)
markiert produktübergreifende SCA-Befunde als Duplikate, und Duplikate werden nicht korreliert. Wenn beide
Funktionen aktiviert sind, spiegelt die Mitgliederzahl einer Ursache daher die verbliebenen Originale wider statt
jedes Vorkommens. Die beiden basieren zudem auf unterschiedlichen Kriterien — die globale Komponenten-Deduplizierung gleicht anhand von Komponentenname
und -version ab, während die Korrelation die vollständige Package URL verwendet —, sodass die gleichzeitige Aktivierung unterstützt wird,
die dabei entstehenden Zählungen jedoch nicht direkt vergleichbar sind.
