---
title: Threat Modeling
description: Erstellen Sie ein Bedrohungsmodell, Angriffspfade und Sicherheitsanforderungen
  aus einem Feature-Entwurf, noch bevor der Code existiert
draft: false
audience: pro
weight: 4
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Threat Modeling ist eine Funktion, die ausschließlich in DefectDojo Pro verfügbar ist, und befindet sich derzeit in der BETA-Phase.</span>

**Threat Modeling** verwandelt einen Feature-Entwurf in ein geprüftes Bedrohungsmodell. Sie liefern den Entwurf — eingefügten Text, ein Design-Dokument und optional ein Architekturdiagramm —, und DefectDojo ermittelt daraus die beschriebenen Komponenten und Datenflüsse, die Bedrohungen dagegen sowie die Sicherheitsanforderungen, die diese Bedrohungen mindern. Anforderungen können anschließend als Befunde in DefectDojo übernommen werden, sodass Arbeit auf Design-Ebene durch dieselbe Triage-, SLA-, Jira- und Reporting-Maschinerie läuft wie alles andere.

Dies ist die **Pre-Code**-Fähigkeit von Sensei. Während [Scan-and-Fix](/sensei/about_sensei/) mit einem bereits existierenden Repository arbeitet, arbeitet Threat Modeling mit dem Entwurf, noch bevor es Code zum Scannen gibt.

> **🔎 BETA:** Threat Modeling wird aktiv weiterentwickelt und ist in der gesamten Benutzeroberfläche mit **BETA** gekennzeichnet. Verhalten und Bildschirme können sich zwischen Releases ändern. Während der BETA-Phase wird die Funktion pro Instanz von DefectDojo aktiviert — wenden Sie sich an Ihren DefectDojo-Ansprechpartner, um sie freischalten zu lassen.

> **📍 Wo Sie es finden:** Öffnen Sie **Threat Modeling** über die Navigation auf der linken Seite, direkt unterhalb von Sensei.

## Was Sie benötigen

- Die lizenzierte Funktion **Sensei**. Threat Modeling wird unter derselben Berechtigung ausgeliefert wie Scan-and-Fix.
- Eine globale Rolle als **Maintainer** oder **Owner**. Benutzer ohne diese Rolle sehen die Seite nicht.
- Ein Produkt, dem das Bedrohungsmodell zugeordnet wird. Instanzen mit 3.0-Benennung sehen Produkte als **Assets** bezeichnet; diese Seite verwendet durchgehend *Produkt*, und die Benutzeroberfläche folgt der Benennung, auf die Ihre Instanz eingestellt ist.

Es wird nichts installiert und kein Repository verbunden. Threat Modeling liest ausschließlich den von Ihnen bereitgestellten Entwurf.

## Ein Bedrohungsmodell erstellen

Wählen Sie **New threat model**, wählen Sie das Produkt aus, vergeben Sie einen Namen und liefern Sie den Entwurf in der Form, in der er vorliegt:

- **Fügen Sie die Beschreibung** direkt ein, oder
- **Laden Sie ein Design-Dokument hoch** — `.md`, `.markdown`, `.txt`, `.text` oder `.pdf`. Die Textextraktion aus PDF erfolgt nach bestem Bemühen; besteht ein PDF größtenteils aus Bildern, fügen Sie den Text stattdessen direkt ein.
- **Fügen Sie optional ein Architekturdiagramm hinzu** — PNG, JPEG, WebP oder GIF. Das Diagramm wird zusammen mit dem Text ausgewertet, sodass auch eine Komponente erfasst wird, die nur im Bild vorkommt.

Sie können beides kombinieren: Eine kurze eingefügte Zusammenfassung plus ein Diagramm ergibt oft ein besseres Modell als jedes für sich allein.

Die Generierung läuft im Hintergrund und durchläuft vier Phasen, die während des Fortschritts am Lauf angezeigt werden:

1. **Extracting architecture** — Komponenten, Vertrauensgrenzen, Daten-Assets und Datenflüsse.
2. **Enumerating threats** — Bedrohungen je STRIDE-Kategorie.
3. **Writing security requirements** — testbare Anforderungen, jede verknüpft mit den Bedrohungen, die sie mindert.
4. **Assembling results** — das Diagramm und abschließende Konsistenzprüfungen.

Ein Lauf dauert in der Regel mehrere Minuten. Sie können die Seite verlassen; Fortschritt und Ergebnisse bleiben am Lauf erhalten.

## Die Ergebnisse lesen

### Architecture

Der Tab **Architecture** stellt das Extrahierte als Datenflussdiagramm dar: Komponenten gruppiert nach Vertrauensgrenze, mit nach Protokoll beschrifteten Flüssen. Flüsse, die **eine Vertrauensgrenze überschreiten**, werden anders dargestellt, da diese die interessanten sind. Die Auswahl einer Komponente zeigt die Bedrohungen, die auf sie abzielen.

Das Modell hält außerdem fest, was es **nicht** bestimmen konnte — Annahmen, die es treffen musste, und Punkte, die im Entwurf unklar waren. Lesen Sie diese zuerst: Sie zeigen, wo der Entwurf selbst mehrdeutig ist, was oft das nützlichste Ergebnis der Übung ist.

### Bedrohungen

Jede Bedrohung enthält:

- Ihre **STRIDE-Kategorie** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) und einen **Schweregrad**.
- Das **Angreiferprofil** — zum Beispiel ein externer, nicht authentifizierter Angreifer, ein Insider oder eine Supply-Chain-Kompromittierung — sowie das erforderliche Können.
- Einen geordneten **Angriffspfad**: die Schritte, die ein Angreifer unternehmen würde, samt Voraussetzungen.
- Eine **CWE**, sofern zutreffend, entnommen aus einer festen Liste statt frei erfunden.
- Die **Komponenten, Flüsse und Daten-Assets**, auf die sie abzielt.

### Sicherheitsanforderungen

Jede Anforderung ist als testbare Aussage formuliert, mit einem **Verification**-Schritt, der beschreibt, wie ihre Erfüllung bestätigt wird, einer Kategorie (Authentifizierung, Autorisierung, Eingabevalidierung, Kryptografie und so weiter) und einer Priorität. Jede Anforderung nennt die Bedrohungen, die sie mindert.

Die Abdeckung wird explizit ausgewiesen: Eine Bedrohung wird entweder durch mindestens eine Anforderung gemindert oder als **Coverage Gap** aufgeführt. Lücken werden angezeigt statt verborgen, sodass eine Bedrohung nie stillschweigend wegfällt.

## Belege und was Sie ihnen glauben können

Jede Komponente, jede Bedrohung und jede Anforderung trägt den **Beleg**, aus dem sie stammt, und Belege sind nach Quelle gekennzeichnet:

- **Aus dem Entwurfstext** — ein Zitat, das Wort für Wort mit dem von Ihnen gelieferten Text abgeglichen wurde.
- **Aus dem Diagramm** — aus dem Bild ausgelesen, sodass es keinen Text zum Zitieren gibt.
- **Abgeleitet** — im Entwurf überhaupt nicht angegeben.

Ein Zitat, das nicht mit dem gelieferten Text abgeglichen werden konnte, wird beibehalten, aber **als nicht verifiziert markiert**, wobei das angebliche Zitat angezeigt wird, damit Sie selbst urteilen können. Einträge werden markiert statt entfernt, denn eine stillschweigend verworfene Bedrohung ist ein Risiko, von dem niemand erfährt. Strukturell fehlerhafte Einträge — etwa eine Bedrohung, die sich auf eine nie extrahierte Komponente bezieht — werden verworfen, und die Anzahl der verworfenen Einträge wird am Lauf festgehalten.

**Behandeln Sie die Ausgabe als zu prüfenden Entwurf, nicht als fertiges Artefakt.** Sie wird von einem Sprachmodell aus einem Design-Dokument generiert; die Beleg-Kennzeichnungen gibt es, damit Sie erkennen können, welche Teile in dem verankert sind, was Sie geschrieben haben, und welche auf Schlussfolgerung beruhen.

## Anforderungen in Befunde übernehmen

Anforderungen werden über **Push to findings** umsetzbar. Wählen Sie die gewünschten Anforderungen aus, und DefectDojo erstellt pro Anforderung einen Befund in einem eigenen Engagement namens **Sensei Threat Modeling** auf diesem Produkt, mit jeweils einem Test pro Threat-Model-Version.

Jeder Befund enthält:

- Die Anforderungsformulierung sowie die Beschreibung jeder Bedrohung, die sie mindert — STRIDE-Kategorie, Angreifer und den nummerierten Angriffspfad —, sodass wer immer das Ticket übernimmt, den Kontext hat, ohne das Bedrohungsmodell zu öffnen.
- Den Verification-Schritt als Minderungsmaßnahme.
- Den Schweregrad und die CWE der Anforderung.
- Den Tag `sensei-threat-model`, einen `tm-v<version>`-Tag und einen STRIDE-Tag.

Befunde werden **aktiv, aber nicht verifiziert** angelegt: Eine generierte Anforderung ist ein Vorschlag, den ein Mensch bestätigen muss.

Der Push ist **idempotent**. Jede Anforderung besitzt ihren Befund, sodass ein erneuter Push desselben Modells den Befund an Ort und Stelle aktualisiert, statt Duplikate zu erzeugen — und wenn Sie eine Anforderung bearbeiten und erneut pushen, zieht der Befund nach. Ein erneuter Push überschreibt nicht, wer den Befund ursprünglich angelegt hat.

## Versionen und Ablösung

Bedrohungsmodelle werden **pro Produkt versioniert**. Das erneute Generieren aus einem aktualisierten Entwurf erzeugt eine neue Version, statt die alte zu überschreiben, sodass Sie die Historie behalten, wie der Entwurf zum Zeitpunkt einer Entscheidung aussah.

Wenn Sie eine neuere Version pushen, werden Befunde der vorherigen Version, die keiner aktuellen Anforderung mehr entsprechen, auf **Behoben** gesetzt statt offen gelassen, sodass das Engagement den aktuellen Entwurf widerspiegelt.

## Exportieren

Ein Bedrohungsmodell kann als **Markdown** für ein Design-Review oder ein Ticket heruntergeladen werden, oder als **JSON** für alles Programmatische. Beides ist direkt am Bedrohungsmodell verfügbar.

## Generierungsaktivität

Der Tab **Activity** listet jede Generierung mit ihrem Status und der erreichten Phase auf. Laufende Läufe können **abgebrochen** werden. Ein fehlgeschlagener Lauf zeigt, **warum** er fehlgeschlagen ist — ein Konfigurationsproblem, eine zu lange Eingabe oder ein vorübergehender Dienstfehler — und abgeschlossene Phasen werden als Checkpoint gespeichert, sodass ein erneuter Versuch fortsetzt, statt von vorn zu beginnen.

## Kosten

Threat Modeling ruft ein großes Sprachmodell auf, und jede Generierung verursacht Kosten. Eine Generierung führt etwa acht Aufrufe durch, und die Nutzung wird pro Lauf zusammen mit Senseis übriger LLM-Nutzung erfasst, sodass Sie sehen können, was ein Modell in der Erstellung gekostet hat. Das Abbrechen eines Laufs stoppt weitere Aufrufe an der nächsten Phasengrenze.
