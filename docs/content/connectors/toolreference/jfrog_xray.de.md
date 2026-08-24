---
title: "JFrog Xray"
description: "Einrichtung des JFrog Xray Upstream-Connectors für DefectDojo"
weight: 81
audience: pro
---
Der JFrog-Xray-Connector verwendet die JFrog-Xray-REST-API, um Schwachstellendaten aus Ihren Artifactory-Repositories abzurufen. DefectDojo ermittelt alle Repositories in Ihrer JFrog-Instanz und erzeugt über Xray Schwachstellenberichte, wobei Befunde geplant importiert werden.

#### Voraussetzungen

Sie benötigen ein API-Token mit Zugriff auf sowohl die Artifactory- als auch die Xray-API. Wir empfehlen, für DefectDojo ein dediziertes Service-Konto anzulegen. Das Konto benötigt:

* Lesezugriff auf Artifactory-Repositories
* Berechtigung, Xray-Schwachstellenberichte zu erzeugen und anzuzeigen (Berechtigung `Apply on Watches` in Xray oder gleichwertig)

#### Connector-Zuordnungen

1. Geben Sie die Basis-URL Ihrer JFrog-Instanz in das Feld **Location** ein. Dies sollte die Root-URL Ihrer JFrog-Instanz sein, zum Beispiel `https://your-instance.jfrog.io`. Geben Sie keinen abschließenden Pfad an — DefectDojo erstellt die passenden API-Pfade automatisch.
2. Geben Sie ein gültiges **Reference Token** in das Feld **Secret** ein. Tokens können unter **User Management \> Access Tokens** in der JFrog-Platform-Oberfläche generiert werden.
Sie müssen ein **Reference Token** generieren und diesen Wert verwenden.

Erforderliche Token-Scopes für JFrog Xray:

- **All Services**, da DefectDojo Zugriff sowohl auf den XRay- als auch auf den Artifactory-Dienst benötigt
- Mindestens **Manage Reports + Manage Resources**.

Standardmäßig ordnet DefectDojo jedes Artifactory-**Repository** als separaten Eintrag zu. Jeder Sync erzeugt über Xray einen vollständigen Schwachstellenbericht pro Repository, sodass die Befundstatus in DefectDojo stets den aktuellen Zustand des Repositorys widerspiegeln.

#### Repository-Filter (optional)

Standardmäßig ermittelt der Connector **jedes** Repository in Ihrer JFrog-Instanz. Bei Instanzen mit einer großen Anzahl von Repositories — von denen viele für die Sicherheitsprüfung möglicherweise nicht relevant sind — kann die Ermittlung mit dem optionalen Feld **Repository Filter** unter **Import Filters** im Connector-Formular eingegrenzt werden.

Der Filter wird während der Ermittlung angewendet, **bevor irgendeine Arbeit pro Repository erfolgt**. Ein Repository außerhalb des Filters verursacht keine Kosten: Für dieses wird kein Xray-Bericht erzeugt, und im Artefakt-Modus werden keine seiner Artefakte der ersten Ebene aufgelistet. Dies macht ihn zur effektivsten Methode, um sowohl die Sync-Zeit als auch die Last zu reduzieren, die DefectDojo auf Ihre JFrog-Instanz legt — mehr als jede später im Sync angewendete Einstellung. Er wird insbesondere in Kombination mit **Artifact-Level Records** bei großen Instanzen empfohlen.

**Syntax:** eine kommagetrennte Liste von Repository-Schlüsseln. Jeder Eintrag kann `*`-Platzhalter verwenden:

* Ein Eintrag, der `*` enthält, wird als Muster abgeglichen — `releases-*` erfasst jeden Repository-Schlüssel, der mit `releases-` beginnt, und `*docker-pr-local*` erfasst jeden Schlüssel, der `docker-pr-local` enthält. Ein `*` erfasst eine beliebige Zeichenfolge, auch `/`.
* Ein Eintrag ohne `*` muss einem Repository-Schlüssel **exakt** entsprechen.
* Ein Repository wird ermittelt, wenn es auf **einen beliebigen** Eintrag der Liste passt. Leerzeichen um Kommas werden ignoriert.

```
releases-*, snapshots
```

Das obige Beispiel ermittelt jedes Repository, dessen Schlüssel mit `releases-` beginnt, sowie das einzelne Repository mit dem exakten Namen `snapshots`.

Hinweise:

* Der Filter ist eine **Allow-Liste** — eine Übereinstimmung wählt ein Repository aus. Es gibt keine Ausschluss- oder Negationssyntax, sodass sich „alles außer X" nicht direkt ausdrücken lässt.
* Der Abgleich erfolgt **groß-/kleinschreibungssensitiv**, sowohl bei exakten Einträgen als auch bei Platzhaltern. `*` ist das einzige Platzhalterzeichen; `?` und Zeichenbereiche werden nicht unterstützt.
* **Leer lassen, um jedes Repository zu ermitteln.** Ein Wert, der nur aus Leerzeichen oder Kommas besteht, wird als leer behandelt.
* Ein Filter, der auf nichts passt, ermittelt einfach nichts — es gibt keine Fehlermeldung. Findet ein Sync unerwartet keine Repositories, prüfen Sie im Connector-Log den Eintrag `repository filter scoped discovery`, der meldet, wie viele der insgesamt vorhandenen Repositories getroffen wurden.
* Das Feld kann nach dem Erstellen der Verbindung geändert werden.

**Den Filter später ändern:** Repositories, die ein neu eingeengter Filter jetzt ausschließt, werden nicht mehr ermittelt, und ihre bestehenden Einträge durchlaufen den normalen Lebenszyklus für Produkte, die das Tool nicht mehr meldet — **zugeordnete** Einträge werden beim nächsten Sync als `MISSING` markiert, und nicht zugeordnete `NEW`-Einträge werden entfernt. Bereits in DefectDojo importierte Befunde werden nicht gelöscht; der Filter steuert nur die Ermittlung.

#### Artifact-Level Records

Der Schalter **Artifact-Level Records** ändert die Ermittlung auf eine Ebene unterhalb des Repositorys: Jeder Eintrag der ersten Ebene unter einer Repository-Root (bei Docker-Repositories jedes Image; bei generischen Repositories jede Datei oder jeder Ordner der obersten Ebene) wird zu einem eigenen Eintrag. Jeder Sync erzeugt weiterhin einen einzigen Xray-Bericht pro Repository — DefectDojo ordnet jede Schwachstelle den Artefakten zu, die sie betrifft, sodass sich die Last auf Ihre JFrog-Instanz nicht erhöht.

> **Prüfen Sie vor Ihrem ersten Sync, in welchem Modus Sie sich befinden.** Artifact-Level Records ist bei **Neuinstallationen standardmäßig aktiviert**. Installationen von vor Einführung dieser Funktion behalten ihr bestehendes Repository-Level-Layout bei, sodass der Schalter dort deaktiviert bleibt, bis ihn jemand einschaltet. In beiden Fällen kann der Schalter jederzeit geändert werden — siehe *Eine bestehende Verbindung umstellen* unten.

Bei aktiviertem Artifact-Level Records:

* Repositories bleiben als Einträge bestehen und werden zu **übergeordneten Assets**: Sie tragen selbst keine Befunde, aber wenn die Asset-Hierarchie-Funktion aktiviert ist, verknüpft DefectDojo jedes Artefakt-Asset automatisch mit einer `parent`-Beziehung mit seinem Repository-Asset. Assets können dann nach Parent/Child gefiltert werden, und Befunde werden in der Hierarchie nach oben aggregiert.
* Eine Schwachstelle, die mehrere Artefakte betrifft, wird in das Asset jedes betroffenen Artefakts importiert, sodass jedes Asset die vollständige Menge der es betreffenden Befunde zeigt.
* Befunde beziehen sich auf den **neuesten Build** jedes Artefakts, sodass die Befunde eines Artefakts dessen aktuellen Build beschreiben, statt Ergebnisse aus jedem von Xray je gescannten Build anzusammeln.
* Von diesem Connector erzeugte Hierarchiebeziehungen überschreiben nie von Ihnen manuell erstellte Beziehungen. Hat ein Asset bereits einen von Ihnen zugewiesenen Parent, lässt der Connector ihn unangetastet.
* Das Token benötigt zusätzlich Lesezugriff auf die Artifactory-Storage-API (in den obigen Scopes enthalten).

**Eine bestehende Verbindung auf Artifact-Level Records umstellen:** Der Schalter kann jederzeit geändert werden. Beim ersten Sync danach erscheinen neue Artefakt-Einträge zur Zuordnung — aktivieren Sie **Auto Map** für die Verbindung beim Umschalten, damit Befunde ohne Lücke übertragen werden. Die Repository-Level-Assets erhalten keine Befunde mehr, und ihre zuvor importierten Befunde werden beim nächsten Sync geschlossen (dieselben Befunde werden mit neuem Status unter den neuen Artefakt-Assets erneut importiert); Notizen und Historie zu den alten Repository-Level-Befunden bleiben am Repository-Asset erhalten. Ein Zurückschalten kehrt dies um: Repository-Einträge tragen wieder Befunde (zuvor geschlossene Befunde werden bei erneuter Übereinstimmung wieder geöffnet), und Artefakt-Einträge werden als MISSING markiert — ihre Assets und Befunde bleiben erhalten, erhalten aber keine Updates mehr, sodass Sie sie nach Belieben archivieren können.

Weitere Informationen finden Sie in der [JFrog-Xray-REST-API-Dokumentation](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis).
