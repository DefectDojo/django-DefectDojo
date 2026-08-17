---
title: Ähnliche Befunde
description: Verwandte Befunde auf der View-Finding-Seite finden und manuell als Duplikate
  verknüpfen
audience: opensource
weight: 3
---

Während die [Deduplizierung](../about_deduplication) automatisch zum Importzeitpunkt ausgeführt wird, ist **Similar Findings** ein manuelles, interaktives Tool auf der Seite **View Finding**. Es zeigt andere Befunde im selben Asset an, die dem gerade betrachteten ähneln, und ermöglicht es Ihnen, diese manuell zu einem Duplikat-Cluster zu verknüpfen.

Verwenden Sie es, wenn die automatische Deduplizierung Befunde, die Ihrer Meinung nach zusammengehören, nicht gruppiert hat, oder wenn Sie erkunden möchten, was sonst noch in einem Asset wie die aktuelle Schwachstelle aussieht.

## Wo Sie es finden

Öffnen Sie einen beliebigen Befund, um zu seiner View-Finding-Seite zu gelangen. Scrollen Sie nach unten zum Panel **Similar Findings**. Die Zahl in der Überschrift gibt die Anzahl der Befunde im Asset an, die mit den Werten des aktuellen Befunds übereinstimmen.

![The Similar Findings panel heading on the View Finding page](images/similar_findings_panel.png)

Das Panel ist standardmäßig eingeklappt. Klicken Sie auf die Panel-Überschrift (oder auf den Pfeil-/Filter-Button rechts), um es aufzuklappen und die Abfrage auszuführen.

## Wie Befunde abgeglichen werden

Wenn Sie das Panel öffnen, füllt DefectDojo einen Filter automatisch mit den Werten des aktuellen Befunds vor und durchsucht **dasselbe Asset** nach anderen passenden Befunden. Die Felder, die für den anfänglichen Abgleich verwendet werden, sind:

- Vulnerability IDs (zum Beispiel CVE-Kennungen)
- CWE
- Dateipfad
- Zeilennummer
- Unique ID from tool
- Testtyp
- Asset (und Asset-Typ)

Der aktuelle Befund wird immer von seinen eigenen Ergebnissen ausgeschlossen. Der Abgleich ist auf das Asset beschränkt, sodass Similar Findings nie Asset-übergreifend arbeitet. Wenn bei einem der beiden Engagements die Deduplizierung auf Engagement-Ebene aktiviert ist, können Übereinstimmungen, die eine Engagement-Grenze überschreiten, nicht verknüpft werden (siehe [Actions](#actions) weiter unten).

Dies unterscheidet sich vom automatischen Deduplizierungsalgorithmus, der `hash_code` (oder Unique ID from tool) vergleicht, um Übereinstimmungen zu bestimmen. Similar Findings wirft bewusst ein weiteres Netz aus, damit Sie verwandte Befunde entdecken können, die ein strikter Hash-Abgleich übersehen würde.

## Den Abgleich verfeinern

Die vorausgefüllten Werte sind nur ein Ausgangspunkt. Über das Filter-Panel am Anfang des Abschnitts können Sie den Abgleich strenger oder lockerer gestalten: Entfernen Sie ein Feld, um die Ergebnisse zu erweitern, oder fügen Sie Kriterien hinzu (Severity, Status, Endpunkt, Datumsangaben, EPSS und mehr), um sie einzugrenzen.

![The Similar Findings filter panel](images/similar_findings_filters.png)

- **Clear filters** leert alle Felder, sodass Sie eine Abfrage von Grund auf neu erstellen können.
- **Restart** kehrt zum Standardabgleich basierend auf den Werten des aktuellen Befunds zurück.

## Die Ergebnisse lesen

Jeder passende Befund wird in einer Tabelle aufgeführt. Die Spalte **Relationship** gibt an, wie dieser Befund mit dem gerade angezeigten Befund zusammenhängt:

- **Original** – der Wurzel-/Original-Befund des Duplikat-Clusters des aktuellen Befunds
- **Duplicate** – ein Befund, der bereits als Duplikat des aktuellen Befunds markiert ist
- **Similar** – eine Übereinstimmung, die noch nicht Teil des Clusters des aktuellen Befunds ist

![The Similar Findings results table](images/similar_findings_list.png)

Die Tabelle zeigt außerdem Severity, Titel, Datum, Status, Test, Engagement, CWE, Vulnerability Id, EPSS-Score, Datei (mit Zeilennummer) und JIRA (wenn die JIRA-Integration aktiviert ist). Jede Spalte ist sortierbar, und die Ergebnisse können exportiert werden (Copy, Excel, CSV, PDF).

## Actions

Wenn Sie über die Bearbeitungsberechtigung für einen Befund verfügen, bietet die Spalte **Action** ein Dropdown-Menü, mit dem Sie den Duplikat-Cluster direkt von dieser Seite aus verwalten können:

![The Similar Findings row action menu](images/similar_findings_actions.png)

- **Mark as duplicate** – verknüpft den ähnlichen Befund mit dem Duplikat-Cluster des aktuellen Befunds.
- **Set as original** – befördert einen Befund zum Original (Cluster-Wurzel).
- **Reset finding duplicate status** – entfernt einen Befund aus seinem Cluster.

Eine Aktion kann nicht verfügbar sein (angezeigt als **None**), wenn sie ungültig ist, zum Beispiel wenn sich der ähnliche Befund in einem anderen Engagement befindet und die Deduplizierung auf Engagement-Ebene aktiviert ist, oder wenn er bereits das Original eines anderen Clusters ist. Diese Aktionen verändern dieselben Duplikat-Beziehungen, die auch die automatische Deduplizierung verwendet, sodass sich ein hier markierter Befund genau wie ein automatisch erkanntes Duplikat verhält.

## Similar Findings aktivieren und deaktivieren

Similar Findings wird über eine globale Systemeinstellung gesteuert. Gehen Sie zu **Configuration > System Settings** und aktivieren/deaktivieren Sie **Enable Similar Findings**. Standardmäßig ist die Funktion aktiviert.

![The Enable Similar Findings system setting](images/similar_findings_enable_setting.png)

Da die Abfrage ein gesamtes Asset durchsucht, kann sie bei großen Assets aufwendig sein. Wenn Sie bemerken, dass die View-Finding-Seiten langsam laden, können Sie die Funktion hier deaktivieren oder die Anzahl der zurückgegebenen Ergebnisse über die Umgebungsvariable `DD_SIMILAR_FINDINGS_MAX_RESULTS` begrenzen (Standard `25`).
