---
title: Ähnliche Befunde
description: Finden Sie verwandte Befunde auf der Seite View Finding und verknüpfen
  Sie sie manuell als Duplikate
audience: pro
weight: 3
---

Während die [Deduplizierung](../about_deduplication) automatisch zum Zeitpunkt des Imports abläuft, sind **Ähnliche Befunde** ein manuelles, interaktives Werkzeug auf der Seite **View Finding**. Es zeigt andere Befunde im selben Asset an, die dem gerade betrachteten Befund ähneln, und ermöglicht es Ihnen, diese manuell zu einem Duplikat-Cluster zu verknüpfen.

Verwenden Sie es, wenn die automatische Deduplizierung Befunde, die Ihrer Ansicht nach zusammengehören, nicht gruppiert hat, oder wenn Sie erkunden möchten, was sonst noch in einem Asset wie die aktuelle Schwachstelle aussieht.

## Wo Sie es finden

Öffnen Sie einen beliebigen Befund und scrollen Sie zur Karte **Duplicate & Similar Findings**. Sie enthält zwei Reiter:

- **Duplicate Findings** – die Befunde, die bereits als Duplikate mit diesem verknüpft sind (der automatische Cluster).
- **Similar Findings** – andere Befunde im Asset, die mit den Werten des aktuellen Befunds übereinstimmen, aber noch nicht Teil seines Clusters sind.

Wählen Sie den Reiter **Similar Findings**, um die Abfrage auszuführen.

![The Duplicate & Similar Findings card on the View Finding page](images/pro_similar_findings.png)

## Wie Befunde zugeordnet werden

DefectDojo durchsucht **dasselbe Asset** nach Befunden, die dem aktuellen ähneln, basierend auf Werten wie Vulnerability IDs (zum Beispiel CVE-Kennungen), CWE, Dateipfad, Zeilennummer und Unique ID From Tool. Der aktuelle Befund wird stets aus seinen eigenen Ergebnissen ausgeschlossen, und die Zuordnung erstreckt sich nie über Assets hinweg.

Dies unterscheidet sich vom automatischen Deduplizierungsalgorithmus, der `hash_code` (oder Unique ID From Tool) vergleicht, um Übereinstimmungen festzustellen. Ähnliche Befunde spannen bewusst ein weiteres Netz, damit Sie verwandte Befunde entdecken können, die ein strikter Hash-Abgleich übersehen würde.

## Mit den Ergebnissen arbeiten

Der Reiter Similar Findings ist eine vollständige Datentabelle mit denselben Bedienelementen, die Sie auch an anderer Stelle in der Pro-Benutzeroberfläche verwenden:

- **Keyword Search** sowie der Filter pro Spalte (Trichter) und die Sortiersteuerung lassen Sie die Liste eingrenzen.
- Das Dropdown **saved views** (**Default**) und das Speichern-Symbol lassen Sie ein Filter-/Spaltenlayout zur Wiederverwendung speichern.
- Die Spalteneinstellungen und Layout-Schaltflächen steuern, welche Spalten angezeigt werden.
- **Export** lädt die aktuellen Ergebnisse herunter, und **Clear Filters** setzt die Tabelle zurück.

Jede Zeile zeigt die ID, den Schweregrad, die Priorität, das Risiko, den Namen, die CWE, die CVSS-Werte, die Vulnerability IDs, die EPSS-Daten, Exploit-Informationen (Known Exploited / Ransomware), den Status, das Asset und mehr des zugeordneten Befunds. Klicken Sie auf einen Befundnamen, um ihn zu öffnen.

## Aktionen

Öffnen Sie das Aktionsmenü (die Schaltfläche **⋮** am Anfang einer Zeile), um den Duplikat-Cluster direkt von dieser Seite aus zu verwalten:

![The Similar Findings row action menu](images/pro_similar_findings_actions.png)

- **Set As Original Finding** – befördert einen Befund zum Original (Cluster-Wurzel).
- **Mark As Duplicate** – verknüpft den ähnlichen Befund mit dem Duplikat-Cluster des aktuellen Befunds.

Diese Aktionen verändern dieselben Duplikat-Beziehungen, die auch die automatische Deduplizierung verwendet, sodass sich ein hier verknüpfter Befund exakt wie ein automatisch erkanntes Duplikat verhält. Jeder Befund, den Sie als Duplikat markieren, erscheint anschließend im Reiter **Duplicate Findings** dieser Karte.

Eine Aktion kann nicht verfügbar sein, wenn sie ungültig ist, zum Beispiel wenn der ähnliche Befund bereits das Original eines anderen Clusters ist, oder wenn eine Verknüpfung eine Engagement-Grenze überschreiten würde, während die Deduplizierung auf Engagement-Ebene aktiviert ist.

## Ähnliche Befunde aktivieren und deaktivieren

Similar Findings wird über die globale Systemeinstellung **Enable Similar Findings** gesteuert, die standardmäßig aktiviert ist. Da die Abfrage ein gesamtes Asset durchsucht, kann sie bei großen Assets aufwendig sein; wenn Sie langsame Ladezeiten auf der Seite **View Finding** bemerken, kann diese Einstellung deaktiviert werden.
