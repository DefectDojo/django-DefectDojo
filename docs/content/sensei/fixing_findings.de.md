---
title: Befunde mit Sensei beheben
description: Scannen, Auto-Fix-Kandidaten triagieren und Fix-Pull-Requests öffnen
draft: false
audience: pro
weight: 3
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Sensei ist eine reine DefectDojo-Pro-Funktion und befindet sich derzeit in der BETA-Phase.</span>

Sobald ein Repository angebunden ist, erscheint Sensei direkt bei Ihren Befunden und im Sensei-Hub. Diese Seite behandelt das Scannen eines Repositorys, das Triagieren von Auto-Fix-Kandidaten und das Beheben einzelner Befunde. Sie benötigen mindestens **Writer**-Zugriff auf das Produkt eines Befunds, um einen Fix auszulösen.

## Ein Repository scannen

Scans importieren Befunde in ein Engagement, das nach dem Branch benannt ist. Sie können einen Scan bei Bedarf über den Sensei-Hub auslösen: Öffnen Sie die Zeilenaktionen eines Repositorys und wählen Sie **Jetzt scannen**.

![Dialog „Mit Sensei scannen“](images/scan_dialog.png)

Wählen Sie den zu scannenden Branch aus (standardmäßig der Standard-Branch des Repositorys) und wählen Sie **Scan starten**. Im DefectDojo-gehosteten Modus laufen Scans außerdem automatisch, wenn ein Pull Request geöffnet wird.

## Die Sensei-Spalte bei Befunden

Angebundene Repositorys fügen der Befundtabelle eine **Sensei**-Spalte hinzu. Jeder Befund zeigt eine Schaltfläche **Fix** (oder seinen aktuellen Fix-Status), sodass Sie beheben können, ohne Ihre Triage-Ansicht zu verlassen.

![Sensei-Spalte in der Befundtabelle](images/findings_sensei_column.png)

Die Schaltfläche hat zwei Zustände:

- **Fix:** Das Produkt des Befunds ist an Sensei angebunden. Ein Klick startet eine Behebung.
- **Produkt konfigurieren:** Das Produkt des Befunds ist noch **nicht** angebunden. Ein Klick führt Sie zu Sensei, um ein Repository für dieses Produkt anzubinden; sobald es angebunden ist, wird aus der Schaltfläche **Fix**.

## Einen einzelnen Befund beheben

Ein Klick auf **Fix** (in der Befundtabelle oder im Detail-Header eines Befunds) öffnet den Dialog **Mit Sensei beheben**. Wählen Sie den Basis-Branch, auf den der Fix-Pull-Request abzielen soll, und klicken Sie dann auf **Fix**.

![Dialog „Mit Sensei beheben“](images/fix_with_sensei_dialog.png)

Sensei erstellt eine Behebung und öffnet einen Pull Request. Der Fix-Status des Befunds wird als Badge angezeigt, das die Stufen *in progress* → *PR open* (oder *failed*) durchläuft. Sobald der Pull Request geöffnet ist, verlinkt das Badge direkt darauf.

![Befunddetails mit Fix-Status-Badge](images/finding_detail_fix.png)

> **💡 Ein Fix, ein PR:** Jeder genehmigte Fix verbraucht einen Fix aus Ihrem Kontingent und öffnet einen Pull Request. Überprüfen und mergen Sie den PR in GitHub wie jeden anderen.

## Triage von Auto-Fix-Kandidaten

Wenn bei einem Repository automatisierte Fixes aktiviert sind, stellt jeder Scan passende Befunde als **Kandidaten** auf dem Tab **Auto-fix Candidates** des Sensei-Hubs bereit. Das ist Senseis Preview-first-Modell: Befunde werden bereitgestellt, aber **es läuft nichts (keine LLM-Kosten), bis Sie genehmigen**. Das Genehmigen öffnet Fix-Pull-Requests und verbraucht Fixes.

![Triage von Auto-Fix-Kandidaten](images/auto_fix_candidates.png)

Jeder Kandidat zeigt den Befund, seinen Status, Schweregrad, Risiko, Priorität, das Ziel-Repository und den PR-Branch. So beheben Sie ihn:

- **Einen genehmigen:** Klicken Sie in einer Zeile auf **Genehmigen**, um die Branch-Auswahl zu öffnen und diesen Fix zu starten.
- **Mehrere genehmigen:** Wählen Sie mehrere Zeilen aus und nutzen Sie die Sammel-Genehmigungsaktion.

Genehmigte Befunde bleiben als **In Bearbeitung** (oder **Fehlgeschlagen**) gelistet, bis ihr Pull Request angehängt ist, sodass ein laufender oder fehlgeschlagener Fix nie verschwindet, bevor er einen PR erzeugt.

> **🔎 Automatische Behebung:** Wenn Sie *Kandidaten automatisch beheben* für das Repository aktiviert haben, öffnet eine Hintergrundprüfung automatisch Fix-PRs für bereitgestellte Kandidaten, bis zu Ihrem Fix-Kontingent, ohne manuelle Genehmigung.

## Scans und Auswirkungen nachverfolgen

Zwei Bereiche im Sensei-Hub helfen Ihnen zu verfolgen, was Sensei getan hat:

- **Scan Activity:** ein Protokoll jedes Scan- und Fix-Laufs mit seinem Modus (Branch Scan, PR Scan, Fix (Finding)), Auslöser (Manual, Webhook, Auto Remediated), Status, Ausführungszeit und Links zum Engagement oder dem erzeugten Pull Request.

  ![Scan Activity-Protokoll](images/scan_activity.png)

- **Fix Impact:** eine Zusammenfassung der angewendeten Fixes, mit den am häufigsten reparierten Assets, oben im Hub.

  ![Fix Impact-Panel](images/fix_impact.png)

Verwenden Sie die Zeilenaktionen **Jetzt scannen**, **Scan-Verlauf**, **Konfigurieren** und **Kandidaten neu bereitstellen**, um jedes angebundene Repository im Zeitverlauf zu verwalten (siehe [Referenz](/sensei/sensei_reference/#repository-row-actions)).
