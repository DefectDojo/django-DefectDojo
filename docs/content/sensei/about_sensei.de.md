---
title: Über Sensei
description: Was Sensei ist und wie das DefectDojo-gehostete Scan-and-Fix funktioniert
draft: false
audience: pro
weight: 1
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Sensei ist eine reine DefectDojo-Pro-Funktion und befindet sich derzeit in der BETA-Phase.</span>

**Sensei** ist die KI-gestützte **Scan-and-Fix**-Funktion von DefectDojo für Quellcode-Repositorys. Verbinden Sie ein Repository (über eine **GitHub App**, **GitLab**, **Bitbucket** oder **Azure DevOps**), und Sensei scannt es, importiert die Ergebnisse als DefectDojo-Befunde und nutzt anschließend ein großes Sprachmodell, um **diese Befunde durch das Öffnen von Pull-/Merge-Requests zu beheben** – alles, ohne DefectDojo zu verlassen.

> **🔀 Mehrere Anbieter:** Sensei unterstützt **GitHub** (github.com und GitHub Enterprise Server), **GitLab** (gitlab.com und selbstgehostet), **Bitbucket** (Cloud und Server/Data Center) sowie **Azure DevOps**, alle mit demselben Scan-and-Fix-Ablauf. Wo in diesem Leitfaden von einem *Pull Request* die Rede ist, verwendet GitLab einen **Merge Request**; die *Statusprüfung* des PR wird als GitLab/Azure-**Commit-Status** oder als Bitbucket-**Build-Status** gemeldet. Die Verbindung unterscheidet sich je nach Anbieter (siehe [Sensei einrichten](/sensei/setup_sensei/)); alles nach dem Onboarding ist identisch.

- **Scan-and-Fix an einem Ort:** Repositorys werden über die Sensei-Seite und über Ihre Befunde gescannt und behoben, unter Verwendung derselben normalisierten, deduplizierten Befunddaten wie im Rest von DefectDojo.
- **Preview-first:** Sensei stellt Fix-*Kandidaten* zur Überprüfung bereit. Es wird nichts an ein LLM gesendet und kein Pull Request geöffnet, bevor Sie zustimmen – so entstehen keine überraschenden Kosten oder unerwarteten PRs.
- **Kurzlebige Zugangsdaten:** Sensei läuft vollständig über eine GitHub App und verwendet kurzlebige Installationstokens. Es gibt nichts einzufügen und nichts zu rotieren.
- **Gemessen und lizenzbeschränkt:** Sensei ist eine Pro-Funktion mit instanzweiten Kontingenten für Fixes und angebundene Repositorys.

> **🧠 Bevor der Code existiert:** Sensei erstellt außerdem ein Bedrohungsmodell, Angriffspfade und Sicherheitsanforderungen aus einem Feature-*Design*, ganz ohne Repository — siehe [Bedrohungsmodellierung](/sensei/threat_modeling/).

> **🔎 BETA:** Sensei befindet sich in aktiver Entwicklung und ist in der gesamten Benutzeroberfläche als **BETA** gekennzeichnet. Verhalten und Bildschirme können sich zwischen den Releases ändern.

> **📍 Wo Sie es finden:** Öffnen Sie **Sensei** über die linke Navigation.

![Sensei-Hub](images/hub_overview.png)

## Wie das DefectDojo-gehostete Scannen funktioniert

DefectDojo-gehostetes Scannen ist die empfohlene Art, Sensei zu betreiben. Scans laufen **innerhalb von DefectDojo** und es wird nichts zu Ihrem Repository hinzugefügt:

1. **Verbinden Sie eine GitHub App** und installieren Sie sie in der Organisation (oder dem Konto), der Ihre Repositorys gehören.
2. **Binden Sie ein Repository an** für gehostetes Scannen und legen Sie fest, wie Befunde gemeldet und (optional) automatisch behoben werden.
3. **Sensei scannt das Repository** (auf Anfrage oder automatisch beim Öffnen eines Pull Requests) und importiert die Ergebnisse in ein Engagement, das nach dem Branch benannt ist.
4. **Sensei behebt Befunde**, indem es einen Fix erstellt und einen Pull Request gegen den Standard-Branch des Repositorys öffnet.

Jedes angebundene Repository ist mit einem DefectDojo-**Asset** (Produkt) verknüpft, sodass seine Befunde, Engagements und Fixes zusammen mit dem Rest Ihrer Daten vorliegen.

## Die drei Wege, wie ein Fix gestartet wird

Sensei kann einen Befund auf drei Arten beheben:

- **Die Schaltfläche „Fix“ bei einem Befund:** Lösen Sie direkt aus der Befundtabelle oder der Detailseite eines Befunds einen einmaligen Fix aus. Siehe [Befunde mit Sensei beheben](/sensei/fixing_findings/).
- **Auto-Fix-Kandidaten:** Nach jedem Scan stellt Sensei die Befunde, die Ihren Kriterien entsprechen, als Kandidaten bereit. Sie überprüfen diese und genehmigen die zu behebenden (oder lassen Sensei sie automatisch beheben). Siehe [Auto-Fix-Kandidaten](/sensei/fixing_findings/#auto-fix-candidate-triage).
- **Ein `/fix`-Kommentar an einem Pull Request:** Kommentieren Sie `/fix` an einem Pull Request, und Sensei überträgt eine Behebung an diesen PR.

## Voraussetzungen

- Eine **DefectDojo-Pro**-Lizenz, die die Funktion **Sensei** enthält.
- Ein verbundener Versionsverwaltungs-Anbieter (siehe [Sensei einrichten](/sensei/setup_sensei/)): eine **GitHub App** (github.com oder Enterprise Server), ein **GitLab**-Projekt-/Gruppen-Zugriffstoken (gitlab.com oder selbstgehostet), eine **Bitbucket**-Verbindung (Cloud oder Server/Data Center — OAuth, API-Token oder Zugriffstoken) oder ein **Azure DevOps** Personal Access Token.
- Um Sensei zu **konfigurieren** (Apps verbinden, Repositorys anbinden): eine globale Rolle **Maintainer** oder **Owner**.
- Um einen **Fix auszulösen** bei einem Befund: mindestens **Writer**-Zugriff auf das Produkt dieses Befunds.

## Kontingente

Sensei wird gegen Ihre Lizenz abgerechnet. Der Sensei-Hub zeigt oben auf der Seite zwei Nutzungsanzeigen:

- **Fixes:** die Anzahl der angewendeten Behebungen gegenüber Ihrem vorausbezahlten Limit. Das Genehmigen eines Kandidaten oder das Auslösen eines Fixes verbraucht dieses Kontingent.
- **Onboarded Repositories:** die Anzahl der angebundenen Repositorys gegenüber Ihrem Repository-Limit.

Wenn ein Kontingent erreicht ist, blockiert Sensei weitere Fixes (oder das Onboarding), bis es erhöht wird. Details finden Sie in der [Referenz](/sensei/sensei_reference/#quotas-and-metering).
