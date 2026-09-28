---
title: Sensei-Referenz
description: Status, Zeilenaktionen, Kontingente und Fehlerbehebung
draft: false
audience: pro
weight: 5
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Sensei ist eine reine DefectDojo-Pro-Funktion und befindet sich derzeit in der BETA-Phase.</span>

Eine kurze Referenz für die Status, Aktionen und Limits, denen Sie bei der Nutzung von Sensei begegnen.

## Repository-Status

Der Status, der für ein angebundenes Repository im Sensei-Hub angezeigt wird:

| Status | Bedeutung |
|--------|---------|
| **Aktiv** | Angebunden und bereit zum Scannen. |
| **Pull Request offen** | Sensei hat einen offenen Pull Request für das Repository. |
| **Pull Request geschlossen** | Ein Sensei-Pull-Request wurde geschlossen. |
| **Fehler** | Der letzte Vorgang ist fehlgeschlagen: Prüfen Sie Scan Activity auf die Ursache. |
| **Nicht konfiguriert** | Das Repository ist verbunden, aber noch nicht konfiguriert. |

## Kandidaten- und Fix-Status

Auto-Fix-Kandidaten und Fix-Datensätze durchlaufen folgende Zustände:

| Status | Bedeutung |
|--------|---------|
| **Kandidat** | Durch die Auto-Fix-Kriterien eines Scans bereitgestellt. Es läuft nichts, bis Sie genehmigen. |
| **In Bearbeitung** | Genehmigt: Sensei erstellt den Fix und wird einen Pull Request öffnen. |
| **PR offen** | Ein Fix-Pull-Request ist offen; das Badge verlinkt darauf. |
| **Fehlgeschlagen** | Der Fix konnte nicht abgeschlossen werden; er bleibt gelistet, damit er nicht stillschweigend verschwindet. |

## Repository-Zeilenaktionen

Jedes angebundene Repository verfügt im Sensei-Hub über ein Zeilenaktionsmenü:

![Repository-Zeilenaktionen](images/repo_row_menu.png)

- **Jetzt scannen:** startet einen Scan auf Anfrage (öffnet die Branch-Auswahl).
- **Scan-Verlauf:** zeigt die früheren Scans dieses Repositorys an.
- **Konfigurieren:** öffnet das Konfigurationsformular erneut (PR-Reporting, automatisierte Fixes, Produktverknüpfung).
- **Kandidaten neu bereitstellen:** bewertet die Befunde des Repositorys erneut anhand der Auto-Fix-Kriterien und stellt neue Kandidaten bereit.
- **Löschen:** entfernt das Repository aus Sensei. Dadurch wird das Scannen beendet; das zugrunde liegende Asset oder die Befunde werden nicht gelöscht.

## Kontingente und Messung

Sensei wird gegen Ihre DefectDojo-Pro-Lizenz gemessen, dargestellt als Anzeigen oben im Hub:

- **Fixes:** angewendete Behebungen gegenüber Ihrem vorausbezahlten Limit. Das Genehmigen eines Kandidaten oder das Auslösen eines Fixes verbraucht dieses Kontingent; ist es aufgebraucht, werden weitere Fixes blockiert (ein Warnbanner erscheint), bis das Limit erhöht wird.
- **Onboarded Repositories:** angebundene Repositorys gegenüber Ihrem Repository-Limit. Ist es erreicht, wird das Anbinden neuer Repositorys blockiert.

Um ein Limit zu erhöhen, wenden Sie sich an Ihr DefectDojo-Account-Team.

## GitLab-Spezifika

GitLab wird neben GitHub unterstützt (gitlab.com und selbstgehostet). Das Scan-and-Fix-Verhalten ist identisch; dies sind die GitLab-spezifischen Details:

- **Verbindung:** ein **Projekt- oder Gruppen-Zugriffstoken** (Rolle **Developer**, oder **Maintainer**, falls Push-Regeln dies erfordern) mit den Scopes **`api`** und **`write_repository`**, keine GitHub App. Siehe [Sensei einrichten](/sensei/setup_sensei/#connect-gitlab).
- **Webhook:** jedes angebundene Projekt benötigt einen Webhook an `…/sensei/gitlab/webhooks` (mit dem Secret der Verbindung), abonniert für die Ereignisse **Push**, **Merge request** und **Comment**. Das Hinzufügen eines Webhooks erfordert **Maintainer**/**Owner** im Projekt.
- **Merge Requests statt Pull Requests:** Fixes öffnen einen **Merge Request** gegen den Standard-Branch; der `/fix`-Kommentar funktioniert bei Merge-Request-Notizen.
- **Commit-Status-Gate:** Die PR-Statusprüfung ist ein GitLab-**Commit-Status** am Head-Commit des Merge Requests: `running` während des Scannens, dann `success` oder `failed` (fail-on-new). GitLab kennt keinen *neutralen* Zustand, daher zeigt ein **nicht blockierender** Scan, der dennoch Befunde aufweist, einen **grünen** Status; die Zusammenfassungsnotiz enthält die Befunddetails.
- **Selbstgehostet:** Richten Sie die **GitLab-Basis-URL** auf Ihre Instanz; DefectDojo klont und ruft die API gegen diesen Host auf.

## Bitbucket-Spezifika

Bitbucket **Cloud** und **Server/Data Center** werden unterstützt. Das Scan-and-Fix-Verhalten ist identisch; dies sind die Bitbucket-spezifischen Details:

- **Verbindung:** **OAuth** (empfohlen), ein Atlassian-**API-Token** (verwendet mit Ihrer Konto-E-Mail-Adresse) oder ein Repository-/Workspace-**Zugriffstoken**. Siehe [Sensei einrichten](/sensei/setup_sensei/#connect-bitbucket). App-Passwörter sind veraltet und werden nicht unterstützt.
- **Workspace-Bindung (Cloud):** API-/Zugriffstoken sind an einen Workspace gebunden, daher ist für Cloud ein **Workspace** erforderlich; OAuth arbeitet im Benutzerkontext und ermittelt zugängliche Workspaces automatisch.
- **Webhook:** jedes angebundene Repository benötigt einen Webhook an `…/sensei/bitbucket/webhooks` (mit dem Secret der Verbindung, verifiziert über HMAC-SHA256 `X-Hub-Signature`), abonniert für die Ereignisse **Push**, **Pull request** (created/updated/merged/declined) und **Pull request comment**.
- **Build-Status-Gate:** Die PR-Statusprüfung wird als Bitbucket-**Build-Status** am Head-Commit gemeldet (`INPROGRESS` → `SUCCESSFUL`/`FAILED`). Bitbucket kennt keinen *neutralen* Zustand, daher wird ein nicht blockierender Scan auf `SUCCESSFUL` abgebildet und der Zusammenfassungskommentar enthält die Details. Der Build-Status-Link muss eine öffentliche URL sein, daher wird Ihr DefectDojo-Host verwendet.
- **Repository-Namen:** `workspace/repo` (Cloud) oder `PROJECTKEY/repo` (Server/Data Center).
- **Server/Data Center:** Setzen Sie die **Basis-URL** auf Ihren Host; DefectDojo verwendet die v1.0-REST-API und `/scm/…`-Git-Pfade.

## Azure-DevOps-Spezifika

Azure DevOps Repos werden über ein **Personal Access Token** unterstützt. Das Scan-and-Fix-Verhalten ist identisch; dies sind die Azure-spezifischen Details:

- **Verbindung:** ein **PAT** mit dem Scope **Code (Read, Write, & Manage)**, plus die **Organisation**. Azure DevOps OAuth-Apps werden eingestellt, daher ist ein PAT die empfohlene Zugangsdaten-Art. Siehe [Sensei einrichten](/sensei/setup_sensei/#connect-azure-devops).
- **Webhook:** Azure **Service Hooks** authentifizieren sich mit HTTP **Basic** (kein HMAC) und verwenden **ein Abonnement pro Ereignis**. Erstellen Sie Abonnements für `…/sensei/azure/webhooks` für **Code pushed** und **Pull request created/updated/merged**, mit dem Basic-Benutzernamen/-Passwort der Verbindung.
- **Commit-Status-Gate:** Die PR-Statusprüfung wird als Git-**Commit-Status** am Head-Commit gemeldet.
- **Repository-Namen:** `project/repo` (die Organisation wird in der Verbindung gespeichert).
- **Azure DevOps Server:** Setzen Sie die **Basis-URL** auf Ihre On-Prem-Collection-URL.

## GitHub-Enterprise-Server-Spezifika

GitHub Enterprise Server verwendet dasselbe **GitHub-App**-Modell wie github.com; nur der Host unterscheidet sich:

- **Verbindung:** Da der App-Manifest-Auto-Create-Ablauf nur für github.com verfügbar ist, erstellen Sie die App **manuell** auf Ihrem GHES-Host und geben Sie deren Zugangsdaten sowie den **Enterprise-Host** über **Manuell einrichten** ein. Siehe [GitHub Enterprise Server verbinden](/sensei/setup_sensei/#connect-github-enterprise-server). DefectDojo leitet die API (`/api/v3`) und die Web-Origins vom Host ab.
- **Koexistenz:** Eine github.com-App-Verbindung und eine GHES-App-Verbindung können auf derselben Instanz konfiguriert werden; jedes Repository wird der Verbindung zugeordnet, über die es angebunden wurde.
- **Erreichbarkeit:** DefectDojo muss den GHES-API-Host erreichen können, und GHES muss den Endpunkt `…/sensei/webhooks` von DefectDojo erreichen können (interne Hosts sind unproblematisch, solange beide Seiten sich verbinden können).

## Fehlerbehebung

- **Die Sensei-Schaltfläche bei einem Befund zeigt „Produkt konfigurieren“.** Das Produkt des Befunds ist nicht angebunden. Klicken Sie darauf, um ein Repository für dieses Produkt anzubinden, und kehren Sie dann zum Befund zurück.
- **Ein Fix zeigt „Fehlgeschlagen“ in Auto-fix Candidates oder Scan Activity.** Öffnen Sie **Scan Activity** und prüfen Sie **Root Cause** / **Details** für diesen Lauf. Fehlgeschlagene Fixes bleiben gelistet, damit sie nicht verschwinden, bevor sie einen PR erzeugen; Sie können sie neu bereitstellen und erneut versuchen.
- **Ein Repository wird beim Onboarding nicht angezeigt.** Es werden nur Repositorys angezeigt, auf die die Verbindung zugreifen kann. Prüfen Sie bei **GitHub**, ob die App in der richtigen Organisation installiert ist und ihr Repository-Zugriff das Repository einschließt. Prüfen Sie bei **GitLab**, ob der Scope des Zugriffstokens das Projekt abdeckt. Prüfen Sie bei **Bitbucket Cloud**, ob der **Workspace** gesetzt ist (Tokens sind workspace-gebunden). Prüfen Sie bei **Azure DevOps**, ob die Organisation des PAT übereinstimmt und dessen **Code**-Scope gewährt ist.
- **Scans oder Fixes starten nach einem Webhook nie.** Stellen Sie sicher, dass der Webhook des Repositorys auf den Receiver des Anbieters zeigt (`…/sensei/{gitlab,bitbucket,azure}/webhooks`, oder `…/sensei/webhooks` für GitHub) mit dem richtigen Secret/den richtigen Zugangsdaten und für Push- + Pull-Request- (+ Comment-)Ereignisse abonniert ist. Die **letzten Zustellungen** des Anbieters sollten `HTTP 200` zeigen. Webhook-gesteuerte Läufe werden nur für Repositorys ausgelöst, die im **gehosteten** Modus angebunden sind; ein Push auf einen Nicht-Standard-Branch wird über dessen Pull Request gescannt, nicht eigenständig.
- **Nach einem Scan passiert nichts.** Prüfen Sie, ob automatisierte Fixes in der Konfiguration des Repositorys aktiviert sind (und Ihre Schweregrad-/Risiko-Schwellenwerte zu den Befunden passen) und ob Ihr **Fixes**-Kontingent nicht aufgebraucht ist.

> **🔎 Noch in BETA:** Sensei entwickelt sich schnell weiter. Wenn das Verhalten nicht mit diesem Leitfaden übereinstimmt, prüfen Sie das [Pro-Changelog](/releases/pro/changelog/) auf aktuelle Änderungen.
