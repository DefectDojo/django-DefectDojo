---
title: Sensei einrichten
description: Verbinden Sie GitHub, GitLab, Bitbucket oder Azure DevOps und binden
  Sie ein Repository für gehostetes Scannen an
draft: false
audience: pro
weight: 2
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Sensei ist eine Funktion, die ausschließlich in DefectDojo Pro verfügbar ist, und befindet sich derzeit in der BETA-Phase.</span>

Die Einrichtung von Sensei besteht aus zwei Teilen: Zunächst **verbinden Sie einen Versionsverwaltungs-Anbieter**, und anschließend **binden Sie die Repositories an**, die Sie scannen möchten. Dazu benötigen Sie eine globale Rolle als **Maintainer** oder **Owner**. Sensei unterstützt:

- **GitHub**: eine GitHub App (github.com oder **GitHub Enterprise Server**).
- **GitLab**: ein Access Token (gitlab.com oder selbst gehostet).
- **Bitbucket**: Cloud oder Server/Data Center, über OAuth (empfohlen), ein Atlassian API-Token oder ein Access Token.
- **Azure DevOps**: ein Personal Access Token.

Onboarding, Konfiguration, Scannen und Fixen laufen bei jedem Anbieter gleich ab; nur die anfängliche Verbindung unterscheidet sich. Diese Seite behandelt [das Verbinden einer GitHub App](#connect-a-github-app), [GitHub Enterprise Server](#connect-github-enterprise-server), [GitLab](#connect-gitlab), [Bitbucket](#connect-bitbucket) und [Azure DevOps](#connect-azure-devops); der Schritt [Repositories auswählen](#select-repositories) und alles danach ist für alle gleich.

**Add Repositories** im Sensei-Hub ist der Einstiegspunkt für beides. Es öffnet ein Menü, das jede Verbindung mit ihrem Namen auflistet: Wählen Sie eine aus, um Repositories daraus auszuwählen, oder wählen Sie **Connect a new source**, um einen noch nicht verbundenen Anbieter einzurichten. Ist noch nichts verbunden, gelangen Sie direkt in den Verbindungs-Ablauf.

![Das Menü „Add Repositories“](images/add_repositories_menu.png)

## Verbindungen

Eine **Verbindung** ist eine konfigurierte Versionsverwaltungs-Identität: eine GitHub-App-Registrierung, ein GitLab-Token, ein Bitbucket-Workspace oder eine Azure-DevOps-Organisation. Sie binden Repositories über eine Verbindung an und verwalten oder trennen diese auf der Seite **Connections** (die Schaltfläche **Connections** im Sensei-Hub).

![Sensei-Verbindungen](images/connections.png)

Die Tabelle zeigt für jede Verbindung Label, Identität, Anzahl der angebundenen Repositories, Erstellungsdatum und Anbieter. Nutzen Sie die Zeilenaktionen (das Menü links in jeder Zeile), um die Verbindung beim jeweiligen Anbieter zu verwalten, Repositories aus dieser Verbindung hinzuzufügen, sie zur Bearbeitung zu öffnen (**Update credentials**, bei GitHub **Manage App & installations**) oder sie zu trennen.

![Zeilenaktionen einer Verbindung](images/connection_row_menu.png) **Add a connection** zeigt niemals die Details einer bestehenden Verbindung. Alles zu einer bereits vorhandenen Verbindung finden Sie auf deren eigenem Bildschirm, den Sie über ihre Zeile erreichen.

### Mehrere Organisationen pro Anbieter

Eine Instanz kann **so viele Verbindungen enthalten, wie Sie benötigen, für jeden Anbieter**, jeweils eine pro Organisation, Gruppe oder Workspace:

- **GitHub:** Installieren Sie die App auf jeder Organisation oder jedem Benutzerkonto (**Install on another account**). Eine einzige App-Registrierung deckt sie alle ab. Um separate Registrierungen zu behalten, etwa einen GitHub-Enterprise-Server-Host neben github.com, verwenden Sie **Register another GitHub App**. Der eigene Zustand einer App (ihre Installationen, Berechtigungsfreigaben, **Install on another account** und **Disconnect this App**) befindet sich auf dem Bildschirm dieser Verbindung, den Sie über **Manage App & installations** in ihrer Zeile öffnen. Bei mehr als einer Registrierung können Sie dort über eine Auswahl zwischen ihnen wechseln.
- **GitLab:** eine Verbindung pro Gruppen- oder Projekt-Token, auch mehrere auf demselben Host (`gitlab.com` plus selbst gehostet).
- **Bitbucket:** eine Verbindung pro Workspace.
- **Azure DevOps:** eine Verbindung pro Organisation, da ein PAT auf Organisationsebene gilt.

Jeder Durchlauf über **Connect** auf der Connections-Seite **fügt** eine Verbindung hinzu; das Verbinden einer zweiten Gruppe oder eines zweiten Workspace ersetzt die erste also nie. Vergeben Sie für jede Verbindung ein **Connection Label**, um sie in der Tabelle auseinanderzuhalten. Jedes Repository speichert, über welche Verbindung es angebunden wurde, und seine Scans, Pull Requests und Fixes verwenden die Anmeldedaten dieser Verbindung. Existieren für einen Anbieter mehrere Verbindungen, fragt das Onboarding, welche verwendet werden soll, statt selbst eine auszuwählen.

Um ein Token, PAT oder App-Passwort zu rotieren, verwenden Sie **Update credentials** in der Zeile dieser Verbindung. Der sich öffnende Bildschirm bezieht sich auf genau eine Verbindung: Er trägt den Titel **Edit connection: \<label\>**, und das Speichern aktualisiert diese Verbindung, statt eine weitere hinzuzufügen. Erreichen Sie ihn stattdessen über **Connect**, lautet der Titel **Add a connection**. (GitHub-App-Anmeldedaten werden auf GitHub verwaltet.)

Die **Webhook-URL eines Anbieters wird von all seinen Verbindungen gemeinsam genutzt**, und jede Verbindung prüft ihr eigenes Secret, sodass Sie nicht pro Gruppe, Workspace oder Organisation eine andere URL benötigen.

> **⚠️ Das Trennen ist destruktiv:** Wenn Sie eine Verbindung trennen, wird sie **zusammen mit jedem darüber angebundenen Repository** entfernt. Dies kann nicht rückgängig gemacht werden.

## Versionsverwaltungs-Anbieter auswählen

Wählen Sie im Sensei-Hub **Add Repositories → Connect a new source** (oder **Connect** auf der Connections-Seite), um **Add a connection** zu öffnen, und wählen Sie dann Ihren Versionsverwaltungs-Anbieter: **GitHub** (einschließlich GitHub Enterprise Server), **GitLab**, **Bitbucket** oder **Azure DevOps**. Der Verbindungsablauf für jeden Anbieter wird im Folgenden beschrieben.

![Add a connection, hier mit ausgewähltem Versionsverwaltungs-Anbieter](images/setup_providers.png)

## Eine GitHub App verbinden

Sensei läuft vollständig über eine GitHub App. Installieren Sie sie auf Ihrer Organisation bzw. Ihrem Konto, und DefectDojo verwendet kurzlebige Tokens, um PRs zu öffnen, zu scannen und Fixes anzuwenden. Nichts zum Einfügen, nichts zum Rotieren.

Wählen Sie im Sensei-Hub **Add Repositories → Connect a new source** (oder **Connect** auf der Connections-Seite), um **Add a connection** zu öffnen.

### Schritt 1: Die App erstellen

Geben Sie die **Organisation** ein, der die zu scannenden Repositories gehören (leer lassen, um die App in Ihrem persönlichen Konto zu erstellen), und klicken Sie dann auf **Create GitHub App**. GitHub füllt Name, URLs und Berechtigungen der App vorab aus; prüfen Sie diese und bestätigen Sie.

![Die GitHub App erstellen](images/setup_create_app.png)

GitHub öffnet eine Bestätigungsseite. Klicken Sie auf **Create GitHub App for `<org>`**, um die App unter dieser Organisation zu registrieren.

![Die App-Erstellung auf GitHub bestätigen](images/github_create_app.png)

> **🔑 Tipp:** Erstellen Sie die App in derselben Organisation, der die zu scannenden Repositories gehören. Der App-Owner wird bei der Erstellung festgelegt.

### Schritt 2: Die App installieren

Zurück in DefectDojo wird die App als *configured* angezeigt. Klicken Sie auf **Install on GitHub**, um sie in Ihrer Organisation zu installieren.

![Der eigene Bildschirm der Verbindung, auf dem die App installiert und verwaltet wird](images/setup_install_app.png)

Bestätigen Sie auf GitHub den Installationsort (Ihre Organisation), wählen Sie **All repositories** oder **Only select repositories**, und prüfen Sie die angeforderten Berechtigungen. Sensei benötigt Lesezugriff auf Actions, Issues und Metadaten sowie Lese-/Schreibzugriff auf Checks, Code, Pull Requests, Secrets und Workflows, damit es scannen und Fix-PRs öffnen kann. Klicken Sie auf **Install**.

![Die App in Ihrer Organisation installieren](images/github_install_app.png)

## GitLab verbinden

Sensei unterstützt auch **GitLab**, sowohl **gitlab.com** als auch **selbst gehostete** Instanzen. Statt einer GitHub App verbindet sich GitLab über ein **Projekt- oder Gruppen-Access-Token** plus einen Webhook; Sensei verwendet dieses Token zum Scannen, zum Öffnen von Merge Requests und zum Anwenden von Fixes.

Wählen Sie im Sensei-Hub **Add Repositories → Connect a new source** (oder **Connect** auf der Connections-Seite), um **Add a connection** zu öffnen, und wählen Sie dann **GitLab** als Versionsverwaltungs-Anbieter.

### Schritt 1: Ein Access Token erstellen

Öffnen Sie in GitLab das Projekt (oder die Gruppe), das/die Sie scannen möchten, und gehen Sie zu **Settings → Access tokens → Add new token**:

- **Role:** **Developer** genügt, um Fix-Branches zu pushen und Merge Requests zu öffnen. Wählen Sie **Maintainer**, wenn die Push-Regeln des Projekts dies erfordern.
- **Scopes:** **`api`** und **`write_repository`**.

Erstellen Sie das Token und kopieren Sie den generierten `glpat-…`-Wert (GitLab zeigt ihn nur einmal an).

> **🔑 Tipp:** Ein **Gruppen**-Access-Token bindet jedes Projekt dieser Gruppe an; ein **Projekt**-Access-Token gilt nur für das einzelne Projekt.

### Schritt 2: Verbinden

Füllen Sie in **Add a connection** mit ausgewähltem **GitLab** Folgendes aus:

- **GitLab Base URL:** `https://gitlab.com` oder die URL Ihrer selbst gehosteten Instanz (zum Beispiel `https://gitlab.example.com`).
- **Access Token:** das `glpat-…`-Token aus Schritt 1.
- **Webhook Secret:** leer lassen, um es automatisch zu generieren (empfohlen). Sie fügen dieses Secret im nächsten Schritt zum Webhook hinzu.

Klicken Sie auf **Add GitLab connection**. DefectDojo validiert das Token, speichert es verschlüsselt und kann anschließend Projekte auflisten, Merge Requests öffnen und Scans ausführen.

### Schritt 3: Den Webhook hinzufügen

Damit DefectDojo Push-, Merge-Request- und Kommentar-Events empfängt, fügen Sie **jedem** GitLab-Projekt, das Sie anbinden möchten, einen Webhook hinzu (**Settings → Webhooks → Add new webhook**):

- **URL:** die auf dem Verbindungsbildschirm angezeigte Webhook-URL (`https://<your-defectdojo-host>/sensei/gitlab/webhooks`).
- **Secret token:** das Webhook-Secret aus Schritt 2.
- **Trigger events:** aktivieren Sie **Push events**, **Merge request events** und **Comments**.

Lassen Sie die SSL-Verifizierung aktiviert, klicken Sie auf **Add webhook**, und verwenden Sie dann **Test → Push events**, um zu bestätigen, dass DefectDojo mit **HTTP 200** antwortet.

Klicken Sie nach dem Verbinden auf **Choose Projects** und fahren Sie mit [Repositories auswählen](#select-repositories) fort; Onboarding, Konfiguration und Scannen funktionieren wie bei GitHub.

> **GitLab-Entsprechungen:** Wo diese Anleitung von *Pull Request* spricht, verwendet GitLab einen **Merge Request**; der **Statuscheck** des Pull Requests wird bei GitLab als **Commit-Status** auf dem Head-Commit des Merge Requests veröffentlicht.

## GitHub Enterprise Server verbinden

Sensei funktioniert mit **GitHub Enterprise Server (GHES)** nach demselben GitHub-App-Modell wie github.com. Nur der Host unterscheidet sich. Da der automatische Erstellungsablauf über das App-Manifest nur für github.com verfügbar ist, **erstellen Sie die App auf GHES manuell** auf Ihrem Enterprise-Host und geben anschließend deren Anmeldedaten sowie den Host in DefectDojo ein.

### Schritt 1: Die App auf Ihrem GHES-Host erstellen

Gehen Sie auf Ihrer GitHub-Enterprise-Server-Instanz zu **Settings → Developer settings → GitHub Apps → New GitHub App** und erstellen Sie eine App mit denselben Berechtigungen, die Sensei auf github.com verwendet: Lesezugriff für Actions, Issues und Metadaten sowie Lese-/Schreibzugriff für Checks, Code, Pull Requests, Secrets und Workflows. Richten Sie ihren Webhook auf `https://<your-defectdojo-host>/sensei/webhooks`. Generieren und laden Sie einen **Private Key** herunter, und notieren Sie sich die **App ID** (sowie OAuth **Client ID/Secret**, falls Sie diese festlegen).

### Schritt 2: Manuell verbinden

Klicken Sie auf dem Verbindungsbildschirm mit ausgewähltem **GitHub** auf **Set up manually instead** und füllen Sie Folgendes aus:

- **App ID** und **Private Key (PEM)** aus Schritt 1 (sowie Client ID/Secret und Webhook Secret, falls konfiguriert).
- **GitHub Enterprise host:** der Host Ihrer Instanz, zum Beispiel `https://github.example.com`. DefectDojo leitet daraus die API- (`/api/v3`) und Web-Origins ab. Für github.com leer lassen.

Klicken Sie auf **Save App credentials**. DefectDojo validiert sie gegen Ihren Enterprise-Host; installieren Sie anschließend die App und fahren Sie mit [Repositories auswählen](#select-repositories) fort.

> **🔑 Tipp:** Der Host muss von DefectDojo aus erreichbar sein (und DefectDojo für Webhooks von GHES aus). Rein interne Hosts sind unproblematisch, solange beide sich in Ihrem Netzwerk gegenseitig erreichen können.

## Bitbucket verbinden

Sensei unterstützt **Bitbucket Cloud** (`bitbucket.org`) und **Bitbucket Server / Data Center** (selbst gehostet). Es werden drei nicht als veraltet markierte Authentifizierungsmethoden angeboten; **OAuth wird empfohlen**.

Wählen Sie im Sensei-Hub **Add Repositories → Connect a new source** (oder **Connect** auf der Connections-Seite), dann **Bitbucket** sowie Ihr **Deployment** (Cloud oder Server/Data Center) und den **Authentifizierungstyp**.

### Schritt 1: Die Anmeldedaten erstellen

**OAuth (empfohlen):** Öffnen Sie in Bitbucket **Workspace settings → OAuth consumers → Add consumer**:

- **Callback URL:** die auf dem Verbindungsbildschirm angezeigte URL (`https://<your-defectdojo-host>/sensei/bitbucket/oauth/callback`).
- **Permissions:** **Account: Read**, **Repositories: Read + Write**, **Pull requests: Read + Write** (fügen Sie **Webhooks: Read + Write** hinzu, wenn Sie Webhooks über die API verwalten möchten).

Speichern Sie und kopieren Sie anschließend **Key** (Client ID) und **Secret** des Consumers.

**API token**: Erstellen Sie ein Atlassian-**API-Token** unter `id.atlassian.com` (Account settings → Security → API tokens). Verwenden Sie es zusammen mit Ihrer **Atlassian-Konto-E-Mail**.

**Access token**: Erstellen Sie in Bitbucket ein Repository- oder Workspace-**Access Token** und verwenden Sie es als Bearer-Anmeldedaten.

### Schritt 2: Verbinden

Zurück auf dem Verbindungsbildschirm mit ausgewähltem **Bitbucket**:

- **OAuth:** Fügen Sie **Client ID** und **Client Secret** ein und klicken Sie dann auf **Connect with Bitbucket**. Bestätigen Sie den Consent-Bildschirm; DefectDojo speichert die resultierenden Tokens verschlüsselt und erneuert sie automatisch.
- **API token / Access token:** Geben Sie Ihren **Workspace** (Cloud), Ihre **E-Mail-Adresse** (nur bei API-Token-Authentifizierung) und das **Token** ein. Geben Sie für Server/Data Center die **Base URL** Ihres Hosts ein.

DefectDojo validiert die Anmeldedaten und kann anschließend Repositories auflisten, Pull Requests öffnen und Scans ausführen.

### Schritt 3: Den Webhook hinzufügen

Fügen Sie **jedem** Bitbucket-Repository einen Webhook hinzu (**Repository settings → Webhooks → Add webhook**):

- **URL:** die auf dem Verbindungsbildschirm angezeigte Webhook-URL (`https://<your-defectdojo-host>/sensei/bitbucket/webhooks`).
- **Secret:** das auf der Seite angezeigte Webhook-Secret (verwendet für die HMAC-SHA256-`X-Hub-Signature`-Verifizierung).
- **Triggers:** **Repository push**, **Pull request** (created, updated, merged, declined) und **Pull request comment created** (für `/fix`-Kommentare).

Klicken Sie nach dem Verbinden auf **Choose Repositories** und fahren Sie mit [Repositories auswählen](#select-repositories) fort.

> **Besonderheiten von Bitbucket:** Repositories werden als `workspace/repo` (Cloud) oder `PROJECTKEY/repo` (Server) adressiert. Der **Statuscheck** des Pull Requests wird bei Bitbucket als **Build-Status** auf dem Head-Commit veröffentlicht. OAuth ist die empfohlene Methode, da sie im Benutzerkontext läuft (keine Workspace-/Benutzername-Eigenheiten) und sich automatisch erneuert; App-Passwörter sind veraltet und werden nicht unterstützt.

## Azure DevOps verbinden

Sensei unterstützt **Azure DevOps Repos** über ein **Personal Access Token (PAT)**. Repositories befinden sich in einer Hierarchie aus **Organisation → Projekt → Repository**.

Wählen Sie im Sensei-Hub **Add Repositories → Connect a new source** (oder **Connect** auf der Connections-Seite) und dann **Azure DevOps**.

### Schritt 1: Ein PAT erstellen

Öffnen Sie in Azure DevOps **User settings → Personal access tokens → New Token**:

- **Organization:** die Organisation, deren Repositories Sie scannen möchten.
- **Scopes:** **Code (Read, Write, & Manage)**, was das Klonen, das Pushen von Fix-Branches und das Öffnen von Pull Requests abdeckt.

Erstellen Sie das Token und kopieren Sie es (Azure DevOps zeigt es nur einmal an).

### Schritt 2: Verbinden

Füllen Sie auf dem Verbindungsbildschirm mit ausgewähltem **Azure DevOps** Folgendes aus:

- **Base URL:** `https://dev.azure.com` oder die Collection-URL Ihres Azure DevOps **Server**.
- **Organization:** Ihr Organisationsname.
- **Personal Access Token:** das Token aus Schritt 1.

Klicken Sie auf **Connect**. DefectDojo validiert das PAT gegen `…/_apis/projects`, speichert es verschlüsselt und kann anschließend Repositories auflisten, Pull Requests öffnen und Scans ausführen.

### Schritt 3: Den Service Hook hinzufügen

Azure DevOps authentifiziert seine **Service Hooks** über HTTP Basic und verwendet **ein Abonnement pro Ereignistyp**. Erstellen Sie unter **Project settings → Service hooks → Create subscription → Web Hooks** jeweils ein Abonnement für **Code pushed**, **Pull request created**, **Pull request updated** und **Pull request merged**, jeweils mit:

- **URL:** die auf dem Verbindungsbildschirm angezeigte Webhook-URL (`https://<your-defectdojo-host>/sensei/azure/webhooks`).
- **Basic authentication username / password:** die auf der Seite angezeigten Werte.

Klicken Sie nach dem Verbinden auf **Choose Repositories** und fahren Sie mit [Repositories auswählen](#select-repositories) fort.

> **Besonderheiten von Azure DevOps:** Repositories werden als `project/repo` adressiert (die Organisation wird an der Verbindung gespeichert). Der **Statuscheck** des Pull Requests wird als Git-**Commit-Status** auf dem Head-Commit veröffentlicht.

## Repositories auswählen

Nachdem die App installiert ist, zeigt DefectDojo die Repositories an, auf die sie Zugriff hat. Aufgelistet werden nur Repositories, für die Sensei **Push-Zugriff** hat; die Behebung funktioniert durch das Pushen eines Branches und das Öffnen eines Pull Requests, daher werden Repositories ohne Push-Zugriff ausgeblendet. Ein Pull Request wird jeweils gegen den **Default Branch** des Repositories geöffnet.

![Anzubindende Repositories auswählen](images/setup_repo_picker.png)

Verwenden Sie **Add**, um ein oder mehrere Repositories auszuwählen, und klicken Sie dann auf **Configure N repo(s)**. Bereits angebundene Repositories sind als **Configured** markiert und können nicht doppelt hinzugefügt werden.

### Ein Repository wird nicht aufgeführt

Die Auswahl zeigt nur Repositories, für die der Verbindung Zugriff gewährt wurde. Ein Repository, für das Sie Sensei nie Zugriff erteilt haben, erscheint nicht. Deckt die Verbindung nur ein einzelnes, bereits angebundenes Repository ab, sieht die Liste so aus, als gäbe es nichts hinzuzufügen. Erweitern Sie, was die Verbindung sehen kann, und kehren Sie dann zu diesem Schritt zurück:

- **GitHub:** Verwenden Sie **Manage repository access for \<account\>**, um die Seite dieser Installation auf GitHub zu öffnen, auf der Sie Repositories zur Installation hinzufügen können. Verwenden Sie **Install on another account**, um die App auf einer zweiten Organisation oder einem zweiten Benutzerkonto zu installieren.
- **GitLab, Bitbucket, Azure DevOps:** Die Liste wird durch die verbundenen Anmeldedaten eingegrenzt. Gewähren Sie dem Token, App-Passwort oder PAT Zugriff auf das Projekt (ein GitLab-**Gruppen**-Token deckt jedes Projekt in der Gruppe ab), oder fügen Sie eine zweite Verbindung für eine weitere Gruppe, einen weiteren Workspace oder eine weitere Organisation hinzu.

## Ein Repository konfigurieren

Das Formular **Configure Repository** steuert, wie Sensei das Repository scannt und darüber berichtet.

![Ein Repository konfigurieren](images/repo_config.png)

- **Scanning Mode (DefectDojo-hosted):** Scans laufen in DefectDojo. Ihrem Repository wird nichts hinzugefügt; lösen Sie Scans bei Bedarf oder automatisch über die GitHub App aus.
- **PR Reporting:** Legen Sie fest, was Sensei auf Pull Requests zurückmeldet:
  - Einen Statuscheck auf dem Pull Request veröffentlichen.
  - Den Check fehlschlagen lassen, wenn neue Befunde hinzukommen.
  - Bei jedem Commit einen Kommentar mit einer Ergebniszusammenfassung veröffentlichen.
  - Beim ersten PR automatisch die Baseline des Base-Branch erstellen.
- **Automated Fixes:** Aktivieren Sie *Stage matching findings for one-click auto-fix after each scan*, damit Sensei Kandidaten automatisch zur Freigabe bereitstellt (siehe unten).

### Kriterien für automatisierte Fixes

Wenn Automated Fixes aktiviert ist, werden Befunde, die Ihre Kriterien erfüllen, nach jedem Scan als **Candidates** auf der Sensei-Seite bereitgestellt. Es wird nichts ausgeführt (und es entstehen keine LLM-Kosten), bis Sie freigeben — es sei denn, Sie aktivieren die automatische Behebung.

![Kriterien für automatisierte Fixes und erweiterte Optionen](images/repo_config_advanced.png)

- **Severity threshold:** Befunde ab diesem Schweregrad qualifizieren sich (wählen Sie *Any*, um nur nach Risiko zu filtern).
- **Risk threshold:** Befunde ab dieser Risikostufe qualifizieren sich ebenfalls (mit Severity über ODER verknüpft).
- **Open fix PRs against branch:** der Branch, gegen den Auto-Fix-Pull-Requests geöffnet werden; bei einzelner Freigabe pro Fix überschreibbar.
- **Exclude findings tagged:** überspringt Befunde mit den von Ihnen aufgeführten Tags (z. B. `no-fix`).
- **Automatically remediate candidates:** Ist dies aktiviert, öffnet eine Hintergrundprüfung (etwa alle 5 Minuten) Fix-Pull-Requests für die bereitgestellten Kandidaten dieses Repositories, ohne auf eine Freigabe zu warten, bis Ihr Fix-Kontingent erreicht ist. Lassen Sie die Option deaktiviert, um jeden Kandidaten selbst zu prüfen und freizugeben.

Unter **Advanced options** können Sie das Repository mit einem bestehenden Produkt/Asset verknüpfen oder ein neues erstellen, die Organisation festlegen und einen Mindest-Schweregrad festlegen, unterhalb dessen Befunde weder gemeldet noch im Merge-Gate berücksichtigt werden.

## Anbinden

Klicken Sie auf **Onboard for hosted scanning**. Das Repository erscheint im Sensei-Hub mit dem Status **Active** und ist bereit zum Scannen. Fahren Sie von hier aus mit [Befunde mit Sensei beheben](/sensei/fixing_findings/) fort.
