---
title: Configura Sensei
description: Connetti GitHub, GitLab, Bitbucket o Azure DevOps e integra un repository
  per la scansione ospitata
draft: false
audience: pro
weight: 2
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Sensei è una funzionalità esclusiva di DefectDojo Pro ed è attualmente in BETA.</span>

La configurazione di Sensei prevede due fasi: **collegare un provider di controllo del codice sorgente**, quindi **integrare i repository** che vuoi sottoporre a scansione. Per farlo è necessario un ruolo globale di **Maintainer** o **Owner**. Sensei supporta:

- **GitHub**: una GitHub App (github.com o **GitHub Enterprise Server**).
- **GitLab**: un token di accesso (gitlab.com o self-managed).
- **Bitbucket**: Cloud o Server/Data Center, tramite OAuth (consigliato), un token API Atlassian o un token di accesso.
- **Azure DevOps**: un Personal Access Token.

L'integrazione, la configurazione, la scansione e la correzione sono identiche per ogni provider; cambia solo la connessione iniziale. Questa pagina copre [la connessione di una GitHub App](#connect-a-github-app), [GitHub Enterprise Server](#connect-github-enterprise-server), [GitLab](#connect-gitlab), [Bitbucket](#connect-bitbucket) e [Azure DevOps](#connect-azure-devops); il passaggio [Seleziona i repository](#select-repositories) in poi è condiviso.

**Add Repositories** nell'hub di Sensei è il punto di ingresso per entrambe le fasi. Apre un menu che elenca ogni connessione per nome: scegline una per selezionare i repository da essa, oppure scegli **Connect a new source** per configurare un provider non ancora collegato. Se non è presente alcuna connessione, si passa direttamente al flusso di connessione.

![Il menu Add Repositories](images/add_repositories_menu.png)

## Connessioni

Una **connessione** è un'identità di controllo del codice sorgente configurata: una registrazione di GitHub App, un token GitLab, uno workspace Bitbucket o un'organizzazione Azure DevOps. Puoi integrare i repository da una connessione, oltre a gestirla o disconnetterla, dalla pagina **Connections** (il pulsante **Connections** nell'hub di Sensei).

![Connessioni di Sensei](images/connections.png)

La tabella elenca l'etichetta, l'identità, il numero di repository integrati, la data di creazione e il provider di ogni connessione. Usa le azioni di riga (il menu a sinistra di ogni riga) per gestire la connessione sul relativo provider, aggiungere repository da quella connessione, aprirla per la modifica (**Update credentials**, oppure **Manage App & installations** per GitHub) o disconnetterla.

![Azioni di riga della connessione](images/connection_row_menu.png) **Add a connection** non mostra mai i dettagli di una connessione esistente. Tutto ciò che riguarda una connessione già esistente si trova nella sua schermata dedicata, raggiungibile dalla relativa riga.

### Più organizzazioni per provider

Un'istanza può contenere **tutte le connessioni di cui hai bisogno, per ogni provider**, una per organizzazione, gruppo o workspace:

- **GitHub:** installa la App su ogni organizzazione o account utente (**Install on another account**). Un'unica registrazione della App le copre tutte. Per mantenere registrazioni separate, ad esempio un host GitHub Enterprise Server insieme a github.com, usa **Register another GitHub App**. Lo stato della App (le sue installazioni, le approvazioni dei permessi, **Install on another account** e **Disconnect this App**) si trova nella schermata di quella connessione, raggiungibile con **Manage App & installations** sulla relativa riga. Con più di una registrazione, un selettore in quella schermata permette di passare dall'una all'altra.
- **GitLab:** una connessione per ogni token di gruppo o progetto, incluse più connessioni sullo stesso host (`gitlab.com` più self-managed).
- **Bitbucket:** una connessione per workspace.
- **Azure DevOps:** una connessione per organizzazione, poiché un PAT ha ambito a livello di organizzazione.

Ogni passaggio attraverso **Connect** nella pagina Connections **aggiunge** una connessione, quindi collegare un secondo gruppo o workspace non sostituisce mai il primo. Assegna a ciascuna un **Connection Label** per distinguerle nella tabella. Ogni repository registra la connessione tramite cui è stato integrato, e le sue scansioni, pull request e correzioni usano le credenziali di quella connessione. Quando per un provider esiste più di una connessione, l'integrazione chiede quale usare invece di sceglierla automaticamente.

Per ruotare un token, un PAT o una password dell'app, usa **Update credentials** sulla riga di quella connessione. La schermata che si apre riguarda una singola connessione: il titolo è **Edit connection: \<label\>** e il salvataggio aggiorna quella connessione invece di aggiungerne un'altra. Raggiungerla invece da **Connect** mostra il titolo **Add a connection**. (Le credenziali della GitHub App vengono gestite su GitHub.)

L'**URL del webhook di un provider è condiviso da tutte le sue connessioni**, e ogni connessione verifica il proprio secret, quindi non serve un URL diverso per ogni gruppo, workspace o organizzazione.

> **⚠️ La disconnessione è distruttiva:** disconnettere una connessione la rimuove **insieme a ogni repository integrato tramite essa**. Questa operazione non può essere annullata.

## Scegli un provider di controllo del codice sorgente

Dall'hub di Sensei, scegli **Add Repositories → Connect a new source** (oppure **Connect** nella pagina Connections) per aprire **Add a connection**, quindi scegli il tuo provider di controllo del codice sorgente: **GitHub** (incluso GitHub Enterprise Server), **GitLab**, **Bitbucket** o **Azure DevOps**. Il flusso di connessione di ogni provider è descritto di seguito.

![Add a connection, con il provider di controllo del codice sorgente scelto qui](images/setup_providers.png)

## Collega una GitHub App

Sensei funziona interamente tramite una GitHub App. Installala sulla tua organizzazione/account e DefectDojo userà token a breve durata per aprire PR, eseguire scansioni e applicare correzioni. Niente da incollare, niente da ruotare.

Dall'hub di Sensei, scegli **Add Repositories → Connect a new source** (oppure **Connect** nella pagina Connections) per aprire **Add a connection**.

### Passaggio 1: crea la App

Inserisci l'**organizzazione** proprietaria dei repository che vuoi sottoporre a scansione (lascia vuoto per creare la App sul tuo account personale), quindi fai clic su **Create GitHub App**. GitHub precompila il nome della app, gli URL e i permessi: verificali e conferma.

![Crea la GitHub App](images/setup_create_app.png)

GitHub apre una pagina di conferma. Fai clic su **Create GitHub App for `<org>`** per registrare la app sotto quell'organizzazione.

![Conferma la creazione della app su GitHub](images/github_create_app.png)

> **🔑 Suggerimento:** crea la App sulla stessa organizzazione proprietaria dei repository che intendi sottoporre a scansione. Il proprietario della App viene impostato al momento della creazione.

### Passaggio 2: installa la App

Tornato in DefectDojo, la app risulta *configured*. Fai clic su **Install on GitHub** per installarla sulla tua organizzazione.

![La schermata dedicata alla connessione, dove la App viene installata e gestita](images/setup_install_app.png)

Su GitHub, conferma la posizione di installazione (la tua organizzazione), scegli **All repositories** oppure **Only select repositories** e verifica i permessi richiesti. Sensei richiede accesso in lettura ad actions, issue e metadata, e accesso in lettura/scrittura a check, codice, pull request, secret e workflow, in modo da poter eseguire scansioni e aprire PR di correzione. Fai clic su **Install**.

![Installa la App sulla tua organizzazione](images/github_install_app.png)

## Collega GitLab

Sensei supporta anche **GitLab**, sia istanze **gitlab.com** sia **self-managed**. Invece di una GitHub App, GitLab si collega con un **token di accesso di progetto o di gruppo** più un webhook; Sensei usa quel token per eseguire scansioni, aprire merge request e applicare correzioni.

Dall'hub di Sensei, scegli **Add Repositories → Connect a new source** (oppure **Connect** nella pagina Connections) per aprire **Add a connection**, quindi seleziona **GitLab** come provider di controllo del codice sorgente.

### Passaggio 1: crea un token di accesso

In GitLab, apri il progetto (o il gruppo) che vuoi sottoporre a scansione e vai su **Settings → Access tokens → Add new token**:

- **Role:** **Developer** è sufficiente per effettuare il push dei branch di correzione e aprire merge request. Scegli **Maintainer** se le regole di push del progetto lo richiedono.
- **Scopes:** **`api`** e **`write_repository`**.

Crea il token e copia il valore generato `glpat-…` (GitLab lo mostra una sola volta).

> **🔑 Suggerimento:** un token di accesso di **gruppo** integra qualsiasi progetto in quel gruppo; un token di accesso di **progetto** è limitato al singolo progetto.

### Passaggio 2: connetti

Tornato in **Add a connection** con **GitLab** selezionato, compila:

- **GitLab Base URL:** `https://gitlab.com`, oppure l'URL della tua istanza self-managed (ad esempio `https://gitlab.example.com`).
- **Access Token:** il token `glpat-…` ottenuto al Passaggio 1.
- **Webhook Secret:** lascia vuoto per generarlo automaticamente (consigliato). Aggiungerai questo secret al webhook nel passaggio successivo.

Fai clic su **Add GitLab connection**. DefectDojo convalida il token, lo memorizza cifrato e può quindi elencare i progetti, aprire merge request ed eseguire scansioni.

### Passaggio 3: aggiungi il webhook

Affinché DefectDojo riceva gli eventi di push, merge request e commento, aggiungi un webhook a **ogni** progetto GitLab che intendi integrare (**Settings → Webhooks → Add new webhook**):

- **URL:** l'URL del webhook mostrato nella schermata della connessione (`https://<your-defectdojo-host>/sensei/gitlab/webhooks`).
- **Secret token:** il secret del webhook ottenuto al Passaggio 2.
- **Trigger events:** abilita **Push events**, **Merge request events** e **Comments**.

Lascia abilitata la verifica SSL, fai clic su **Add webhook**, quindi usa **Test → Push events** per confermare che DefectDojo risponda con **HTTP 200**.

Dopo la connessione, fai clic su **Choose projects** e prosegui con [Seleziona i repository](#select-repositories); l'integrazione, la configurazione e la scansione funzionano come per GitHub.

> **Equivalenti GitLab:** dove questa guida dice *pull request*, GitLab usa una **merge request**; il **controllo di stato** della pull request viene pubblicato come **commit status** di GitLab sul commit head della merge request.

## Collega GitHub Enterprise Server

Sensei funziona con **GitHub Enterprise Server (GHES)** usando lo stesso modello di GitHub App di github.com. Cambia solo l'host. Poiché il flusso di creazione automatica tramite manifest della App è disponibile solo su github.com, su GHES devi **creare la App manualmente** sul tuo host enterprise e poi inserire in DefectDojo le sue credenziali insieme all'host.

### Passaggio 1: crea la App sul tuo host GHES

Sulla tua istanza GitHub Enterprise Server, vai su **Settings → Developer settings → GitHub Apps → New GitHub App** e crea una App con gli stessi permessi usati da Sensei su github.com: lettura per actions, issue e metadata, e lettura/scrittura per check, codice, pull request, secret e workflow. Imposta il webhook su `https://<your-defectdojo-host>/sensei/webhooks`. Genera e scarica una **chiave privata**, e annota l'**App ID** (e il **Client ID/Secret** OAuth se li configuri).

### Passaggio 2: connetti manualmente

Nella schermata della connessione con **GitHub** selezionato, fai clic su **Set up manually instead** e compila:

- **App ID** e **Private Key (PEM)** ottenuti al Passaggio 1 (oltre a Client ID/Secret e Webhook Secret se configurati).
- **GitHub Enterprise host:** l'host della tua istanza, ad esempio `https://github.example.com`. DefectDojo ne deriva gli origin dell'API (`/api/v3`) e web. Lascia vuoto per github.com.

Fai clic su **Save App credentials**. DefectDojo le convalida rispetto al tuo host enterprise, poi installa la App e prosegui con [Seleziona i repository](#select-repositories).

> **🔑 Suggerimento:** l'host deve essere raggiungibile da DefectDojo (e DefectDojo deve essere raggiungibile da GHES per i webhook). Gli host solo interni vanno bene, purché entrambi possano raggiungersi reciprocamente sulla tua rete.

## Collega Bitbucket

Sensei supporta **Bitbucket Cloud** (`bitbucket.org`) e **Bitbucket Server / Data Center** (self-hosted). Sono disponibili tre metodi di autenticazione non deprecati; si consiglia **OAuth**.

Dall'hub di Sensei, scegli **Add Repositories → Connect a new source** (oppure **Connect** nella pagina Connections), quindi seleziona **Bitbucket** e il tuo tipo di **deployment** (Cloud o Server/Data Center) e di **autenticazione**.

### Passaggio 1: crea la credenziale

**OAuth (consigliato):** in Bitbucket, apri **Workspace settings → OAuth consumers → Add consumer**:

- **Callback URL:** quello mostrato nella schermata della connessione (`https://<your-defectdojo-host>/sensei/bitbucket/oauth/callback`).
- **Permissions:** **Account: Read**, **Repositories: Read + Write**, **Pull requests: Read + Write** (aggiungi **Webhooks: Read + Write** se gestirai i webhook tramite l'API).

Salvalo, quindi copia il **Key** (Client ID) e il **Secret** del consumer.

**API token**: crea un **token API** Atlassian su `id.atlassian.com` (Account settings → Security → API tokens). Usalo con la tua **email dell'account Atlassian**.

**Access token**: crea un **Access Token** di repository o workspace in Bitbucket e usalo come credenziale bearer.

### Passaggio 2: connetti

Tornato nella schermata della connessione con **Bitbucket** selezionato:

- **OAuth:** incolla il **Client ID** e il **Client Secret**, quindi fai clic su **Connect with Bitbucket**. Approva la schermata di consenso; DefectDojo memorizza cifrati i token risultanti e li aggiorna automaticamente.
- **API token / Access token:** inserisci il tuo **Workspace** (Cloud), la tua **email** (solo per l'autenticazione con API token) e il **token**. Per Server/Data Center, inserisci la **Base URL** del tuo host.

DefectDojo convalida la credenziale e può quindi elencare i repository, aprire pull request ed eseguire scansioni.

### Passaggio 3: aggiungi il webhook

Aggiungi un webhook a **ogni** repository Bitbucket (**Repository settings → Webhooks → Add webhook**):

- **URL:** l'URL del webhook mostrato nella schermata della connessione (`https://<your-defectdojo-host>/sensei/bitbucket/webhooks`).
- **Secret:** il secret del webhook mostrato nella pagina (usato per la verifica HMAC-SHA256 `X-Hub-Signature`).
- **Triggers:** **Repository push**, **Pull request** (created, updated, merged, declined) e **Pull request comment created** (per i commenti `/fix`).

Dopo la connessione, fai clic su **Choose repositories** e prosegui con [Seleziona i repository](#select-repositories).

> **Specifiche di Bitbucket:** i repository sono indirizzati come `workspace/repo` (Cloud) o `PROJECTKEY/repo` (Server). Il **controllo di stato** della pull request viene pubblicato come **build status** di Bitbucket sul commit head. OAuth è il metodo consigliato perché è basato sul contesto utente (nessuna particolarità di workspace/username) e si aggiorna automaticamente; le app password sono deprecate e non supportate.

## Collega Azure DevOps

Sensei supporta **Azure DevOps Repos** usando un **Personal Access Token (PAT)**. I repository risiedono in una gerarchia **organizzazione → progetto → repository**.

Dall'hub di Sensei, scegli **Add Repositories → Connect a new source** (oppure **Connect** nella pagina Connections), quindi seleziona **Azure DevOps**.

### Passaggio 1: crea un PAT

In Azure DevOps, apri **User settings → Personal access tokens → New Token**:

- **Organization:** l'organizzazione i cui repository vuoi sottoporre a scansione.
- **Scopes:** **Code (Read, Write, & Manage)**, che copre clonazione, push dei branch di correzione e apertura di pull request.

Crea il token e copialo (Azure DevOps lo mostra una sola volta).

### Passaggio 2: connetti

Tornato nella schermata della connessione con **Azure DevOps** selezionato, compila:

- **Base URL:** `https://dev.azure.com`, oppure l'URL della collection del tuo **Server** Azure DevOps.
- **Organization:** il nome della tua organizzazione.
- **Personal Access Token:** il token ottenuto al Passaggio 1.

Fai clic su **Connect**. DefectDojo convalida il PAT rispetto a `…/_apis/projects`, lo memorizza cifrato e può quindi elencare i repository, aprire pull request ed eseguire scansioni.

### Passaggio 3: aggiungi il service hook

Azure DevOps autentica i suoi **Service Hooks** con HTTP Basic e usa **una subscription per ogni tipo di evento**. In **Project settings → Service hooks → Create subscription → Web Hooks**, crea una subscription per ciascuno di **Code pushed**, **Pull request created**, **Pull request updated** e **Pull request merged**, tutte con:

- **URL:** l'URL del webhook mostrato nella schermata della connessione (`https://<your-defectdojo-host>/sensei/azure/webhooks`).
- **Basic authentication username / password:** i valori mostrati nella pagina.

Dopo la connessione, fai clic su **Choose repositories** e prosegui con [Seleziona i repository](#select-repositories).

> **Specifiche di Azure DevOps:** i repository sono indirizzati come `project/repo` (l'organizzazione è memorizzata sulla connessione). Il **controllo di stato** della pull request viene pubblicato come **commit status** Git sul commit head.

## Seleziona i repository

Dopo l'installazione della App, DefectDojo mostra i repository a cui può accedere. Vengono elencati solo i repository su cui Sensei ha **accesso in push**; la remediation funziona effettuando il push di un branch e aprendo una pull request, quindi i repository senza accesso in push sono nascosti. Una pull request viene aperta contro il **branch predefinito** di ogni repository.

![Seleziona i repository da integrare](images/setup_repo_picker.png)

Usa **Add** per selezionare uno o più repository, quindi fai clic su **Configure N repo(s)**. I repository già integrati sono contrassegnati come **Configured** e non possono essere aggiunti due volte.

### Un repository non è elencato

Il selettore mostra solo i repository a cui la connessione ha ricevuto accesso. Un repository a cui non hai mai concesso l'accesso a Sensei non comparirà. Se la connessione copre un singolo repository già integrato, l'elenco sembrerà non avere nulla da aggiungere. Amplia ciò che la connessione può vedere, poi torna a questo passaggio:

- **GitHub:** usa **Manage repository access for \<account\>** per aprire la pagina di quell'installazione su GitHub, dove puoi aggiungere repository all'installazione. Usa **Install on another account** per installare la App su una seconda organizzazione o account utente.
- **GitLab, Bitbucket, Azure DevOps:** l'elenco è delimitato dalla credenziale collegata. Concedi al token, alla app password o al PAT l'accesso al progetto (un token di **gruppo** GitLab copre ogni progetto del gruppo), oppure aggiungi una seconda connessione per un altro gruppo, workspace o organizzazione.

## Configura un repository

Il modulo **Configure Repository** controlla il modo in cui Sensei esegue la scansione e produce report sul repository.

![Configura un repository](images/repo_config.png)

- **Scanning Mode (DefectDojo-hosted):** le scansioni vengono eseguite in DefectDojo. Non viene aggiunto nulla al tuo repository; avvia le scansioni su richiesta o automaticamente tramite la GitHub App.
- **PR Reporting:** scegli cosa Sensei pubblica sulle pull request:
  - Pubblica un controllo di stato sulla pull request.
  - Fai fallire il controllo quando vengono introdotti riscontri completamente nuovi.
  - Pubblica un commento di riepilogo dei risultati su ogni commit.
  - Crea automaticamente la baseline del branch base alla prima PR.
- **Automated Fixes:** abilita *Stage matching findings for one-click auto-fix after each scan* per far sì che Sensei metta automaticamente in stage i candidati (vedi sotto).

### Criteri di correzione automatica

Quando le correzioni automatiche sono abilitate, i riscontri che soddisfano i tuoi criteri vengono messi in stage come **candidati** nella pagina di Sensei dopo ogni scansione. Non viene eseguito nulla (e non viene sostenuto alcun costo LLM) finché non approvi, a meno che tu non abiliti la remediation automatica.

![Criteri di correzione automatica e opzioni avanzate](images/repo_config_advanced.png)

- **Severity threshold:** i riscontri con questa gravità o superiore sono idonei (scegli *Any* per basarsi solo sul rischio).
- **Risk threshold:** anche i riscontri con questo livello di rischio o superiore sono idonei (combinato con la gravità tramite OR).
- **Open fix PRs against branch:** il branch verso cui puntano le pull request di correzione automatica; può essere sovrascritto per singola correzione quando approvi individualmente.
- **Exclude findings tagged:** salta i riscontri che portano i tag elencati (ad es. `no-fix`).
- **Automatically remediate candidates:** se abilitato, un controllo in background (circa ogni 5 minuti) apre pull request di correzione per i candidati in stage di questo repository senza attendere l'approvazione, fino al raggiungimento della tua quota di correzioni. Lascia disabilitato per rivedere e approvare tu stesso ogni candidato.

In **Advanced options** puoi collegare il repository a un Prodotto/asset esistente o crearne uno nuovo, impostare l'organizzazione e impostare una gravità minima al di sotto della quale i riscontri non vengono né segnalati né usati nel merge gate.

## Integra

Fai clic su **Onboard for hosted scanning**. Il repository compare nell'hub di Sensei con stato **Attivo**, pronto per la scansione. Da qui, prosegui con [Correggere i riscontri con Sensei](/sensei/fixing_findings/).
