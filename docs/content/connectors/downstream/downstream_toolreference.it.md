---
title: Guida di riferimento degli strumenti Downstream Connectors
description: Guide dettagliate alla configurazione dei Downstream Connectors
weight: 1
audience: pro
aliases:
- /it/en/share_your_findings/integrations_toolreference
- /it/issue_tracking/pro_integration/integrations_toolreference/
---

Di seguito sono riportate istruzioni specifiche su come configurare un Downstream Connector di DefectDojo con un Issue Tracker di terze parti.

## Azure DevOps Boards

### Configurazione dell'istanza

- **Etichetta** deve corrispondere all'etichetta che vuoi usare per identificare questa integrazione.
- **Posizione** deve essere impostata sul tuo URL di Azure, ad esempio `https://dev.azure.com/{your organization}`
- **Token** deve essere impostato su un token di accesso personale di Azure.

L'autenticazione con Azure DevOps richiede un [token di accesso personale](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)
con i permessi impostati su "Read, Write and Manage" per "Work Items" per il Project di Azure con cui vuoi lavorare.

### Mappatura Issue Tracker

Questi dettagli stabiliscono in che modo DefectDojo mappa gli attributi di un Riscontro o di un Gruppo di Riscontri su un determinato Project in Azure DevOps:

#### Dettagli della mappatura Issue Tracker

Il campo `Project ID` corrisponde al nome o all'ID del Project in Azure.

#### Dettagli della mappatura Gravità

Gli attributi nel modulo sono forniti come valori predefiniti e sono i seguenti:

- **Nome del campo Gravità**: `/fields/Microsoft.VSTS.Common.Priority`
- **Mappatura Info**: `4`
- **Mappatura Bassa**: `4`
- **Mappatura Media**: `3`
- **Mappatura Alta**: `2`
- **Mappatura Critica**: `1`

#### Dettagli della mappatura Stato

Gli attributi nel modulo sono forniti come valori predefiniti e sono i seguenti:

- **Nome del campo Stato**: `/fields/System.State`
- **Mappatura Attivo**: `To Do`
- **Mappatura Chiuso**: `Done`
- **Mappatura Falso positivo**: `Done`
- **Mappatura Rischio accettato**: `Done`

## Bitbucket

L'integrazione con Bitbucket consente di inviare issue all'[issue tracker](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/) di un repository Bitbucket Cloud.

L'issue tracker è facoltativo in Bitbucket e deve essere abilitato sul repository prima che DefectDojo possa creare Issue al suo interno. Per abilitarlo, apri il repository in Bitbucket e seleziona **Repository settings**, quindi abilita l'issue tracker in **Features**.

### Configurazione dell'istanza

- **Etichetta** deve corrispondere all'etichetta che vuoi usare per identificare questa integrazione.
- **Posizione** deve essere impostata su `https://bitbucket.org`.
- **Email** deve essere l'indirizzo email dell'account Atlassian a cui appartiene l'API Token.
- **API Token** deve essere impostato su un API Token di Atlassian con ambiti limitati.

Le app password di Bitbucket sono deprecate da Atlassian e non funzionano con questa integrazione. Per creare un API Token:

1. Apri le [impostazioni dell'account Atlassian](https://id.atlassian.com/manage-profile/security/api-tokens) e scegli **Security**, poi **Create and manage API tokens**.
2. Scegli **Create API token with scopes**, assegna un nome al token e imposta una data di scadenza.
3. Seleziona **Bitbucket** come app.
4. Concedi al token il permesso di leggere i repository e di leggere e scrivere le issue.

### Mappatura Issue Tracker

- **Workspace** deve essere lo slug del workspace che contiene il repository, così come appare negli URL di bitbucket.org.
- **Slug del Repository** deve essere lo slug del repository in cui vuoi creare le Issue.

### Dettagli della mappatura Gravità

Questo campo viene mappato sul campo Priority delle issue di Bitbucket. Gli attributi nel modulo sono forniti come valori predefiniti e ciascun valore deve essere una delle priorità di Bitbucket: `trivial`, `minor`, `major`, `critical` o `blocker`.

- **Nome del campo Gravità**: `priority`
- **Mappatura Info**: `trivial`
- **Mappatura Bassa**: `minor`
- **Mappatura Media**: `major`
- **Mappatura Alta**: `critical`
- **Mappatura Critica**: `blocker`

### Dettagli della mappatura Stato

Questo campo viene mappato sul campo State delle issue di Bitbucket. Ciascun valore deve essere uno degli stati delle issue di Bitbucket: `new`, `open`, `resolved`, `on hold`, `invalid`, `duplicate`, `wontfix` o `closed`.

- **Nome del campo Stato**: `state`
- **Mappatura Attivo**: `new`
- **Mappatura Chiuso**: `resolved`
- **Mappatura Falso positivo**: `invalid`
- **Mappatura Rischio accettato**: `wontfix`

## GitHub

L'integrazione con GitHub consente di aggiungere issue a un [GitHub Project](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects), il che apre anche Issue in un Repo associato. Questi Repo/Project possono essere associati a una GitHub Organization o a un account personale GitHub.

### Configurazione dell'istanza

- **Etichetta** deve corrispondere all'etichetta che vuoi usare per identificare questa integrazione.
- **Posizione** deve essere impostata sull'URL del tuo User o Organization GitHub, a seconda di dove desideri creare le issue, ad esempio `https://github.com/{your-organization}`
- **Token** deve essere impostato su un token di accesso personale di GitHub.

I token di accesso personale per GitHub possono essere creati su https://github.com/settings/tokens. Il token deve avere gli ambiti Repo e Project.

### Mappatura Issue Tracker

- **Etichetta della mappatura Issue Tracker** deve essere impostata per identificare il Project o il Repo in cui vuoi creare le Issue.
- **Numero del Project** deve essere l'ID di un progetto GitHub a cui vuoi inviare gli elementi. Puoi trovarlo nell'URL quando visualizzi un Project, ad esempio `https://github.com/orgs/{your-org}/projects/{project number}`.
- **Nome del Repository** deve essere il nome di un repository associato alla tua organization (o al tuo account) a cui vuoi inviare le Issue.


### Dettagli della mappatura Gravità

**Per configurare l'integrazione, il Project deve avere un campo personalizzato creato per rappresentare la Issue Priority, altrimenti la Gravità non verrà mappata correttamente e le Issue non verranno inviate a GitHub.**

Segui questa guida per creare un [campo personalizzato](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority).
Ogni Gravità dovrà avere una corrispondente opzione a scelta singola disponibile. Ad esempio, DefectDojo suggerisce di default P0, P1, P2, P3, P4 come possibili valori di Priority, e ciascuno di questi dovrà essere aggiunto al campo personalizzato Priority.

- **Nome del campo Gravità**: `Priority`
- **Mappatura Info**: `P0`
- **Mappatura Bassa**: `P1`
- **Mappatura Media**: `P2`
- **Mappatura Alta**: `P3`
- **Mappatura Critica**: `P4`

### Dettagli della mappatura Stato

Per impostazione predefinita, i nuovi GitHub Project hanno gli Status delle Issue "In Progress" e "Done". Se lo desideri, puoi aggiungere altri status al Project per tracciare lo stato Falso positivo o Rischio accettato. Un modo per farlo è aggiungere una nuova Status Column al Project Board.

- **Nome del campo Stato**: `Status`
- **Mappatura Attivo**: `In Progress`
- **Mappatura Chiuso**: `Done`
- **Mappatura Falso positivo**: `Done`
- **Mappatura Rischio accettato**: `Done`

## GitLab

L'integrazione con GitLab consente di aggiungere issue a un [GitLab Project](https://docs.gitlab.com/ee/user/project/).

### Configurazione dell'istanza

- **Etichetta** deve corrispondere all'etichetta che vuoi usare per identificare questa integrazione.
- **Posizione** deve essere impostata sul link al tuo server GitLab, ad esempio `https://gitlab.com/`.
- **Token** deve essere impostato su un token di accesso personale di GitLab. Il token deve avere ambiti API. Consulta la [guida di GitLab alla creazione di un token di accesso personale](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token).

### Mappatura Issue Tracker

- **Nome del Project**: il nome del progetto in GitLab a cui vuoi inviare le issue.

### Dettagli della mappatura Gravità

Questo campo viene mappato sul campo Priority di GitLab.
- **Nome del campo Gravità**: `Priority`
- **Mappatura Info**: `1`
- **Mappatura Bassa**: `2`
- **Mappatura Media**: `3`
- **Mappatura Alta**: `4`
- **Mappatura Critica**: `5`

### Dettagli della mappatura Stato

Per impostazione predefinita, GitLab ha gli status 'opened' e 'closed'. Puoi aggiungere altre etichette di stato se vuoi tracciare lo stato Falso positivo o Rischio accettato. Consulta la [documentazione di GitLab](https://docs.gitlab.com/user/work_items/status/) per i dettagli.

- **Nome del campo Stato**: `Status`
- **Mappatura Attivo**: `opened`
- **Mappatura Chiuso**: `closed`
- **Mappatura Falso positivo**: `closed`
- **Mappatura Rischio accettato**: `closed`

## Jira

L'integrazione con Jira invia i Riscontri e i Gruppi di Riscontri di DefectDojo a un progetto Jira come issue, mantiene lo status di ciascuna issue sincronizzato con il Riscontro e collega il Riscontro all'issue creata. Sono supportati sia Jira **Cloud** sia **Data Center / Server**. Jira Service Management non è supportato.

### Scelta del metodo di autenticazione

Imposta prima **Jira Deployment**, poi scegli un **Authentication Method**:

**Jira Cloud**
- **API Token (email + token)** — autenticazione HTTP Basic tramite l'email di un account Atlassian e un [API token](https://id.atlassian.com/manage-profile/security/api-tokens). Le chiamate vengono effettuate direttamente all'URL del tuo sito.
- **OAuth 2.0 (consigliato)** — un consenso del browser una tantum; DefectDojo ottiene e rinnova i token per te.
- **Service Account Token** — un API Token con ambiti limitati creato per un [service account](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/) di Atlassian.

**Jira Data Center / Server**
- **Personal Access Token (consigliato)**
- **Username + Password**

> **Come l'autenticazione Cloud raggiunge Jira:** OAuth 2.0 e Service Account si autenticano entrambi come Bearer token contro il gateway di Atlassian — `https://api.atlassian.com/ex/jira/{cloudId}` — che è un *host diverso* dal tuo URL del sito `https://your-site.atlassian.net`. DefectDojo usa il gateway per ogni chiamata API, ma costruisce sempre il link del ticket mostrato su un Riscontro a partire dal tuo **URL del sito**, quindi il link su cui l'utente clicca è un normale link `.../browse/{ISSUE-KEY}` navigabile nel browser. (L'autenticazione API Token e Data Center chiama direttamente l'URL del sito, quindi non c'è questa distinzione.)

### Configurazione dell'istanza

- **Etichetta** deve corrispondere all'etichetta che vuoi usare per identificare questa integrazione.
- **Posizione** deve essere impostata sull'**URL del sito** Jira, ad esempio `https://your-organization.atlassian.net`. Viene usato per i link dei ticket navigabili nel browser e — per l'autenticazione API Token e Data Center — come URL di base dell'API.
- I campi restanti dipendono dal metodo scelto sopra (email + API token, credenziali client OAuth, token service-account, PAT, oppure username e password).

### Configurazione di OAuth 2.0 (Cloud)

Crea un'app dedicata nella [console sviluppatori di Atlassian](https://developer.atlassian.com/console/myapps/), quindi connettiti da DefectDojo.

1. Scegli **Create → OAuth 2.0 integration**. Deve essere una *OAuth 2.0 integration* — un'app Connect o Forge non può usare il grant authorization-code 3LO (otterresti `grant_type is not enabled for client`).
2. Quando richiesto per **Access type**, scegli **Resource-level**. Questo limita l'ambito del token al singolo sito Jira autorizzato dall'utente, che è esattamente ciò a cui punta una singola connessione DefectDojo. (**Account-level** concede l'accesso a tutti i siti dell'account Atlassian — un ambito più ampio del necessario.)
3. In **Permissions**, aggiungi la **Jira platform REST API** e concedi gli ambiti elencati di seguito. Nota: `offline_access` *non* è elencato qui — è un ambito OAuth standard che DefectDojo richiede nell'URL di autorizzazione, non qualcosa che aggiungi in questa schermata.
4. In **Authorization**, accanto a **OAuth 2.0 (3LO)** clicca **Configure** e imposta la **Callback URL** su `https://<your-defectdojo-host>/integrators/jira/oauth/callback` — deve corrispondere esattamente all'URL del sito DefectDojo. Abilitare questa opzione è ciò che attiva il grant authorization-code e i refresh token; saltare questo passaggio causa gli errori `grant_type is not enabled` / `Client is not allowed to use offline_access`.
5. Copia il **Client ID** e il **Client Secret** nel modulo di DefectDojo e clicca **Submit** per salvare la connessione.
6. Clicca **Connect with Jira** e approva la schermata di consenso. Atlassian reindirizza nuovamente a DefectDojo, che memorizza i token e risolve automaticamente il tuo `cloudId`. Quando l'operazione riesce, appare un indicatore "Connected".

> L'host di callback è il tuo `SITE_URL` di DefectDojo. Atlassian deve poter reindirizzare il browser a quell'indirizzo, e il valore deve corrispondere esattamente a quello inviato da DefectDojo — quindi usa il vero hostname con cui i tuoi utenti raggiungono DefectDojo, non un valore raggiungibile solo dall'interno della rete.

#### Ambiti OAuth minimi

Per impostazione predefinita, DefectDojo richiede questi quattro ambiti classici, che rappresentano anche il **minimo assoluto** richiesto — ciascuno supporta un comportamento specifico:

| Scope | Required for |
|-------|--------------|
| `read:jira-work` | Leggere il progetto, le issue e le transizioni disponibili (validazione della connessione e sincronizzazione dello status). |
| `write:jira-work` | Creare e modificare issue ed eseguire transizioni di status. |
| `read:jira-user` | Il controllo di identità della connessione — DefectDojo chiama `/myself` durante la convalida dell'accesso. |
| `offline_access` | Emettere un **refresh token**. Senza di esso il token di accesso scade (~1 ora dopo la connessione) e la connessione smette di funzionare, perché DefectDojo non può più rinnovarlo. |

Atlassian consiglia gli ambiti classici rispetto a quelli granulari; i quattro sopra indicati mantengono minimo l'ingombro dell'app e sono sufficienti per tutto ciò che fa l'integrazione.

##### Alternativa con ambiti granulari

Se la tua organizzazione richiede ambiti **granulari** invece di quelli classici, l'insieme minimo equivalente è:

| Granular scope | Required for |
|----------------|--------------|
| `read:user:jira` | Il controllo di identità `/myself`. |
| `read:project:jira` | Convalidare l'esistenza del progetto di destinazione. |
| `read:issue:jira` | Leggere lo status corrente di un'issue durante la sincronizzazione. |
| `write:issue:jira` | Creare e modificare issue **ed eseguire transizioni di status** — non esiste un ambito separato per la scrittura delle transizioni; una transizione è una scrittura sull'issue. |
| `read:issue.transition:jira` | Elencare le transizioni disponibili su un'issue. |
| `offline_access` | Il refresh token (come per gli ambiti classici). |

A seconda della configurazione dei campi del tuo sito, un endpoint potrebbe richiedere anche ambiti di lettura complementari per espandere i campi — più comunemente `read:status:jira` e `read:field:jira` (e `read:issue-meta:jira` per la creazione). Se un invio fallisce con un errore `403` "scope does not match", aggiungi l'ambito esatto indicato nell'errore. Questa proliferazione di ambiti complementari è esattamente il motivo per cui si consigliano gli ambiti classici.

Per il metodo **Service Account Token**, concedi al token `read:jira-work` e `write:jira-work` (più `read:jira-user`) — oppure gli equivalenti granulari sopra indicati, senza `offline_access`. `offline_access` non si applica — un token service-account è di lunga durata e non viene rinnovato da DefectDojo.

### Mappatura Issue Tracker

- **Chiave del Project**: la chiave del progetto Jira in cui creare le issue, ad esempio `SEC`.
- **Tipo di Issue**: il tipo di issue da creare, ad esempio `Bug` o `Task`. Il valore predefinito è `Bug`.

### Dettagli della mappatura Gravità

I valori predefiniti corrispondono allo schema di priorità predefinito di Jira. Modificali per farli corrispondere ai nomi di priorità nel tuo progetto:

- **Nome del campo Gravità**: `priority`
- **Mappatura Info**: `Lowest`
- **Mappatura Bassa**: `Low`
- **Mappatura Media**: `Medium`
- **Mappatura Alta**: `High`
- **Mappatura Critica**: `Highest`

### Dettagli della mappatura Stato

Gli status variano in base al workflow di ciascun progetto, quindi questi valori predefiniti sono pensati per essere modificati con i nomi di status del **tuo** workflow:

- **Nome del campo Stato**: `status`
- **Mappatura Attivo**: `To Do`
- **Mappatura Chiuso**: `Done`
- **Mappatura Falso positivo**: `Done`
- **Mappatura Rischio accettato**: `Done`

### Campi personalizzati (opzionale)

Puoi mappare campi Jira aggiuntivi — ad esempio un campo `resolution` obbligatorio alla chiusura, o `labels` — nel passaggio **Campi personalizzati** della mappatura. Ogni mappatura di campo personalizzato ha quattro parti:

- **Origine** — da dove proviene il valore: un attributo del **Riscontro**, del **Test**, dell'**Engagement** o dell'**Asset** che viene inviato, oppure un **Valore statico**.
- **Valore** — per un'origine di tipo oggetto, l'attributo specifico da leggere, scelto da un elenco dei campi di quell'oggetto con etichette leggibili (ad esempio *Gravità*, *CVE*, *Mitigazione*). Per un'origine di tipo **Valore statico**, questo è un campo di testo libero in cui digitare il valore letterale.
- **Campo del fornitore** — il campo Jira su cui scrivere. Poiché DefectDojo può leggere il catalogo dei campi di Jira, si tratta di un selettore con ricerca che elenca ciascun campo in base al suo **nome visualizzato** e lo risolve automaticamente nell'id interno per te — quindi selezioni *DD Close Justification* e DefectDojo memorizza `customfield_10255`. Il selettore viene popolato a partire dalla connessione, quindi funziona una volta che la connessione è stata salvata e convalidata.
- **Punto di applicazione** — *quando* inviare il campo: alla **creazione del ticket**, a **ogni aggiornamento**, oppure come parte di una specifica **transizione** di status (Attivo / Chiuso / Falso positivo / Rischio accettato). Un campo associato a una transizione viene inviato come parte della modifica di quella transizione — è così che fornisci un valore che Jira accetta solo in una schermata di transizione, più comunemente un `resolution` richiesto dal tuo workflow quando un'issue viene risolta.

### Modelli di ticket (opzionale)

Per impostazione predefinita, le issue di Jira usano il titolo e il corpo integrati di DefectDojo. Per personalizzarli, allega un **Modello di ticket** alla mappatura nel relativo passaggio **Modello di ticket**. Un modello definisce quattro elementi facoltativi in modo indipendente — il riepilogo e la descrizione del **Riscontro**, e il riepilogo e la descrizione del **Gruppo di Riscontri**. Ogni elemento lasciato vuoto ricade sul valore predefinito integrato, quindi puoi sovrascrivere solo il titolo, solo il corpo, oppure tutti e quattro. Usa **Test render** nell'editor del modello per visualizzare in anteprima l'output renderizzato su dati di esempio — individuando errori come placeholder sconosciuti o valori che superano il limite di lunghezza di un campo — prima di salvare. Se un modello viene successivamente eliminato, le mappature che lo usavano tornano automaticamente ai valori predefiniti integrati.

### Come funziona

- **Create / Update / Delete:** la creazione invia una nuova issue e registra il link sul Riscontro; l'aggiornamento modifica l'issue esistente; l'eliminazione di un Riscontro forza la chiusura della sua issue (in Jira non viene eliminato nulla). Gli invii possono essere manuali ("Push to Integrator") o automatici in base all'Issue Tracker Assignment.
- **Riconciliazione dello status:** dopo la creazione (e a ogni aggiornamento) DefectDojo legge lo status corrente dell'issue e, se differisce dall'obiettivo mappato, trova un'unica transizione di workflow che lo raggiunge e la applica. Se non esiste una transizione di questo tipo, la mappatura registra un errore invece di fallire silenziosamente. Eventuali campi personalizzati associati alla transizione vengono inviati insieme a quella transizione.
- **Link del ticket:** il link mostrato sul Riscontro è `https://your-site.atlassian.net/browse/{ISSUE-KEY}` — sempre l'URL pubblico del tuo sito, mai il gateway interno.
- **Ciclo di vita del token (OAuth):** DefectDojo gestisce l'intero flusso — esegue lo scambio authorization-code, memorizza i token di accesso e refresh, e li rinnova su richiesta prima di ogni invio, salvando il nuovo refresh token ogni volta (Atlassian lo ruota a ogni rinnovo).
- **Archiviazione delle credenziali:** tutte le credenziali di connessione (password, token, client secret, token OAuth) sono cifrate quando memorizzate e non vengono mai restituite tramite l'API — la modifica di una connessione mostra un placeholder "leave blank to keep" per i segreti memorizzati.

## Linear

L'integrazione con Linear consente di inviare i Riscontri di DefectDojo come Issue di [Linear](https://linear.app/). Le Issue vengono create in un Team nel tuo workspace Linear.

### Configurazione dell'istanza

- **Etichetta** deve corrispondere all'etichetta che vuoi usare per identificare questa integrazione.
- **Posizione** deve essere impostata su `https://api.linear.app/graphql`.
- **Chiave API** deve essere impostata su una chiave API personale di Linear. Le chiavi possono essere generate in Linear in Settings, poi Security & access, poi [API](https://linear.app/settings/account/security). La chiave viene inviata all'API GraphQL di Linear nell'header `Authorization`.

### Mappatura Issue Tracker

- **ID Team (Gruppo)** deve essere impostato sull'ID del Team Linear per cui verranno create le Issue. Puoi elencare i tuoi Team e i relativi ID chiamando l'API GraphQL di Linear:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Dettagli della mappatura Gravità

Una Issue di Linear ha una **priority** numerica invece di un campo di gravità. Ogni gravità di DefectDojo viene mappata su una priority di Linear, dove `1` è Urgent e `4` è Low:

- **Nome del campo Gravità**: `Priority`
- **Mappatura Info**: `4`
- **Mappatura Bassa**: `4`
- **Mappatura Media**: `3`
- **Mappatura Alta**: `2`
- **Mappatura Critica**: `1`

### Dettagli della mappatura Stato

Ogni valore di status deve essere impostato sull'ID di un Workflow State nel tuo Team Linear. Gli ID dei Workflow State sono univoci per ciascun workspace, quindi non esistono valori predefiniti. Puoi elencare i Workflow State e i relativi ID chiamando l'API GraphQL di Linear:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Nome del campo Stato**: `Workflow State ID`
- **Mappatura Attivo**: l'ID di uno stato avviato o non avviato, ad esempio `Todo` o `In Progress`.
- **Mappatura Chiuso**: l'ID di uno stato completato, ad esempio `Done`. Quando un Riscontro viene eliminato in DefectDojo, la sua Issue viene spostata in questo stato.

## Opsgenie

L'integrazione con Opsgenie consente di inviare i Riscontri e i Gruppi di Riscontri di DefectDojo come Alert di Opsgenie, indirizzati facoltativamente a un Team Opsgenie come responder.

### Configurazione dell'istanza

- **Etichetta** deve corrispondere all'etichetta che vuoi usare per identificare questa integrazione.
- **Posizione** deve essere impostata su `https://api.opsgenie.com`. Se il tuo account Opsgenie è ospitato nella regione di servizio UE, usa invece `https://api.eu.opsgenie.com`. Se i tuoi alert si trovano in Jira Service Management Operations (Atlassian sta integrando Opsgenie in JSM), usa `https://api.atlassian.com/jsm/ops/integration`.
- **Chiave API** deve essere impostata su una chiave di tipo **API integration** di Opsgenie. Un amministratore dell'account può crearne una nella web app di Opsgenie in **Settings > Integrations**: aggiungi un'integrazione di tipo **API** e assegnale *Create and Update Access* (e *Read Access* in modo che DefectDojo possa verificare la connessione). Nota che si tratta di una chiave di integrazione, non di una chiave API personale - DefectDojo si autentica con l'autorizzazione `GenieKey`, supportata solo dalle chiavi di integrazione.

### Mappatura Issue Tracker

- **Nome del Team** *(opzionale)* deve essere il nome del Team Opsgenie da aggiungere come responder sugli alert creati. Puoi lasciarlo vuoto: se la chiave API integration ha ambito limitato al team, gli alert vengono indirizzati automaticamente a quel team, altrimenti sono le regole di instradamento del tuo account a decidere i responder.

### Dettagli della mappatura Gravità

Le gravità vengono mappate sul campo **Priority** degli alert di Opsgenie, che utilizza la scala fissa di Opsgenie da `P1` (critica) a `P5` (informativa):

- **Nome del campo Gravità**: `Priority`
- **Mappatura Info**: `P5`
- **Mappatura Bassa**: `P4`
- **Mappatura Media**: `P3`
- **Mappatura Alta**: `P2`
- **Mappatura Critica**: `P1`

Se una gravità viene mappata su un valore non riconosciuto, la priority viene omessa e Opsgenie applica il proprio valore predefinito (`P3`).

### Dettagli della mappatura Stato

Gli alert di Opsgenie sono `open` o `closed`, e un alert aperto può inoltre essere `acknowledged`:

- **Nome del campo Stato**: `Status`
- **Mappatura Attivo**: `open`
- **Mappatura Chiuso**: `closed`
- **Mappatura Falso positivo**: `closed`
- **Mappatura Rischio accettato**: `acknowledged`

Nota che `closed` è uno status finale in Opsgenie - un alert chiuso non può essere riaperto, e il suo alias viene rilasciato. A differenza di altri strumenti, Opsgenie consente la modifica dei contenuti dopo la creazione, quindi l'invio di un Riscontro aggiornato sincronizza il suo messaggio, la descrizione e la priority insieme allo status.

DefectDojo imposta l'**alias** di ciascun alert su una chiave stabile derivata dal Riscontro o dal Gruppo di Riscontri, e Opsgenie deduplica gli alert aperti in base all'alias - quindi un nuovo invio dello stesso Riscontro aggiorna l'alert aperto esistente invece di crearne uno duplicato.

## PagerDuty

L'integrazione con PagerDuty consente di inviare i Riscontri e i Gruppi di Riscontri di DefectDojo come Incident di PagerDuty, aperti su un Service di PagerDuty a tua scelta.

### Configurazione dell'istanza

- **Etichetta** deve corrispondere all'etichetta che vuoi usare per identificare questa integrazione.
- **Posizione** deve essere impostata su `https://api.pagerduty.com`. Se il tuo account PagerDuty è ospitato nella regione di servizio UE, usa invece `https://api.eu.pagerduty.com`.
- **API Token** deve essere impostato su una chiave REST API di PagerDuty. Un amministratore dell'account può crearne una nella web app di PagerDuty in **Integrations > API Access Keys > Create New API Key**. Lascia deselezionato "Read-only" - DefectDojo deve poter creare e aggiornare gli incident.
- **Email mittente** deve essere l'indirizzo email di un utente valido del tuo account PagerDuty. PagerDuty richiede questo indirizzo quando crea o aggiorna gli incident, e verrà mostrato come richiedente dell'incident.

### Mappatura Issue Tracker

- **ID del Service** deve essere l'ID del Service di PagerDuty su cui verranno aperti gli incident. Puoi trovarlo alla fine dell'URL quando visualizzi il Service in PagerDuty, ad esempio `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`.

### Dettagli della mappatura Gravità

Per impostazione predefinita, questo campo viene mappato sul campo **Urgency** dell'incident di PagerDuty, che accetta solo `high` o `low`:

- **Nome del campo Gravità**: `Urgency`
- **Mappatura Info**: `low`
- **Mappatura Bassa**: `low`
- **Mappatura Media**: `low`
- **Mappatura Alta**: `high`
- **Mappatura Critica**: `high`

In alternativa, se il tuo account PagerDuty ha le [Priorities](https://support.pagerduty.com/main/docs/incident-priority) abilitate, puoi mappare le gravità sui nomi di Priority. Imposta **Nome del campo Gravità** su `Priority` e usa i nomi di Priority del tuo account (ad esempio da `P1` a `P5`) come valori di mappatura. Quando mappi su Priority, l'Urgency dell'incident viene lasciata alle regole di urgenza del tuo Service.

### Dettagli della mappatura Stato

Gli incident di PagerDuty hanno tre status: `triggered`, `acknowledged` e `resolved`.

- **Nome del campo Stato**: `Status`
- **Mappatura Attivo**: `triggered`
- **Mappatura Chiuso**: `resolved`
- **Mappatura Falso positivo**: `resolved`
- **Mappatura Rischio accettato**: `acknowledged`

Nota che `resolved` è uno status finale in PagerDuty - un incident risolto non può essere riaperto. Nota anche che PagerDuty non consente di modificare il titolo o la descrizione di un incident dopo la creazione, quindi l'invio di un Riscontro aggiornato sincronizzerà il suo status, l'urgency e la priority, ma non le modifiche ai contenuti.

## ServiceNow

L'integrazione ServiceNow consente di inviare i Riscontri di DefectDojo come Incident di ServiceNow.

### Configurazione dell'istanza

DefectDojo si autentica a ServiceNow tramite OAuth 2.0. Il modo in cui si creano le credenziali OAuth dipende dalla release di ServiceNow in uso: le release più recenti (Zurich e successive) utilizzano una concessione Client Credentials, mentre le release precedenti utilizzano un refresh token.

#### ServiceNow Zurich e versioni successive (client credentials)

Le release più recenti di ServiceNow hanno reso obsoleta l'opzione classica "Create an OAuth API endpoint for external clients" a favore della **New Inbound Integration Experience**, che rilascia una concessione OAuth **Client Credentials** legata a un account di servizio:

1. Nella barra di navigazione a sinistra, cercare "Application Registry" e selezionarlo.
2. Fare clic su **New**, quindi scegliere **New Inbound Integration Experience**.
3. Selezionare **New Integration → OAuth - Client credentials grant**.
4. Impostare **OAuth Application User** sull'account di servizio che creerà gli Incident. I ruoli di tale account determinano che cosa DefectDojo è autorizzato a scrivere.
5. Salvare la registrazione. ServiceNow genera automaticamente **Client ID** e **Client Secret** (lasciare vuoti questi campi durante la creazione della registrazione).

Quindi, in DefectDojo:

- **Instance Label** deve contenere l'etichetta che si desidera utilizzare per identificare questa integrazione.
- **Location** deve essere impostato sull'URL del server ServiceNow in uso, ad esempio `https://your-organization.service-now.com/`.
- **Client ID** deve corrispondere al Client ID ottenuto dalla registrazione OAuth.
- **Client Secret** deve corrispondere al Client Secret ottenuto dalla registrazione OAuth.

Lasciare vuoti i campi Refresh Token, Nome utente e Password: DefectDojo richiede un nuovo token client-credentials per ogni sincronizzazione.

#### Release precedenti di ServiceNow (refresh token)

Nelle release che offrono ancora la registrazione classica, ottenere un Refresh Token associato all'account utente o di servizio che invierà gli Incident a ServiceNow:

1. Nella barra di navigazione a sinistra, cercare "Application Registry" e selezionarlo.
2. Fare clic su "New".
3. Scegliere "Create an OAuth API endpoint for external clients".
4. Compilare i campi richiesti:
    * Name: fornire un nome significativo per l'applicazione (ad es. Vulnerability Integration Client).
    * (Facoltativo) Regolare il Token Lifespan:
    * Access Token Lifespan: il valore predefinito è 1800 secondi (30 minuti).
    * Refresh Token Lifespan: il valore predefinito è 8640000 secondi (circa 100 giorni).
5. Fare clic su Submit per creare il record dell'applicazione.
6. Dopo l'invio, selezionare l'applicazione dall'elenco e prendere nota dei campi **Client ID e Client Secret**.

Sarà quindi necessario utilizzare questa registrazione per ottenere un Refresh Token, che può essere ottenuto solo tramite l'API di ServiceNow.  Aprire una finestra di terminale e incollare quanto segue (sostituendo le variabili racchiuse tra `{{}}` con le informazioni effettive del proprio utente)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

Se le credenziali di ServiceNow sono corrette e consentono un accesso di livello amministrativo a ServiceNow, si dovrebbe ricevere una risposta contenente un RefreshToken.  Questo token sarà necessario per completare l'integrazione con DefectDojo.

- **Instance Label** deve contenere l'etichetta che si desidera utilizzare per identificare questa integrazione.
- **Location** deve essere impostato sull'URL del server ServiceNow in uso, ad esempio `https://your-organization.service-now.com/`.
- **Refresh Token** è il campo in cui inserire il Refresh Token.
- **Client ID** deve corrispondere al Client ID impostato nella OAuth App Registration.
- **Client Secret** deve corrispondere al Client Secret impostato nella OAuth App Registration.

### Dettagli della mappatura della gravità

Corrisponde al campo Impact di ServiceNow.
- **Mappatura Info**: `1`
- **Mappatura Bassa**: `1`
- **Mappatura Media**: `2`
- **Mappatura Alta**: `3`
- **Mappatura Critica**: `3`

### Dettagli della mappatura dello stato

- **Nome del campo Stato**: `State`
- **Mappatura Attivo**: `New`
- **Mappatura Chiuso**: `Closed`
- **Mappatura Falso positivo**: `Resolved`
- **Mappatura Rischio accettato**: `Resolved`

Ogni mappatura accetta un'etichetta di stato standard (`New`, `In Progress`, `On Hold`, `Resolved`, `Closed`, `Cancelled`) oppure un valore di stato numerico. Sulle istanze con stati Incident personalizzati, o quando si ha come destinazione una tabella diversa da `incident`, utilizzare il **valore di stato** numerico presente nell'elenco di scelta dell'istanza in uso; un valore numerico esterno all'insieme standard viene inviato a ServiceNow esattamente come configurato. Il valore predefinito del codice di risoluzione integrato accompagna solo gli stati risolto/chiuso standard, quindi è necessario abbinare i valori di stato personalizzati alle mappature dei campi di chiusura e risoluzione riportate di seguito.

### Campi di chiusura e risoluzione

Alcune istanze di ServiceNow applicano una Data Policy che rende obbligatori campi come il **codice di risoluzione** (`close_code`) ogni volta che un Incident passa a uno stato risolto o chiuso. Se DefectDojo chiude un Incident senza questi campi, ServiceNow rifiuta la scrittura con un HTTP 403 *"Data Policy Exception"* e il motivo viene registrato nella vista degli errori dell'integrazione.

Collegare i campi richiesti al cambiamento di stato tramite le **Custom Field Mappings**, impostando **Apply On** sulla disposizione che deve includerli:

- **Transizione a Chiuso** — inviato quando un Riscontro viene mitigato/chiuso.
- **Transizione a Falso positivo** — inviato quando un Riscontro viene contrassegnato come falso positivo.
- **Transizione a Rischio accettato** — inviato quando per un Riscontro viene accettato il rischio.

Ad esempio, per soddisfare un codice di risoluzione obbligatorio:

| Origine | Nome campo | Valore | Applica a |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transizione a Chiuso |
| Static | `close_notes` | `Reviewed by the security team` | Transizione a Chiuso |
| Static | `close_code` | `Not a defect` | Transizione a Falso positivo |

Note:

- Field Name è il nome della colonna in ServiceNow — `close_code`, `close_notes`, oppure un campo personalizzato `u_...`.
- Le mappature di transizione scattano quando lo stato del record cambia effettivamente: un Riscontro già chiuso al momento del primo invio, un aggiornamento che chiude o riapre il record, e la chiusura forzata quando un collegamento al ticket viene eliminato. Non vengono reinviate per aggiornamenti di routine su un record invariato, quindi i campi journal come `work_notes` ricevono una sola voce per transizione.
- I campi di riferimento come `assignment_group` e `assigned_to` richiedono un **sys_id**, non un nome visualizzato.
- I valori interpretabili come JSON vengono inviati con il proprio tipo: `true`, `42`, `[...]`, `{...}` — e `null`, che svuota il campo. Per inviare tale testo come stringa letterale, racchiuderlo tra virgolette doppie (ad es. `"null"`).
- `short_description`, `description`, `state`, `impact`, `urgency` e `priority` sono di competenza del modello di descrizione e delle mappature di gravità/stato, quindi non possono essere impostati tramite una mappatura di campo personalizzata.
- Sulle tabelle diverse da `incident`, i valori di stato che coincidono con l'insieme standard degli Incident (`1`, `2`, `3`, `6`, `7`, `8`) vengono comunque interpretati con la semantica degli Incident, incluso il valore predefinito automatico del codice di risoluzione su `6`/`7`/`8`. Su tabelle personalizzate, preferire valori di stato al di fuori di tale intervallo, oppure fornire esplicitamente i campi di chiusura come indicato sopra.

## ServiceNow SecOps

L'integrazione ServiceNow SecOps (nota anche come **ServiceNow SecOps / Vulnerability Response**) invia i Riscontri e i Gruppi di riscontri di DefectDojo in una tabella di sicurezza di ServiceNow — un **Security Incident** (`sn_si_incident`) o un **Vulnerable Item** (`sn_vul_vulnerable_item`) — e la mantiene sincronizzata man mano che il Riscontro cambia (creazione, aggiornamento e risoluzione/chiusura). È la controparte per le operazioni di sicurezza dell'integrazione ServiceNow come issue tracker descritta sopra; utilizzare ServiceNow SecOps quando si utilizzano le applicazioni Security Incident Response (SIR) o Vulnerability Response (VR).

### Configurazione dell'istanza

- **Instance Label** deve contenere l'etichetta che si desidera utilizzare per identificare questa integrazione.
- **Location** deve essere impostato sull'URL del server ServiceNow in uso, ad esempio `https://your-organization.service-now.com/`.

ServiceNow SecOps supporta tre metodi di autenticazione; fornirne **uno**:

- **OAuth 2.0** — inserire un **Client ID**, un **Client Secret** e un **Refresh Token**. Ottenerli esattamente come descritto nella sezione [ServiceNow](#servicenow) sopra (creare un endpoint API OAuth nell'Application Registry, quindi scambiare le proprie credenziali su `/oauth_token.do` per ottenere un refresh token). In alternativa, fornire **Client ID** e **Client Secret** insieme a **Nome utente** e **Password** per utilizzare la concessione OAuth con password invece del refresh token.
- **API Key** — inserire una **API Key**, inviata come header `x-sn-apikey`. La chiave non autentica nulla finché all'istanza non vengono associati un Inbound Authentication Profile e una REST API Access Policy.
- **HTTP Basic** — inserire **Nome utente** e **Password** dell'account di servizio.

L'account di servizio (o il client OAuth) necessita dell'accesso in scrittura alla tabella di destinazione.

### Mappatura Issue Tracker

- **Tabella di destinazione** seleziona la tabella di ServiceNow in cui vengono scritti i record: **Security Incident** (`sn_si_incident`, valore predefinito) oppure **Vulnerable Item** (`sn_vul_vulnerable_item`).

### Dettagli della mappatura della gravità

Per un Security Incident questo corrisponde al campo **Impact**; ServiceNow deriva la Priority dell'incident da Impact e Urgency, quindi Urgency rispecchia l'Impact mappato a meno che non venga mappata autonomamente. Per un Vulnerable Item, mappare la gravità sul campo di rischio utilizzato dall'istanza in uso. I valori predefiniti riportati di seguito corrispondono alla scala Impact SIR standard (`1` High, `2` Medium, `3` Low) e sono modificabili.

- **Nome del campo Gravità**: `impact`
- **Mappatura Info**: `3`
- **Mappatura Bassa**: `3`
- **Mappatura Media**: `2`
- **Mappatura Alta**: `1`
- **Mappatura Critica**: `1`

### Dettagli della mappatura dello stato

Corrisponde al campo **State** del record. I valori di State sono codici numerici che differiscono tra le tabelle Security Incident e Vulnerable Item e possono essere personalizzati per istanza, quindi verificarli rispetto alla propria configurazione. I valori predefiniti riportati di seguito utilizzano i codici di stato SIR standard (`16` Analysis, `3` Closed).

- **Nome del campo Stato**: `state`
- **Mappatura Attivo**: `16`
- **Mappatura Chiuso**: `3`
- **Mappatura Falso positivo**: `3`
- **Mappatura Rischio accettato**: `3`

Quando un record viene chiuso, DefectDojo imposta anche i campi ServiceNow **Close Code** e **Close Notes** (`Resolved` per i Riscontri chiusi, `False positive` e `Risk accepted` per gli stati corrispondenti).

### Comportamenti specifici di ServiceNow SecOps

- **Deduplicazione** — ogni record viene contrassegnato con l'identificativo DefectDojo del Riscontro o del Gruppo di riscontri nel proprio `correlation_id`. Prima di creare un record, DefectDojo ne cerca uno esistente tramite `correlation_id`; in caso di corrispondenza il record viene adottato e aggiornato anziché duplicato, rendendo le risincronizzazioni idempotenti.
- **Updates** vengono pubblicati nel journal **Work notes** del record (interno), mai nei Comments visibili al cliente.
- **Resolve on delete** — l'eliminazione di un Riscontro in DefectDojo risolve/chiude il record ServiceNow (State + Close Code) invece di eliminarlo; i record non vengono mai eliminati definitivamente.
- **Reference fields** — i valori facoltativi `cmdb_ci`, `assignment_group` e `assigned_to` possono essere forniti come nomi visualizzati; DefectDojo risolve ciascuno nel relativo `sys_id`. Un nome che non viene risolto viene scartato con un avviso anziché causare il fallimento dell'invio.

## Shortcut

L'integrazione Shortcut consente di inviare i Riscontri di DefectDojo come Story di [Shortcut](https://www.shortcut.com/). Le Story vengono create con il tipo Bug e assegnate a un Team nell'area di lavoro Shortcut in uso.

### Configurazione dell'istanza

- **Label** deve contenere l'etichetta che si desidera utilizzare per identificare questa integrazione.
- **Location** deve essere impostato su `https://api.app.shortcut.com`.
- **API Token** deve contenere un token API di Shortcut. I token possono essere generati in Shortcut in Settings, poi Your Account, poi [API Tokens](https://app.shortcut.com/settings/account/api-tokens).

### Mappatura Issue Tracker

- **ID Team (Gruppo)** deve essere impostato sull'UUID del Team di Shortcut per cui verranno create le Story. È possibile trovare questo UUID aprendo la pagina del Team in Shortcut e copiando l'identificativo dall'URL, oppure richiamando l'API di Shortcut:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### Dettagli della mappatura della gravità

Ogni valore di gravità viene applicato alla Story come label. Le label vengono create automaticamente in Shortcut se non esistono già, quindi i valori predefiniti riportati di seguito possono essere utilizzati così come sono, oppure sostituiti con nomi di label a scelta. Quando la gravità di un Riscontro cambia, la vecchia label di gravità viene rimossa dalla Story e ne viene aggiunta una nuova.

- **Nome del campo Gravità**: `Label`
- **Mappatura Info**: `sev-info`
- **Mappatura Bassa**: `sev-low`
- **Mappatura Media**: `sev-medium`
- **Mappatura Alta**: `sev-high`
- **Mappatura Critica**: `sev-critical`

### Dettagli della mappatura dello stato

Ogni valore di stato deve essere impostato sull'ID numerico di un Workflow State nell'area di lavoro Shortcut in uso. Gli ID dei Workflow State sono univoci per ciascuna area di lavoro, quindi non esistono valori predefiniti. È possibile elencare i Workflow State e i relativi ID richiamando l'API di Shortcut:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **Nome del campo Stato**: `Workflow State ID`
- **Mappatura Attivo**: l'ID dello stato per il lavoro aperto, ad esempio uno stato Backlog o To Do.
- **Mappatura Chiuso**: l'ID di uno stato di tipo Done. Quando un Riscontro viene eliminato in DefectDojo, la relativa Story viene spostata in questo stato.
- **Mappatura Falso positivo**: l'ID dello stato da utilizzare per i Riscontri contrassegnati come Falso positivo.
- **Mappatura Rischio accettato**: l'ID dello stato da utilizzare per i Riscontri con Rischio accettato.

## Freshservice

L'integrazione Freshservice consente di inviare i Riscontri e i Gruppi di riscontri di DefectDojo come ticket di Freshservice, assegnati a un Gruppo di agenti a scelta.

### Configurazione dell'istanza

- **Label** deve contenere l'etichetta che si desidera utilizzare per identificare questa integrazione.
- **Location** deve essere impostato sull'URL di Freshservice in uso: `https://yourcompany.freshservice.com`.
- **API Key** deve contenere una chiave API di Freshservice.  È possibile trovarla facendo clic sulla propria immagine del profilo (in alto a destra) > **Profile settings** - la chiave appare a destra, sotto la sezione **Delegate Approvals**, dopo aver completato il captcha.  Se lì non compare alcuna chiave, l'accesso alle API potrebbe essere disabilitato a livello di account ed è necessario che un amministratore lo abiliti prima.
- **Requester Email** deve contenere l'indirizzo email per conto del quale vengono richiesti i ticket.  Freshservice richiede un richiedente per ogni ticket, quindi DefectDojo crea i ticket utilizzando questo indirizzo come richiedente.

### Mappatura Issue Tracker

- **ID gruppo** deve contenere l'ID numerico del gruppo di agenti Freshservice a cui verranno assegnati i ticket.  È possibile trovarlo nell'URL visualizzando il gruppo in **Admin > Agent Groups**.
- **ID area di lavoro** (facoltativo) instrada i ticket verso un'area di lavoro specifica sugli account multi-workspace.  Lasciarlo vuoto per utilizzare l'area di lavoro principale.

### Dettagli della mappatura della gravità

Corrisponde al campo **Priority** del ticket Freshservice, che utilizza codici numerici (`1` Low, `2` Medium, `3` High, `4` Urgent).  Sono accettati anche i nomi delle priorità:

- **Nome del campo Gravità**: `Priority`
- **Mappatura Info**: `1`
- **Mappatura Bassa**: `1`
- **Mappatura Media**: `2`
- **Mappatura Alta**: `3`
- **Mappatura Critica**: `4`

### Dettagli della mappatura dello stato

Corrisponde al campo **Status** del ticket, che utilizza codici numerici (`2` Open, `3` Pending, `4` Resolved, `5` Closed).  Sono accettati anche i nomi degli stati:

- **Nome del campo Stato**: `Status`
- **Mappatura Attivo**: `2`
- **Mappatura Chiuso**: `5`
- **Mappatura Falso positivo**: `5`
- **Mappatura Rischio accettato**: `3`

Alcuni comportamenti specifici di Freshservice da tenere presenti:

- Gli aggiornamenti sincronizzano l'intero contenuto del ticket - Freshservice consente di modificare oggetto e descrizione dopo la creazione.
- I ticket vengono chiusi anziché eliminati quando un Riscontro viene rimosso; i ticket già Resolved o Closed non vengono modificati.  Alla chiusura viene allegata automaticamente una nota di risoluzione, quindi gli account che ne richiedono una (una regola aziendale comune) accettano la chiusura.
- Alcuni account calcolano la priorità di un ticket a partire da una matrice Impact/Urgency o da una regola aziendale, ignorando la priorità inviata alla creazione.  DefectDojo rileva questa situazione e riapplica la priorità mappata con un aggiornamento successivo, in modo che la mappatura abbia comunque effetto.

## ServiceDesk Plus

L'integrazione ManageEngine ServiceDesk Plus consente di inviare i Riscontri e i Gruppi di riscontri di DefectDojo come richieste di ServiceDesk Plus, assegnate a un Gruppo di supporto a scelta.  La stessa integrazione supporta sia l'edizione **cloud** (ServiceDesk Plus OnDemand) sia quella **on-premises** - le credenziali fornite determinano quale modalità viene utilizzata.

### Configurazione dell'istanza

- **Label** deve contenere l'etichetta che si desidera utilizzare per identificare questa integrazione.
- **Location** deve essere impostato sull'URL di ServiceDesk Plus in uso: `https://sdpondemand.manageengine.com` per l'edizione cloud (o l'equivalente regionale), oppure l'indirizzo del proprio server per le installazioni on-premises.

Fornire quindi **uno** dei due set di credenziali:

#### On-premises: Chiave del tecnico

- **Chiave del tecnico** deve contenere una chiave API generata per un tecnico sul server in uso, in **Admin > General Settings > API**.  Lasciare vuoti i campi Zoho OAuth.

#### Cloud: Zoho OAuth

L'edizione cloud si autentica tramite Zoho Accounts OAuth:

1. Aprire la [Zoho API Console](https://api-console.zoho.com/) e creare un **Self Client**.
2. Annotare **Client ID** e **Client Secret**.
3. Nella scheda "Generate Code" del Self Client, inserire lo scope `SDPOnDemand.requests.ALL`, scegliere una durata e generare il codice.
4. Scambiare il codice per ottenere un refresh token:

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. Inserire **Client ID**, **Client Secret** e il **Refresh Token** restituito nel modulo dell'istanza.  Se l'account è ospitato al di fuori del data center statunitense, impostare **Token URL** sull'endpoint regionale di Zoho Accounts (ad esempio `https://accounts.zoho.eu/oauth/v2/token`).

### Mappatura Issue Tracker

- **Nome del gruppo** deve contenere il nome del gruppo di supporto di ServiceDesk Plus a cui verranno assegnate le richieste, esattamente come appare in **Admin > Users > Support Groups**.

### Dettagli della mappatura della gravità

Corrisponde al campo **Priority** della richiesta ServiceDesk Plus per nome, utilizzando i nomi di priorità dell'account in uso:

- **Nome del campo Gravità**: `Priority`
- **Mappatura Info**: `Low`
- **Mappatura Bassa**: `Normal`
- **Mappatura Media**: `Medium`
- **Mappatura Alta**: `High`
- **Mappatura Critica**: `High`

### Dettagli della mappatura dello stato

Corrisponde al campo **Status** della richiesta per nome.  I valori predefiniti utilizzano gli stati integrati:

- **Nome del campo Stato**: `Status`
- **Mappatura Attivo**: `Open`
- **Mappatura Chiuso**: `Closed`
- **Mappatura Falso positivo**: `Closed`
- **Mappatura Rischio accettato**: `On Hold`

Alcuni comportamenti specifici di ServiceDesk Plus da tenere presenti:

- Gli aggiornamenti sincronizzano l'intero contenuto della richiesta - a differenza della maggior parte dei tracker, ServiceDesk Plus consente di modificare oggetto e descrizione dopo la creazione.
- Le richieste vengono chiuse anziché eliminate quando un Riscontro viene rimosso; le richieste già Closed o Resolved non vengono modificate.
- Se l'account in uso rende obbligatori alcuni campi alla chiusura (ad esempio una risoluzione), una chiusura inviata da DefectDojo potrebbe essere rifiutata da tali regole e comparirà nella tabella degli errori dell'integrazione.

## Zendesk

L'integrazione Zendesk consente di inviare i Riscontri e i Gruppi di riscontri di DefectDojo come ticket di Zendesk, assegnati a un Gruppo Zendesk a scelta.

### Configurazione dell'istanza

- **Label** deve contenere l'etichetta che si desidera utilizzare per identificare questa integrazione.
- **Location** deve essere impostato sull'URL dell'account Zendesk in uso, ad esempio `https://your-subdomain.zendesk.com`.
- **Email** deve contenere l'indirizzo email dell'agente Zendesk a cui appartiene il token API.
- **API Token** deve contenere un token API di Zendesk.  Un amministratore può crearne uno nello Zendesk Admin Center in **Apps and integrations > APIs > Zendesk API** (l'accesso tramite token deve essere abilitato).

### Mappatura Issue Tracker

- **ID gruppo** deve contenere l'ID numerico del Gruppo Zendesk a cui verranno assegnati i ticket.  È possibile trovarlo nell'Admin Center in **People > Team > Groups**, oppure nell'URL durante la visualizzazione del gruppo.

### Dettagli della mappatura della gravità

Corrisponde al campo **Priority** del ticket Zendesk, che accetta `low`, `normal`, `high` e `urgent`:

- **Nome del campo Gravità**: `Priority`
- **Mappatura Info**: `low`
- **Mappatura Bassa**: `low`
- **Mappatura Media**: `normal`
- **Mappatura Alta**: `high`
- **Mappatura Critica**: `urgent`

### Dettagli della mappatura dello stato

I ticket Zendesk supportano gli stati `new`, `open`, `pending`, `hold`, `solved` e `closed`.  Da notare che `hold` deve essere abilitato sull'account prima di poter essere utilizzato.

- **Nome del campo Stato**: `Status`
- **Mappatura Attivo**: `new`
- **Mappatura Chiuso**: `solved`
- **Mappatura Falso positivo**: `solved`
- **Mappatura Rischio accettato**: `pending`

Alcuni comportamenti specifici di Zendesk da tenere presenti:

- La descrizione del ticket è il primo commento in Zendesk e non può essere modificata dopo la creazione, quindi l'invio di un Riscontro aggiornato sincronizzerà l'oggetto, la priorità e lo stato del ticket, ma non le modifiche alla descrizione.
- I ticket vengono contrassegnati come `solved` anziché eliminati quando un Riscontro viene rimosso; Zendesk chiude automaticamente i ticket risolti dopo un certo periodo di tempo.
- `closed` è uno stato finale - i ticket chiusi non possono essere aggiornati in alcun modo, e l'invio di un Riscontro il cui ticket è stato chiuso genererà un errore.
