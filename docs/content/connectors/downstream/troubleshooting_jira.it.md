---
title: Risoluzione dei problemi con Jira (Legacy)
description: Risolvere i problemi con l'integrazione di Jira
weight: 2
aliases:
- /it/issue_tracking/jira/troubleshooting_jira/
- /it/en/share_your_findings/troubleshooting_jira/
---

Ecco alcuni problemi comuni con l'integrazione di Jira e i modi per risolverli.

## Non riesco a trovare nessuna impostazione di Jira in DefectDojo

Se non c'è alcun menu Jira nella barra laterale, nessuna sezione Jira nei moduli Prodotto / Engagement e nessuna opzione **Push to Jira** sui Riscontri, è molto probabile che l'integrazione di Jira sia ancora disabilitata nelle Impostazioni di Sistema.  DefectDojo nasconde ogni controllo relativo a Jira finché non viene attivato.

Controlla **Enable Jira Integration** nella pagina delle Impostazioni di Sistema:

* Open Source: ⚙️ **Configuration \> System Settings**, poi seleziona **Enable JIRA integration**.  È richiesto anche un **Jira webhook secret** prima che il modulo possa essere salvato, quindi fai clic sull'icona 🔄 per generarne uno.  Consulta la [Guida all'integrazione di Jira](/connectors/os_jira/os__jira_guide/#step-1-enable-the-jira-integration-in-system-settings).
* Pro: **\<Your Edition\> Settings \> System Settings**, poi seleziona **Enable Jira Integration** in **Jira Integration Settings**.  Consulta la [Guida all'integrazione di Jira](/connectors/downstream/pro__jira_guide/#step-1-enable-the-jira-integration-in-system-settings).

Se l'impostazione è già abilitata e continui a non vedere il menu Jira, al tuo utente potrebbe mancare il permesso di configurazione **View Jira Instance**, anch'esso necessario perché il menu compaia.  Può essere assegnato direttamente nella pagina Utente o tramite un Gruppo di Utenti.  Consulta [Informazioni su permessi e ruoli](/admin/user_management/about_perms_and_roles/#configuration-permissions).

## DefectDojo non riesce a raggiungere Jira (o altri servizi in uscita)

Se l'integrazione Jira di DefectDojo fallisce con errori di connessione del tipo "connection refused", "no route to host" o generici fallimenti dell'handshake TLS — e le credenziali stesse sono valide — la tua istanza DefectDojo potrebbe trovarsi dietro un firewall che richiede che il traffico in uscita passi attraverso un proxy HTTPS in avanti (forward proxy).

Per i deployment Pro on-prem, imposta le variabili d'ambiente `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` sul deployment.  `dojo-compose-cli` le propaga automaticamente ai container `uwsgi`, `celeryworker` e Connector.  Consulta [Eseguire DefectDojo dietro un forward HTTPS proxy](/onprem_deployment/forward_proxy/) per la procedura completa di configurazione.

> Nota: impostare `HTTPS_PROXY` configura solo il traffico **in uscita** da DefectDojo.  Non influisce sulla capacità di Jira di inviare webhook **in entrata** verso DefectDojo — per quel caso consulta [Le modifiche apportate ai ticket Jira non aggiornano i Riscontri in DefectDojo](#changes-made-to-jira-issues-are-not-updating-findings-in-defectdojo) più avanti.

## Impossibile configurare Jira in DefectDojo a causa di errori 404, 401 o 403
Jira Cloud:
- Consulta la documentazione delle API REST di Jira Cloud sull'autenticazione: https://developer.atlassian.com/cloud/jira/software/basic-auth-for-rest-apis/
- Verifica da riga di comando che le credenziali fornite possano accedere ai ticket necessari in Jira:

```
curl -D- \
   -u <emailaddress>:<personal_access_token> \
   -X GET \
   -H "Content-Type: application/json" \
   https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Ad esempio:
```
curl -D- \
   -u defectdojo@example.com:ATATT1234567890abcdefghijklmnopqrstuvwxyz \
   -X GET \
   -H "Content-Type: application/json" \
   https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Jira Data Center o Server:
- Consulta la documentazione delle API REST di Jira Data Center sull'autenticazione:
    - https://developer.atlassian.com/server/jira/platform/basic-authentication/ (nome utente + password)
    - https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html (token di accesso personale)
- Verifica da riga di comando che le credenziali fornite possano accedere ai ticket necessari in Jira:

```
curl -u username:password -X GET -H "Content-Type: application/json" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Ad esempio:
```
curl -u defectdojo@example.com:123456 -X GET -H "Content-Type: application/json" https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Quando si usano token di accesso personali:
```
curl -H "Authorization: Bearer <personal_access_token>" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Ad esempio:
```
curl -H "Authorization: Bearer ATATT1234567890abcdefghijklmnopqrstuvwxyz" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

## Gli account di servizio Jira non sono supportati

Gli account di servizio (Service Account) di Jira Cloud (creati tramite la console di amministrazione di Atlassian) utilizzano un host API diverso rispetto agli account utente standard e **non sono attualmente supportati** dall'integrazione Jira di DefectDojo. Il tentativo di utilizzare un token API di un account di servizio o credenziali OAuth 2.0 provenienti da un account di servizio comporterà errori HTTP 403.

Per configurare l'integrazione con Jira, crea un account utente Jira standard (con un indirizzo email valido) e genera un token API da tale account. Se vuoi identificare chiaramente i ticket creati da DefectDojo, crea un utente dedicato con un nome come "DefectDojo" e usa il suo token API per l'integrazione.

## Non riesco a trovare un Epic Name ID per il mio Space
Alcuni Space in Jira, come gli Space Team-Managed, non usano gli Epic e quindi non avranno un Epic Name ID.  In questo caso, imposta Epic Name ID a 0 in DefectDojo.

## I Riscontri che invio con 'Push To Jira' non compaiono in Jira
L'uso del flusso 'Push To Jira' avvia un processo asincrono; tuttavia un ticket dovrebbe essere creato in Jira abbastanza rapidamente dopo l'attivazione di 'Push To Jira'.

* Controlla le notifiche di DefectDojo per verificare se il processo è andato a buon fine.  Se il push fallisce, riceverai una risposta di errore da Jira nelle tue notifiche.

Motivi comuni per cui i ticket non vengono creati:
* Il Default Issue Type selezionato non è utilizzabile con lo Space Jira
* I ticket nello Space hanno attributi obbligatori che ne impediscono la creazione tramite DefectDojo (gestibili tramite i Custom Field in Jira)


## Errore: Product Misconfigured o mancanza di permessi in Jira?

Questo messaggio di errore può comparire quando si tenta di aggiungere una configurazione Jira creata a un Prodotto.  DefectDojo tenterà di validare una connessione a Jira e, se tale connessione fallisce, genererà questo messaggio di errore.

* Verifica che le tue credenziali Jira siano autorizzate a creare ticket nello Space Jira selezionato.
* Il campo "Project Key" deve essere uno Space Jira valido. I ticket Jira possono usare Chiavi diverse all'interno di un singolo Space; il modo più semplice per confermare la tua Project Key è guardare l'URL di quello specifico Space Jira: in genere avrà un aspetto simile a `https://xyz.atlassian.net/jira/core/projects/JTV/board`.  In questo caso `JTV` è la Space Key.

## Le modifiche apportate ai ticket Jira non aggiornano i Riscontri in DefectDojo

* Inizia confermando che il ricevitore webhook di DefectDojo sia configurato correttamente e possa ricevere correttamente gli aggiornamenti.

* Assicurati che il certificato SSL usato da Defect Dojo sia considerato attendibile da JIRA. Per JIRA Cloud devi usare [un certificato SSL/TLS valido, firmato da un'autorità di certificazione globalmente affidabile](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

* Se stai cercando di inviare cambi di stato, conferma che le mappature delle transizioni Jira siano configurate correttamente (Reopen / Close Transition IDs).

* [Testa](https://support.atlassian.com/jira/kb/testing-webhooks-in-jira-cloud/) il tuo webhook JIRA usando un endpoint pubblico come Pipedream o Beeceptor:

* Conferma che il Riscontro sia effettivamente collegato al ticket Jira. Se il ticket non è collegato a un Riscontro DefectDojo, la richiesta webhook viene comunque accettata (HTTP `200`) ma nessun Riscontro viene aggiornato.

* Ricorda che l'endpoint **restituisce sempre HTTP `200`**, indipendentemente dal fatto che un aggiornamento sia stato applicato o meno. Un `200` sul lato mittente (un webhook di sistema o una regola di Jira Automation) non conferma che la modifica abbia raggiunto un Riscontro — controlla il corpo della risposta e i log di DefectDojo per vedere l'esito effettivo.

* Se stai usando **Jira Automation** (*Send web request*) invece di un webhook di sistema, controlla quanto segue:
    * Il **Body** della richiesta è impostato su **Custom data** e include un `webhookEvent` di primo livello pari a `"jira:issue_updated"` oppure `"comment_created"`. Le opzioni body **Empty** e **Jira issue data** omettono questo campo, e DefectDojo ignora qualsiasi richiesta il cui `webhookEvent` non riconosce.
    * `Content-Type: application/json` è impostato sulla richiesta — DefectDojo rifiuta qualsiasi altro content type.
    * Per gli aggiornamenti dei ticket, `issue.id` è l'ID **numerico** del ticket Jira (`{{issue.id}}`), non la issue key, ed entrambi i campi `resolution` e `updated` sono presenti (`resolution` può essere `null`). L'assenza di `resolution`/`updated` fa sì che la richiesta venga scartata silenziosamente.
    * Per i commenti, l'URL `comment.self` contiene l'`{{issue.id}}` numerico nel segmento `.../issue/<id>/comment/...`, e sono presenti sia `body` che `updateAuthor`.
    * Se i commenti non compaiono, controlla la **prevenzione dei loop**: DefectDojo salta un commento quando il suo autore corrisponde all'account Jira che DefectDojo usa per pubblicare i commenti. Esegui la regola di Automation come un utente Jira diverso se vuoi che quei commenti vengano acquisiti.
    * Usa l'anteprima del payload di Automation per confermare che gli smart value vengano risolti come previsto — i loro nomi possono variare tra le istanze Jira.

## Gli Epic di Jira non vengono creati

`"Field 'customfield_xyz' cannot be set. It is not on the appropriate screen, or unknown."`

L'integrazione Jira di DefectDojo richiede un valore customfield per 'Epic Name'.  Tuttavia, le impostazioni del tuo Progetto potrebbero non usare effettivamente 'Epic Name' come campo durante la creazione degli Epic.  Atlassian ha introdotto una modifica ad [agosto 2023](https://community.atlassian.com/t5/Jira-articles/Upcoming-changes-to-epic-fields-in-company-managed-projects/ba-p/1997562) che ha unito i campi 'Epic Name' ed 'Epic Summary'.

Gli Space Jira più recenti potrebbero non usare questo campo per impostazione predefinita quando creano gli Epic, il che genera questo messaggio di errore.

Per correggere questo problema, puoi aggiungere il campo 'Epic Name' alla schermata di creazione dei ticket del tuo Progetto:

1. Prova a creare un Epic in Jira manualmente (tramite l'interfaccia utente di Jira).
2. Apri il menu "..."
3. Fai clic su 'Find Your Field'
4. Digita 'Epic Name'
5. Aggiungi Epic Name come campo a questa schermata specifica seguendo le istruzioni di Jira.

![image](images/epic_name_error.png)

## Configurazione dei tentativi e dei timeout di connessione JIRA

L'integrazione JIRA di DefectDojo include impostazioni configurabili di tentativi e timeout per gestire il rate limiting e i problemi di connessione. Queste impostazioni sono importanti per mantenere la reattività del sistema, specialmente quando si usano worker Celery.

### Variabili di configurazione disponibili

Le seguenti variabili d'ambiente controllano il comportamento della connessione JIRA:

- **`DD_JIRA_MAX_RETRIES`** (predefinito: `3`): Numero massimo di tentativi per errori recuperabili. L'integrazione riprova automaticamente su HTTP 429 (Too Many Requests), HTTP 503 (Service Unavailable) ed errori di connessione. Consulta la [documentazione sul rate limiting di JIRA](https://developer.atlassian.com/cloud/jira/platform/rate-limiting/) per maggiori informazioni.

- **`DD_JIRA_CONNECT_TIMEOUT`** (predefinito: `10` secondi): Timeout di connessione per stabilire una connessione al server JIRA.

- **`DD_JIRA_READ_TIMEOUT`** (predefinito: `30` secondi): Timeout di lettura per attendere una risposta dal server JIRA dopo che la connessione è stata stabilita.

**Nota sul rate limiting**: la libreria jira ha un tempo massimo di attesa integrato di 60 secondi per i tentativi legati al rate limiting. Se l'header `Retry-After` di JIRA indica un tempo di attesa superiore a 60 secondi, la richiesta fallirà e non verrà ritentata. Questa è una limitazione della versione della libreria jira attualmente in uso.

### Perché i valori conservativi sono importanti

**Importante**: si raccomanda di usare valori conservativi (più bassi) per queste impostazioni. Ecco perché:

1. **Blocco dei task Celery**: le operazioni JIRA in DefectDojo vengono eseguite come task Celery asincroni. Quando un task è in attesa di un ritardo di ritentativo, blocca quel worker Celery dall'elaborare altri task.

2. **Esaurimento del pool di worker**: se più operazioni JIRA stanno ritentando con ritardi lunghi, puoi esaurire rapidamente il tuo pool di worker Celery, causando l'accodamento e l'attesa di altri task (non solo quelli legati a JIRA).

3. **Reattività del sistema**: ritardi di ritentativo lunghi possono far apparire il sistema non reattivo, specialmente durante interruzioni di JIRA o eventi di rate limiting.

Il rate limiting JIRA è una funzionalità recente, quindi facci sapere su Slack o GitHub cosa funziona meglio per te.

## Jira e DefectDojo non sono sincronizzati

A volte Jira è inattivo, oppure DefectDojo è inattivo, oppure si è verificato un bug in un webhook. In questo caso, Jira può disallinearsi rispetto a DefectDojo. Se questo accade per molti ticket, la riconciliazione manuale potrebbe non essere fattibile. Per questo scenario esiste il comando di gestione 'jira_status_reconciliation'.

Poiché questo comando richiede accesso al backend, non è disponibile per gli utenti Cloud di DefectDojo Pro; in tal caso, contatta il nostro team di Supporto per assistenza su questo problema.

{{< highlight bash >}}
usage: manage.py jira_status_reconciliation [-h] [--mode MODE] [--product PRODUCT] [--engagement ENGAGEMENT] [--dryrun] [--version] [-v {0,1,2,3}]

Reconcile finding status with JIRA issue status, stdout will contain semicolon seperated CSV results.
Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped.

optional arguments:
  -h, --help            show this help message and exit
  --mode MODE           - reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change
                        timestamp in both systems to determine which one is the correct status
                        - push_status_to_jira: update JIRA status for all JIRA issues
                        connected to a Defect Dojo finding (will not push summary/description, only status)
                        - import_status_from_jira: update Defect Dojo
                        finding status from JIRA
  --product PRODUCT     Only process findings in this product (name)
  --engagement ENGAGEMENT
                        Only process findings in this product (name)
  --dryrun              Only print actions to be performed, but make no modifications.
  -v {0,1,2,3}, --verbosity {0,1,2,3}
                        Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, 3=very verbose output
{{< /highlight >}}

Questo può essere eseguito dal container docker uwsgi usando:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation'
{{< /highlight >}}

L'output di DEBUG può essere ottenuto tramite `-v 3`, ma solo dopo aver aumentato il livello di logging a DEBUG nel tuo file settings.dist.py o local_settings.py

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation -v 3'
{{< /highlight >}}

Alla fine del comando verrà stampato un riepilogo CSV separato da punto e virgola. Questo può essere catturato reindirizzando lo stdout su un file:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation > jira_reconciliation.csv'
{{< /highlight >}}
