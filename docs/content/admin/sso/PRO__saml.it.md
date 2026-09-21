---
title: Configurazione SAML
description: Configura SAML in DefectDojo Pro
weight: 1
audience: pro
---

DefectDojo Pro supporta l'autenticazione SAML tramite l'interfaccia **Enterprise Settings**. DefectDojo open source non include il SSO — consulta [Utenti autorizzati](/admin/user_management/os__authorized_users/) per il controllo degli accessi in open source.

## URL ACS (Assertion Consumer Service)

Il tuo Identity Provider deve sapere dove effettuare il POST della risposta SAML dopo l'autenticazione di un utente. L'URL ACS di DefectDojo è:

```
https://<your-instance>.cloud.defectdojo.com/saml2/acs/
```

Alcune cose da sapere su questo endpoint:

- **L'endpoint accetta solo richieste `POST`.** Aprire l'URL ACS direttamente in un browser genera una richiesta GET e restituisce un **HTTP 405 Method Not Allowed**. Si tratta di un comportamento previsto — non significa che SAML sia rotto o mal configurato. L'endpoint è pensato per essere invocato dal tuo IdP come parte del flusso di redirect SAML, non digitando l'URL in un browser.
- **L'URL ACS è sempre disponibile sulla tua istanza DefectDojo Cloud** — non è necessario abilitare prima SAML in DefectDojo per poterlo indicare al tuo IdP. Puoi configurare il lato IdP e il lato DefectDojo nell'ordine che preferisci.

## Configurazione

1. Apri **Enterprise Settings > SAML Settings**.

   ![image](images/sso_betaui_1.png)

2. Imposta un **Entity ID** — un'etichetta o un URL che il tuo SAML Identity Provider utilizza per identificare DefectDojo. Questo campo è obbligatorio.

3. Facoltativamente, imposta **Login Button Text** — il testo mostrato sul pulsante che gli utenti cliccano per avviare l'accesso SAML.

4. Facoltativamente, imposta un **Logout URL** verso cui reindirizzare gli utenti dopo che escono da DefectDojo.

5. Scegli un **Name ID Format**:
   - **Persistent** — gli utenti vengono identificati in modo coerente tramite SAML tra una sessione e l'altra.
   - **Transient** — gli utenti ricevono un ID SAML diverso a ogni accesso.
   - **Entity** — tutti gli utenti condividono un unico NameID SAML.
   - **Encrypted** — il NameID di ciascun utente è crittografato.

6. **Required Attributes** — specifica gli attributi che DefectDojo richiede dalla risposta SAML.

7. **Attribute Mapping** — associa gli attributi inviati dal tuo IdP ai campi utente di DefectDojo che devono popolare. Ogni riga abbina un **SAML Attribute** a un **DefectDojo Field**; usa **Add Attribute Mapping** per aggiungere altre righe e l'icona del cestino per rimuoverne una.

   ![image](images/sso_saml_attribute_mapping.png)

   - **SAML Attribute** è testo libero e deve corrispondere al nome dell'attributo effettivamente emesso dal tuo IdP. Alcuni IdP (ad esempio Entra ID / Azure AD) inviano URI di claim completamente qualificati, come `http://schemas.microsoft.com/identity/claims/emailaddress`, anziché nomi semplici. Se non sei sicuro di cosa invii il tuo IdP, abilita **Enable SAML Debugging** (vedi [Risoluzione dei problemi](#troubleshooting)) e ispeziona l'asserzione nei log.
   - **DefectDojo Field** si sceglie da un elenco: **Username**, **First Name**, **Last Name** e **Email**.
   - Come minimo, associa l'attributo corrispondente a **Username**. DefectDojo cerca gli utenti in base allo username quando abbina gli accessi SAML agli account esistenti.
   - Si consiglia vivamente di associare un attributo a **Email**: DefectDojo utilizza l'indirizzo email per le notifiche e per abbinare un accesso in entrata a un account esistente in base all'email.
   - Lo stesso attributo può alimentare più di un campo — ad esempio un claim email usato sia per **Email** sia per **Username**. Il contrario non è consentito: ogni campo di DefectDojo può essere mappato da un solo attributo.
   - Una riga con solo una metà compilata viene rifiutata al salvataggio e la cella incriminata viene evidenziata. Le righe aggiunte ma mai compilate vengono scartate anziché essere trattate come errori.

8. **Remote SAML Metadata** — l'URL in cui è ospitato il metadata del tuo SAML Identity Provider.

9. Seleziona **Enable SAML** in fondo al modulo per attivare l'accesso SAML. Nella pagina di accesso di DefectDojo apparirà un pulsante **Login With SAML**.

   ![image](images/sso_saml_login.png).

## Opzioni aggiuntive

* **Create Unknown User** — crea automaticamente un nuovo utente DefectDojo se non viene trovato nella risposta SAML.
* **Allow Unknown Attributes** — consente l'accesso agli utenti che hanno attributi non elencati nell'Attribute Mapping.
* **Sign Assertions/Responses** — richiede che tutte le risposte SAML in entrata siano firmate.
* **Sign Logout Requests** — firma tutte le richieste di logout inviate da DefectDojo.
* **Force Authentication** — richiede agli utenti di autenticarsi con l'Identity Provider a ogni accesso, indipendentemente dalle sessioni esistenti.
* **Enable SAML Debugging** — registra un output SAML dettagliato per la risoluzione dei problemi. Consulta [Risoluzione dei problemi → Output di SAML Debugging](#saml-debugging-output) per sapere dove compare l'output dei log.

## SAML Group Mapping

DefectDojo può utilizzare l'asserzione SAML per assegnare automaticamente gli utenti ai [Gruppi di utenti](../../user_management/create_user_group/). I gruppi in DefectDojo assegnano i permessi a tutti i loro membri, quindi il Group Mapping consente di gestire i permessi in blocco. Questo è l'unico modo per impostare i permessi tramite SAML.

**Il group mapping è facoltativo.** Sebbene i campi **Group Name Attribute** e **Group Limiter Regex Expression** compaiano con l'asterisco dei campi obbligatori (`*`) nell'interfaccia, il modulo SAML viene inviato anche senza compilarli, e l'accesso SAML funziona anche senza group mapping. Non è necessario creare in anticipo gruppi o ruoli nel tuo IdP (ad esempio i ruoli applicativi di Azure AD) prima di abilitare SAML — devi configurare questi campi solo quando vuoi effettivamente che DefectDojo legga l'appartenenza ai gruppi dall'asserzione. Se non configuri il group mapping, i nuovi utenti SSO creati non avranno alcun permesso per impostazione predefinita; consulta [Accesso predefinito per gli utenti forniti tramite SSO](#default-access-for-sso-provisioned-users) più sotto.

Il campo **Group Name Attribute** specifica quale attributo nell'asserzione SAML contiene le appartenenze ai gruppi dell'utente. Quando un utente accede, DefectDojo legge questo attributo e assegna l'utente a tutti i gruppi corrispondenti. Per limitare quali gruppi dell'asserzione vengono considerati, usa il campo **Group Limiter Regex Expression** — si tratta di un'espressione regolare applicata ai nomi dei gruppi presenti nell'asserzione, usata per filtrare su quali DefectDojo deve agire.

Il valore deve corrispondere esattamente al nome dell'attributo emesso dal tuo Identity Provider nell'asserzione, incluso eventuale prefisso di namespace. Un nome breve e semplice come `groups` funziona solo se il tuo IdP è configurato per emettere esattamente quel nome di attributo — molti IdP utilizzano invece un URI di claim completamente qualificato.

### Group Name Attribute per Identity Provider

| Identity Provider | Nome attributo predefinito da usare |
|---|---|
| **Entra ID / Azure AD** | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |
| **Okta** | `groups` (il nome dell'attributo configurato nella Group Attribute Statement dell'app SAML) |
| **Keycloak** | `groups` (oppure il valore impostato come "SAML Attribute Name" nel mapper Group List) |
| **PingFederate / generico** | Il valore configurato lato IdP — verifica l'asserzione del tuo IdP prima di presumere che sia `groups` |

Se il group mapping sembra non avere alcun effetto — gli utenti accedono correttamente ma non viene creato o assegnato alcun gruppo — consulta [Risoluzione dei problemi → Il SAML group mapping non ha alcun effetto](#saml-group-mapping-does-nothing--users-log-in-but-no-groups-are-assigned) più sotto.

Se non esiste alcun gruppo con un nome corrispondente, DefectDojo ne crea automaticamente uno e assegna ai suoi membri il ruolo **Reader**. Nota che questo ruolo Reader governa l'accesso del membro *al gruppo stesso* — non concede alcun accesso ai Prodotti, ai Tipi di Prodotto o ad altri asset organizzativi sottostanti. Questi permessi vengono configurati separatamente, e un gruppo appena creato automaticamente non ne ha ancora nessuno finché un Superuser non assegna al gruppo un ruolo sui relativi Prodotti o Tipi di Prodotto.

Per attivare il group mapping, seleziona la casella **Enable Group Mapping** in fondo al modulo.

## Accesso predefinito per gli utenti forniti tramite SSO

Quando un nuovo utente viene creato tramite SAML (o qualsiasi provider di social-auth) e non viene aggiunto ad alcun gruppo tramite il SAML Group Mapping, si troverà su un'istanza DefectDojo **senza alcun permesso**. Al momento dell'accesso non vedrà alcun Tipo di Prodotto, alcun Prodotto né alcun Engagement — la dashboard apparirà vuota.

Per fornire a ogni nuovo utente SSO una base di permessi ragionevole, configura un **Default group** e un **Default group role** nella pagina System Settings:

1. Apri **⚙️ Configuration → System Settings** (solo Superuser).
2. Imposta **Default group** sul [Gruppo di utenti](../../user_management/create_user_group/) a cui devono unirsi i nuovi utenti creati.
3. Imposta **Default group role** sul ruolo che devono avere in quel gruppo (ad esempio **Reader**).
4. Facoltativamente, imposta **Default group email pattern** su un'espressione regolare (ad esempio `.*@yourcompany\.com$`) in modo che il gruppo predefinito venga applicato solo agli utenti la cui email corrisponde.
5. Salva.

Devono essere impostati sia **Default group** sia **Default group role** — se anche uno solo dei due è vuoto, il gruppo predefinito non viene applicato.

Questa impostazione si applica a **ogni nuovo utente creato**, compresi quelli creati tramite SAML, OAuth e altri provider di social-auth, perché viene eseguita sul signal di creazione utente di Django anziché all'interno di un backend di autenticazione specifico.

> **Gli utenti esistenti non sono interessati.** Il gruppo predefinito viene applicato solo alla prima creazione di un utente. Gli utenti DefectDojo esistenti manterranno le loro attuali appartenenze ai gruppi anche se in seguito modifichi questa impostazione.

## Differenze tra Cloud e On-Premise

DefectDojo Cloud non offre lo stesso livello di personalizzazione SAML di DefectDojo On-Prem.  Le uniche variabili impostabili sono quelle disponibili tramite l'interfaccia.  Ecco alcune delle differenze principali:

| Capability | Cloud | On-Premise |
|---|---|---|
| **Corrispondenza username** | Solo NameID | Solo NameID (la variabile d'ambiente `SAML_USE_NAME_ID_AS_USERNAME` si applica solo a Open Source, non a Pro) |
| **Crittografia dell'asserzione SAML** | Non attualmente supportata | Non attualmente supportata |
| **Log di accesso SAML** | Non disponibili nell'interfaccia. Contatta il Supporto per richiedere i log. | Disponibili tramite i log del container dell'applicazione (`docker logs dojo`) |
| **Metodo di configurazione** | Solo interfaccia Enterprise Settings | Interfaccia Enterprise Settings, Django Admin o Django Shell |
| **Variabili d'ambiente** | Non possono essere impostate direttamente dai clienti. Contatta il Supporto per le modifiche. | Possono essere impostate tramite `dojo-compose-cli environment add` |

Se hai bisogno di far corrispondere gli utenti in base a un attributo diverso da NameID (come `uid` o `email`), configura il tuo Identity Provider affinché invii il valore desiderato come NameID, invece di modificare le impostazioni di DefectDojo.

## Risoluzione dei problemi

### Output di SAML Debugging

Quando è selezionata **Enable SAML Debugging** (in [Opzioni aggiuntive](#additional-options)), DefectDojo scrive un output dettagliato dell'elaborazione SAML — inclusi gli attributi grezzi ricevuti dall'IdP — nei log dell'applicazione a livello `DEBUG`, sotto il logger `saml2`.

| Where you're running | Where to read the debug output |
|---|---|
| **DefectDojo Cloud** | Il log di debug SAML non è esposto nell'interfaccia. Contatta il Supporto DefectDojo per richiedere i log relativi a un intervallo di tempo specifico. |
| **On-Premise (container singolo)** | `docker logs dojo` (oppure l'aggregatore di log del tuo Helm/K8s) |
| **On-Premise (Helm/K8s)** | `kubectl logs deployment/defectdojo-django -c uwsgi` (oppure l'aggregatore di log del tuo cluster) |

Disattiva questa opzione una volta terminata la risoluzione dei problemi — i log di debug SAML sono verbosi e potrebbero contenere valori di attributi sensibili provenienti dal tuo IdP.

### Gli utenti ricevono un errore "User not found" o "Permission denied" dopo un accesso IdP riuscito

Se l'asserzione SAML viene analizzata correttamente (nessun errore XML o di firma) ma DefectDojo rifiuta l'accesso, la causa più comune è una **discrepanza tra gli username** dell'IdP e di DefectDojo.

DefectDojo cerca l'utente **in base allo username** quando abbina un accesso SAML a un account esistente. Se il valore inviato dal tuo IdP come attributo `username` non corrisponde allo username di un utente DefectDojo esistente, la ricerca fallisce — anche se il resto dell'asserzione è valido.

Due possibili soluzioni, scegli quella più adatta al tuo ambiente:

- **Rimuovi `username` dall'Attribute Mapping** e lascia che DefectDojo utilizzi invece il `NameID` SAML come username. Questo è appropriato se gli username di DefectDojo corrispondono già al formato NameID emesso dal tuo IdP.
- **Allinea gli username.** Assicurati che gli username in DefectDojo corrispondano esattamente a quanto invia il tuo IdP nel claim `username`. Per la maggior parte delle organizzazioni la convenzione più semplice è far coincidere gli username di DefectDojo con l'indirizzo email dell'utente, e far sì che l'IdP invii l'email come claim `username`.

Se non sei sicuro di cosa stia effettivamente inviando l'IdP, abilita **Enable SAML Debugging** (sopra) e ispeziona gli attributi analizzati nei log.

### Il SAML group mapping non ha alcun effetto — gli utenti accedono ma non viene assegnato alcun gruppo

La causa più comune è una discrepanza tra il campo **Group Name Attribute** e il nome dell'attributo effettivamente inviato dal tuo IdP. Consulta la tabella [Group Name Attribute per Identity Provider](#group-name-attribute-by-identity-provider) più sopra e abilita **Enable SAML Debugging** per vedere gli attributi grezzi restituiti dall'IdP.
