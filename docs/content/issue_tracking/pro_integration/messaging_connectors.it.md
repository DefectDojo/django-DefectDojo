---
title: Connettori di messaggistica
description: Invia avvisi da DefectDojo a Slack, Microsoft Teams, email o Amazon SNS.
weight: 4
audience: pro
---

**Disponibilità:** i Connettori di messaggistica sono una funzionalità beta. Abilita **Messaging Connectors** nella pagina Feature Flags. Poiché gli avvisi vengono instradati tramite regole, è necessario abilitare anche **Rules Engine 2.0**.

I Connettori di messaggistica inviano avvisi da DefectDojo a un servizio di chat, a un indirizzo email o a un topic Amazon SNS. Si trovano accanto ai connettori di ticketing e di gestione degli incidenti nella stessa pagina **Downstream Connectors** e si configurano allo stesso modo: si crea una connessione una sola volta, poi si decide cosa inviarle.

I connettori di ticketing e i connettori di messaggistica rispondono a esigenze diverse. Un connettore di ticketing crea e aggiorna un ticket che segue nel tempo un singolo Riscontro. Un connettore di messaggistica pubblica un messaggio su qualcosa che è appena successo, ad esempio un'importazione che ha portato nuovi Riscontri di gravità Alta e Critica. Un messaggio non ha uno stato da far transitare né un ticket da tenere sincronizzato, quindi i due tipi si configurano separatamente e non si influenzano a vicenda.

## Cosa puoi inviare

Gli avvisi vengono instradati da Rules Engine 2.0. Una regola decide **quando** inviare (un trigger), **quali** Riscontri sono idonei (condizioni) e **dove** arriva il messaggio (un nodo di notifica che indirizza la connessione e il canale).

Questo significa che i filtri disponibili per un avviso sono gli stessi disponibili per una regola: gravità, ambito, tag, stato e qualsiasi altra cosa una condizione di regola possa esprimere. Più avvisi diversi indirizzati a più canali diversi sono semplicemente più regole.

## I quattro fornitori

| Fornitore | Cosa fornisci | Quante destinazioni per connessione |
| --- | --- | --- |
| Slack | Un bot token di un'app Slack | Molte. Ogni destinazione indica un ID canale. |
| Microsoft Teams | Un URL di workflow di Power Automate | Una. L'URL determina il canale. |
| Email | Nulla. Viene usato il server di posta dell'istanza. | Molte. Ogni destinazione indica dei destinatari. |
| Amazon SNS | Una chiave di accesso AWS autorizzata a pubblicare | Molte. Ogni destinazione indica un ARN di topic. |

Ognuno si configura allo stesso modo: aggiungi la connessione in **Connect > Downstream**, poi crea un avviso
che la indirizzi.

## Configurare una connessione Slack

Serve un'app Slack con un bot token. Se il tuo workspace ne ha già una per DefectDojo, puoi riutilizzarla.

### 1. Crea un'app Slack

1. Vai su [https://api.slack.com/apps](https://api.slack.com/apps) e seleziona **Create New App**, poi **From scratch**.
2. Assegna un nome all'app (ad esempio DefectDojo) e scegli il workspace in cui deve pubblicare.
3. Apri **OAuth & Permissions** e aggiungi questi **Bot Token Scopes**:
   - `chat:write` (obbligatorio): consente all'app di pubblicare messaggi.
   - `chat:write.public` (facoltativo): consente all'app di pubblicare in qualsiasi canale pubblico senza doverla prima invitare. Senza questo scope devi invitare il bot in ogni canale che vuoi usare.
4. Seleziona **Install to Workspace** e approva l'app.
5. Copia il **Bot User OAuth Token**. Inizia con `xoxb-`.

### 2. Aggiungi la connessione in DefectDojo

1. Vai su **Connect > Downstream**.
2. Nella sezione **Messaging**, trova il riquadro Slack e seleziona **Add Configuration**.
3. Inserisci:
   - **Location**: l'URL del tuo workspace Slack, ad esempio `https://your-workspace.slack.com`. Viene usato solo per la visualizzazione e i link.
   - **Identifier**: un'etichetta che distingue questa connessione dalle altre, ad esempio `Security workspace`.
   - **Bot Token**: il token `xoxb-` che hai copiato.
4. Salva. DefectDojo convalida immediatamente il token con Slack, quindi un token errato o revocato viene segnalato qui, non alla prima attivazione di un avviso.

Puoi aggiungere tutte le connessioni Slack di cui hai bisogno. Connessioni separate sono il modo per raggiungere più di un workspace.

### 3. Trova l'ID del canale

Le destinazioni Slack richiedono l'**ID** del canale, non il suo nome.

1. In Slack, apri il canale e seleziona il suo nome in alto.
2. Scorri fino in fondo alla scheda **About**.
3. Copia il **Channel ID**. Ha un formato simile a `C0123456789`.

Se l'app non ha lo scope `chat:write.public`, devi anche invitarla nel canale: digita `/invite @your-app-name` nel canale.

## Configurare una connessione Microsoft Teams

Teams utilizza un **URL di workflow di Power Automate**. I classici connettori di Office 365 sono stati dismessi e questo
percorso non richiede né la registrazione di un'app né il consenso dell'amministratore del tenant: chiunque abbia
i diritti sul canale crea il flusso e incolla l'URL restituito.

**Una connessione pubblica in un solo canale.** L'URL del workflow determina dove arriva il messaggio, quindi un
secondo canale richiede una seconda connessione, non una seconda destinazione.

### 1. Crea il workflow

1. In Teams, apri il canale in cui vuoi pubblicare, seleziona il menu **...** accanto al nome del canale, poi **Workflows**.
2. Scegli il modello **Post to a channel when a webhook request is received**.
3. Conferma il team e il canale, poi seleziona **Add workflow**.
4. Copia l'URL restituito dal workflow. È un indirizzo `https://` piuttosto lungo su un host Microsoft Power Automate.

Tratta questo URL come una password. Chiunque lo possieda può pubblicare in quel canale.

### 2. Aggiungi la connessione in DefectDojo

1. Vai su **Connect > Downstream**.
2. Nella sezione **Messaging**, trova il riquadro Microsoft Teams e seleziona **Add Configuration**.
3. Inserisci:
   - **Location**: l'URL di Teams o Microsoft 365. Viene usato solo per la visualizzazione e i link.
   - **Instance Label**: un'etichetta che indica il canale raggiunto da questa connessione, ad esempio `Security / Alerts`.
   - **Workflow URL**: l'URL che hai copiato.
4. Salva.

Al salvataggio DefectDojo verifica il formato dell'URL (deve essere `https://` e su un host workflow Microsoft), ma non vi pubblica nulla. Un URL di workflow non ha altro modo di essere testato se non inviando un messaggio, e un messaggio a sorpresa in un canale al momento del salvataggio sarebbe peggio che scoprirlo più tardi. Usa **Send test message** quando sei pronto.

Una destinazione Teams ha un unico campo facoltativo, un'etichetta di canale, che serve solo a etichettare il record di consegna. L'URL del workflow determina già la destinazione.

## Configurare una connessione Email

L'email non richiede alcuna credenziale. DefectDojo invia tramite il server di posta già usato da questa istanza per le notifiche, quindi non c'è nulla di nuovo da configurare e non esiste un secondo punto in cui l'SMTP possa essere sbagliato.

1. Vai su **Connect > Downstream**.
2. Nella sezione **Messaging**, trova il riquadro Email e seleziona **Add Configuration**.
3. Inserisci:
   - **Location**: l'identità del mittente da visualizzare, ad esempio `mailto:defectdojo@example.com`.
   - **Instance Label**: un'etichetta che distingue questa connessione dalle altre.
4. Salva.

Il salvataggio fallisce se questa istanza non ha un server di posta o un indirizzo mittente configurato, perché nulla di ciò che viene inviato tramite la connessione uscirebbe mai. Configura prima l'SMTP in **Settings > System Settings**.

I destinatari si impostano sull'avviso, non sulla connessione, quindi una sola connessione Email serve tutti gli avvisi. Una destinazione email accetta fino a 50 indirizzi; oltre questo limite, usa un indirizzo di distribuzione.

## Configurare una connessione Amazon SNS

SNS è diverso per natura dagli altri tre: DefectDojo pubblica un messaggio su un topic e AWS
lo distribuisce a tutto ciò che è iscritto, che siano indirizzi email, numeri SMS, una funzione Lambda,
un endpoint HTTPS o una coda SQS. A DefectDojo non importa quale.

### 1. Crea una chiave di accesso in grado di pubblicare

1. Nella console AWS, crea (o scegli) un utente o ruolo IAM per DefectDojo.
2. Collega una policy che consenta `sns:Publish` sui topic che intendi usare. Indicare esplicitamente gli ARN dei topic è meglio che consentirli tutti.
3. Crea una chiave di accesso per esso e copia entrambe le parti. AWS mostra la secret access key una sola volta.

Se il topic è cifrato con una chiave KMS, lo stesso principal ha bisogno anche di `kms:GenerateDataKey` e `kms:Decrypt` su quella chiave, altrimenti ogni pubblicazione viene rifiutata.

### 2. Aggiungi la connessione in DefectDojo

1. Vai su **Connect > Downstream**.
2. Nella sezione **Messaging**, trova il riquadro Amazon SNS e seleziona **Add Configuration**.
3. Inserisci:
   - **Location**: un URL solo per visualizzazione e link, ad esempio l'URL della tua console AWS.
   - **Instance Label**: un'etichetta che distingue questa connessione dalle altre, ad esempio `Production AWS account`.
   - **Access Key ID**: l'ID della chiave, con un formato simile a `AKIAIOSFODNN7EXAMPLE`.
   - **Secret Access Key**: la parte segreta.
4. Salva.

DefectDojo verifica immediatamente la credenziale con AWS, quindi una chiave errata o eliminata viene segnalata qui, non alla prima attivazione di un avviso. Questo controllo conferma solo che la credenziale è valida; se può pubblicare su un determinato topic viene verificato quando imposti la destinazione.

**Non c'è alcuna regione da inserire.** La regione fa parte dell'ARN del topic, quindi una connessione può pubblicare su topic in più di una regione, e non esiste una seconda impostazione che possa essere in contrasto con l'ARN.

### 3. Trova l'ARN del topic

Una destinazione SNS richiede l'ARN del topic.

1. Nella console SNS, apri il topic.
2. Copia l'**ARN** dalla parte superiore della pagina. Ha un formato simile a `arn:aws:sns:us-east-1:123456789012:security-alerts`.

A differenza dell'URL di workflow di Teams, un ARN non è un segreto: identifica un topic, e pubblicarvi richiede la credenziale sulla connessione. Per questo una sola connessione SNS può servire molti topic.

I topic FIFO (un ARN che termina in `.fifo`) non sono supportati. Richiedono un message group e un deduplication ID, regole di ordinamento che un avviso non ha modo di fornire. Usa un topic standard.

## Invia un messaggio di test

Ovunque sia configurata una destinazione di messaggistica, **Send test message** invia un breve messaggio esattamente attraverso lo stesso percorso usato da un avviso reale, e riporta la risposta del fornitore.

Usalo per verificare gli aspetti più facili da sbagliare: per Slack, che l'ID del canale sia corretto e che il bot possa pubblicarvi; per Teams, che l'URL del workflow funzioni ancora; per l'email, che l'indirizzo sia recapitabile; per SNS, che la chiave possa pubblicare su quel topic. La risposta del fornitore viene riportata così com'è, quindi un invito Slack mancante appare come un messaggio che ti dice di invitare il bot, non come un errore generico.

Un test riuscito riabilita anche una connessione che era stata disattivata automaticamente (vedi [Quando una connessione smette di funzionare](#when-a-connection-stops-working)).

## Creare un avviso

Ci sono due modi per procedere. Entrambi producono lo stesso risultato: una regola di Rules Engine 2.0.

### La pagina degli avvisi

Il percorso più rapido, per il caso comune di annunciare nuovi riscontri da un'importazione.

1. Vai su **Connect > Downstream** e seleziona **Create Alert** su una connessione di messaggistica, oppure apri direttamente **Messaging Alerts**.
2. Seleziona **New Alert** e compila:
   - **Name**: a cosa serve questo avviso, ad esempio `New highs to the security channel`.
   - **Alert**: di cosa si tratta. **New findings from an import** è attualmente l'unica opzione.
   - **Send over**: la connessione di messaggistica.
   - **Where it delivers**: il campo di destinazione specifico del fornitore, quindi un ID canale Slack, un'etichetta di canale Teams facoltativa, un elenco di indirizzi email o un ARN di topic SNS.
   - **Severity**: la soglia minima, da **Critical only** a **Every severity**.
   - **Mode**: **Simulate** registra cosa sarebbe stato inviato senza inviarlo davvero, **Live** invia effettivamente.
3. Seleziona **Create Alert**.

La pagina elenca gli avvisi creati, con il trigger, la soglia di gravità e un interruttore per abilitare o disabilitare ciascuno.

Inizia in **Simulate** se vuoi vedere cosa avrebbe intercettato un avviso prima che qualsiasi canale ne venga a conoscenza. La regola viene eseguita, le consegne vengono registrate e non viene inviato nulla.

Gli avvisi sono regole, quindi possono anche essere aperti nell'editor delle regole dalla stessa lista. Quando una regola è stata modificata in qualcosa che il form non può esprimere, come un secondo ramo o un secondo messaggio, la lista propone l'editor delle regole al posto del form, invece di un form che azzererebbe silenziosamente il lavoro aggiuntivo.

### L'editor delle regole

Il percorso completo, per tutto ciò che il form non copre.

1. Vai su **Automation > Rules Engine 2.0** e crea una regola.
2. Aggiungi un trigger. Per gli avvisi su Riscontri appena importati, usa il trigger evento Finding su **created**. Le importazioni sono raggruppate, quindi un'importazione produce un solo avviso invece di uno per ogni Riscontro.
3. Aggiungi le condizioni per stabilire cosa deve qualificarsi, ad esempio una gravità minima Alta.
4. Aggiungi un nodo messaggio per il fornitore desiderato (**Send a Slack Message**, **Send a Microsoft Teams Message**, **Send an Email** o **Publish to an SNS Topic**) e imposta:
   - **Connection**: la connessione di messaggistica che hai creato.
   - **Destination**: la destinazione specifica del fornitore, quindi un ID canale per Slack, un'etichetta di canale facoltativa per Teams, i destinatari per l'email o un ARN di topic per SNS.
5. Salva la regola e abilitala.

Non viene inviato nulla quando nessun Riscontro soddisfa le condizioni, quindi una regola filtrata su Alta e superiori resta silenziosa su un'importazione che ha portato solo Riscontri di gravità Bassa.

### Regole scritte prima dei Connettori di messaggistica

Un nodo messaggio invia tramite una connessione, e solo tramite una connessione. In precedenza, i nodi Slack, Teams ed email ricadevano sulle impostazioni globali dell'istanza in **Settings > Notifications** quando non veniva scelta alcuna connessione. Ora non lo fanno più.

Una regola scritta in quel modo continua a essere eseguita e il suo nodo messaggio registra una consegna saltata segnalando che non indica alcuna connessione. Per risolvere, apri la regola, scegli una connessione e una destinazione sul nodo, e salva. Una consegna già registrata può essere ripetuta dalla lista delle consegne una volta che il nodo indica una connessione.

La connessione è un campo obbligatorio su ogni nodo messaggio, quindi l'editor delle regole ne richiede una prima che la regola possa essere salvata.

## Quando una connessione smette di funzionare

Un bot token revocato, un workflow eliminato o una chiave di accesso AWS eliminata fanno fallire ogni avviso che servono. Invece di registrare lo stesso errore per ogni evento, DefectDojo conta i fallimenti consecutivi della credenziale per destinazione e smette di inviare dopo alcuni di essi. La connessione segnala quale destinazione è stata disabilitata e perché.

Per ripristinare: correggi la credenziale (reinstalla l'app Slack e incolla il nuovo token, ricrea il workflow Teams e incolla il nuovo URL, oppure crea una nuova chiave di accesso AWS), quindi invia un messaggio di test a quella destinazione, che la riabilita in caso di successo, oppure usa direttamente l'azione di riabilitazione.

Solo i fallimenti della credenziale causano questo comportamento. Un messaggio rifiutato perché un ID canale Slack è sbagliato, il bot non è stato invitato, un indirizzo email non esiste, o una policy IAM non consente di pubblicare su un topic non disabilita nulla, perché la credenziale è valida e correggere la destinazione o la policy dovrebbe funzionare immediatamente.

## Avvisi e notifiche insieme

I Connettori di messaggistica non sostituiscono le notifiche. Le impostazioni globali dell'istanza per Slack, Teams ed email in **Settings > Notifications**, le notifiche personali e la matrice delle notifiche continuano a funzionare esattamente come configurate. Sono ciò che annuncia gli eventi propri di DefectDojo; un Connettore di messaggistica è ciò tramite cui invia una regola che hai scritto.

Un aspetto a cui prestare attenzione: se un avviso pubblica sullo stesso canale o indirizzo a cui già annuncia l'impostazione globale dell'istanza, quella destinazione riceve entrambi i messaggi. Configura l'uno o l'altro per una data destinazione.

## Limitazioni

- Il testo dei messaggi non è ancora personalizzabile. Gli avvisi usano il testo predefinito di DefectDojo.
- I messaggi sono a senso unico. DefectDojo non legge le risposte e nel messaggio non ci sono pulsanti né elementi interattivi.
- I thread, la modifica dei messaggi e i messaggi diretti ai singoli utenti non sono supportati. Le notifiche personali continuano a usare il sistema di notifiche esistente.
- Una connessione Teams raggiunge un solo canale, perché è l'URL del workflow a indirizzare il canale.
- I messaggi SNS sono testo semplice. Un topic può distribuire contemporaneamente a iscritti email, SMS, Lambda e HTTPS, quindi non esiste un formato unico adatto a tutti, e non viene pubblicata alcuna variante per protocollo.
- I topic SNS FIFO non sono supportati.
- Non è ancora possibile inviare report o altri allegati. Gli avvisi sono messaggi con link di ritorno a DefectDojo.
- La pagina degli avvisi copre i nuovi riscontri da un'importazione. Tutto il resto si costruisce nell'editor delle regole.
