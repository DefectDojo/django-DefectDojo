---
title: Jira
description: Lavorare con l'integrazione Jira
weight: 2
audience: opensource
aliases:
- /it/issue_tracking/jira/os__jira_guide/
---

L'integrazione Jira di DefectDojo può essere utilizzata per inviare i dati dei Riscontri a uno o più Spazi Jira. In questo modo è possibile integrare DefectDojo nel proprio flusso di lavoro di sviluppo standard. Ecco alcuni esempi di come questo può funzionare:

* Il team AppSec può inviare selettivamente i Riscontri a uno Spazio Jira utilizzato dagli sviluppatori, in modo che la risoluzione dei problemi possa essere opportunamente prioritizzata insieme al normale sviluppo. Gli sviluppatori su questa bacheca non hanno bisogno di accedere a DefectDojo: possono mantenere tutto il proprio lavoro in un unico posto.
* DefectDojo può inviare TUTTI i Riscontri a uno Spazio Jira bidirezionale utilizzato dal team AppSec, il che consente loro di suddividere la convalida dei problemi. Questa bacheca resta sincronizzata con DefectDojo e consente flussi di lavoro di risoluzione complessi.
* DefectDojo può inviare selettivamente i Riscontri da singoli Prodotti e/o Engagement a Spazi Jira separati, per mantenere ogni elemento nel proprio contesto corretto.

# Configurazione di Jira

La configurazione di Jira richiede i seguenti passaggi:
1. Abilitare l'integrazione Jira nelle Impostazioni di sistema. Finché non viene fatto, il resto delle impostazioni Jira resta nascosto in tutto DefectDojo.
2. Collegare un'istanza Jira, tramite un nome utente / password oppure un token API. È possibile collegare più istanze.
3. Aggiungere tale istanza Jira a uno o più Prodotti o Engagement all'interno di DefectDojo.
4. Per utilizzare la sincronizzazione bidirezionale, creare un Webhook Jira che invii gli aggiornamenti a DefectDojo.

## Passaggio 1: abilitare l'integrazione Jira nelle Impostazioni di sistema

L'integrazione Jira è disattivata per impostazione predefinita e, quando è disattivata, DefectDojo nasconde ogni altro controllo Jira nell'interfaccia. Questa è la prima cosa da configurare: nessuno dei passaggi seguenti è disponibile finché non viene abilitata.

Quando l'integrazione è disabilitata, la voce ⚙️ **Configurazione \> JIRA** non è presente nella barra laterale, quindi non c'è modo di aggiungere un'istanza Jira:

![immagine](images/jira-config-menu-hidden-os.png)

### Abilitare l'integrazione

1. Passare a ⚙️ **Configurazione \> Impostazioni di sistema** dalla barra laterale di DefectDojo.
​
2. Selezionare **Abilita integrazione JIRA**.
​
3. Non appena l'integrazione viene abilitata, è richiesto un **segreto webhook Jira**. Fare clic sull'icona 🔄 accanto al campo per generarne uno. Se il modulo viene inviato senza un segreto, viene rifiutato con il messaggio *"This field is required when enable Jira Integration is True"*:

![immagine](images/jira-webhook-secret-required-os.png)

Il segreto fa parte dell'URL del webhook a cui Jira invia le richieste (`https://<YOUR DOJO DOMAIN>/jira/webhook/<SECRET>`), quindi trattare il valore generato come una credenziale. È necessario comunicarlo a Jira solo se si configura la sincronizzazione bidirezionale nel [Passaggio 4](#step-4-configure-bidirectional-sync-jira-webhook); generarlo ora serve solo a soddisfare il modulo.

4. Fare clic su **Invia**. ⚙️ **Configurazione \> JIRA** compare ora nella barra laterale:

![immagine](images/jira-enable-system-settings-os.png)

### Cosa controlla questa impostazione

Abilitare **Abilita integrazione JIRA** è ciò che fa comparire il resto dell'interfaccia Jira. Con questa opzione attivata, si ottiene:

* la pagina ⚙️ **Configurazione \> JIRA**, dove le istanze Jira vengono aggiunte e modificate
* la sezione **JIRA** nei moduli Modifica Prodotto (Asset) e Modifica Engagement, utilizzata per collegare un Prodotto o un Engagement a uno Spazio Jira
* i controlli **Invia a Jira** su Riscontri, Gruppi di Riscontri e moduli di modifica collettiva, oltre alle colonne e ai filtri Jira negli elenchi di Riscontri, Engagement e Prodotti

Ad esempio, la sezione **JIRA** compare in fondo al modulo Modifica Prodotto solo quando l'integrazione è abilitata:

![immagine](images/jira-asset-settings-visible-os.png)

L'impostazione regola l'integrazione anche al di fuori dell'interfaccia utente: quando è disattivata, DefectDojo non invierà i Riscontri a Jira (comprese le richieste `push_to_jira` inviate tramite l'API), e i webhook Jira in arrivo vengono ignorati.

I restanti campi Jira nella pagina Impostazioni di sistema (**Abilita webhook JIRA**, **Gravità minima Jira**, **Etichette Jira**, **Aggiungi ID vulnerabilità come etichetta JIRA**) restano visibili indipendentemente dal fatto che l'integrazione sia attiva o meno, ma non hanno alcun effetto finché non viene abilitata.

## Passaggio 2: collegare un'istanza Jira

Con l'integrazione abilitata, collegare un'istanza Jira è il passaggio successivo nella configurazione dell'integrazione Jira di DefectDojo. Notare che Jira Service Management non è attualmente supportato.

#### Informazioni richieste da Jira

Atlassian utilizza metodi di autenticazione diversi tra Jira Cloud e Jira Data Center.

per **Jira Cloud** sono necessari:
* un URL Jira, ad es. https://yourcompany.atlassian.net/
* un account con i permessi per creare e aggiornare i problemi nella propria istanza Jira. Può trattarsi di:
    * una combinazione standard di **nome utente / password**
    * una combinazione di **nome utente / Token API**

per **Jira Data Center (o Server)** sono necessari:
* un URL Jira, ad es. https://jira.yourcompany.com
* un account con i permessi per creare e aggiornare i problemi nella propria istanza Jira. Può trattarsi di:
    * una combinazione standard di **nome utente / password**

Facoltativamente, è possibile mappare:
* le Transizioni Jira per attivare la riapertura e la chiusura dei Riscontri
* le Risoluzioni Jira che possono applicare gli stati Rischio accettato e Falso positivo ai Riscontri (opzionale)

Un'unica connessione a un'istanza Jira può gestire più Spazi Jira, purché l'account / token Jira utilizzato da DefectDojo disponga dei permessi per creare Problemi nello Spazio Jira associato.

### Aggiungere un'istanza Jira

1. Assicurarsi che **Abilita integrazione JIRA** sia selezionato nelle Impostazioni di sistema, come descritto nel [Passaggio 1](#step-1-enable-the-jira-integration-in-system-settings). L'opzione ⚙️ **Configurazione \> JIRA** non compare nella barra laterale finché ciò non avviene.
​
2. Passare alla pagina ⚙️ **Configurazione \> JIRA** dalla barra laterale di DefectDojo.
​
![immagine](images/Connect_DefectDojo_to_Jira.png)

3. Verrà visualizzato un elenco di tutti gli Spazi Jira attualmente configurati e collegati a DefectDojo. Per aggiungere una nuova configurazione di progetto, fare clic sull'icona a forma di chiave inglese e scegliere l'opzione **Add Jira Configuration (Express)** oppure **Add Jira Configuration**.

#### Aggiungi configurazione Jira (Express)

Il metodo Express consente di collegare uno Spazio in modo più rapido. Utilizzare il metodo Express se si desidera semplicemente collegare rapidamente uno Spazio Jira, senza dover gestire un flusso di lavoro Jira complesso.

![immagine](images/Connect_DefectDojo_to_Jira_2.png)

1. Selezionare un nome per questa configurazione Jira da utilizzare in DefectDojo. Questo nome è semplicemente un'etichetta per la connessione dell'istanza in DefectDojo e non deve necessariamente essere collegato ai dati Jira.
​
2. Selezionare l'URL della propria istanza Jira aziendale, probabilmente simile a `https://**yourcompany**.atlassian.net` se si utilizza un'installazione Jira Cloud.
​
3. Inserire un metodo di autenticazione appropriato nei campi Nome utente / Password per Jira:
    * Per l'autenticazione standard **nome utente / password di Jira**, inserire un nome utente Jira e la password corrispondente in questi campi.
    * Per l'autenticazione con il **Token API di un utente (Jira Cloud)**, inserire il nome utente con il **Token API** corrispondente nel campo password.
​
4. Selezionare il tipo di problema predefinito che si desidera utilizzare per la creazione dei Problemi in Jira. Le opzioni disponibili sono **Bug, Task, Story** ed **Epic** (che sono tipi di problema standard di Jira), oltre a **Spike** e **Security**, che sono tipi di problema personalizzati. Se si desidera utilizzare un Tipo di problema diverso, contattare [support@defectdojo.com](mailto:support@defectdojo.com) per assistenza.
​
5. Selezionare il Modello di problema, che determinerà la Descrizione del problema quando i Problemi vengono creati in Jira.

I due tipi sono:
- **Jira\_full**, che includerà tutte le informazioni del Riscontro nei Problemi Jira
- **Jira\_limited**, che includerà una quantità minore di informazioni e metadati del Riscontro.

Se questo campo viene lasciato vuoto, verrà impostato per impostazione predefinita su **Jira\_full.**

6. Selezionare uno o più tipi di Risoluzione Jira che cambieranno lo stato di un Riscontro in Rischio accettato (quando la Risoluzione viene attivata sul Problema). Se non si desidera utilizzare questa automazione, il campo può essere lasciato vuoto.
​
7. Selezionare uno o più tipi di Risoluzione Jira che cambieranno lo stato di un Riscontro in Falso positivo (quando la Risoluzione viene attivata sul Problema). Se non si desidera utilizzare questa automazione, il campo può essere lasciato vuoto.
​
8. Decidere se inviare le notifiche SLA come commento su un problema Jira.
​
9. Decidere se sincronizzare automaticamente i Riscontri con Jira. Se questa opzione è abilitata, i Problemi Jira verranno mantenuti automaticamente sincronizzati con i Riscontri correlati. Se non è abilitata, sarà necessario inviare manualmente eventuali modifiche apportate a un Riscontro dopo che il Problema è stato creato in Jira.
​
10. Selezionare la Chiave del problema. In Jira, si tratta della stringa associata a un Problema (ad es. la parola **'EXAMPLE'** in un problema chiamato **EXAMPLE\-123**). Se non si conosce la propria chiave del problema, creare un nuovo Problema nello Spazio Jira. Nello screenshot seguente, si può notare che la chiave del problema nel nostro Spazio Jira è **DEF**.
​
![immagine](images/Connect_DefectDojo_to_Jira_3.png)
​
11. Fare clic su **Invia.** DefectDojo cercherà automaticamente le mappature appropriate in Jira e le aggiungerà alla configurazione. A questo punto è possibile collegare questa configurazione a uno o più Prodotti in DefectDojo.

#### Aggiungi configurazione Jira (Standard)

La configurazione Jira Standard aggiunge alcuni passaggi supplementari per consentire un controllo più preciso sulle mappature e sulle interazioni con Jira. Questa impostazione può essere modificata dopo che una configurazione Jira è stata aggiunta, anche se è stata creata utilizzando il metodo Express.
​
### Opzioni aggiuntive del modulo

* **ID nome Epic:** se in Jira sono presenti più tipi di Epic, è possibile specificare quello da utilizzare trovando il relativo ID nella Jira Field Spec.
​
Per ottenere l'"Epic name id", visitare `https://<YOUR JIRA URL>/rest/api/2/field` e cercare Epic Name. Copiare il numero da `number` e incollarlo qui.
​  ​
* **ID transizione di riapertura:** se si desidera che una specifica Transizione Jira riapra un problema, è possibile specificare qui l'ID della Transizione. Se si utilizza la configurazione Jira Express, DefectDojo troverà automaticamente una Transizione appropriata e creerà la mappatura.
​
Visitare `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` per trovare l'ID della propria istanza Jira. Incollarlo nel campo ID transizione di riapertura.
​
* **ID transizione di chiusura:** se si desidera che una specifica Transizione Jira chiuda un problema, è possibile specificare qui l'ID della Transizione. Se si utilizza la **configurazione Jira Express**, DefectDojo troverà automaticamente una Transizione appropriata e creerà la mappatura.
​
Visitare `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` per trovare l'ID della propria istanza Jira. Incollarlo nel campo ID transizione di chiusura.
​
* **Mappatura dei campi di Gravità:** ogni Problema Jira ha una Priorità associata, che DefectDojo assegnerà automaticamente in base alla Gravità di un Riscontro. Inserire i nomi di ciascuna Priorità a cui associare le Gravità Info, Bassa, Media, Alta e Critica.

* **Testo del Riscontro** - se si desidera aggiungere un testo standardizzato aggiuntivo a ogni Problema creato, è possibile inserirlo qui. Non si tratta di un testo che corrisponde a un campo in Jira, ma di un testo aggiuntivo che viene aggiunto alla Descrizione del problema. Ad esempio, "**Creato da DefectDojo**".

I Commenti (in Jira) e le Note (in DefectDojo) possono essere mantenuti sincronizzati. Questa impostazione può essere abilitata una volta che la configurazione Jira è stata aggiunta a un Prodotto, tramite il modulo **Modifica Prodotto**.

## Passaggio 3: collegare un Prodotto o un Engagement a Jira

Ogni Prodotto o Engagement in DefectDojo dispone di impostazioni proprie che determinano come i Riscontri vengono convertiti in Problemi JIRA. Da qui è possibile decidere lo Spazio Jira associato e impostare il comportamento predefinito per la creazione di Problemi, Epic, Etichette e altri metadati JIRA.

### Aggiungere Jira a un Prodotto o Engagement

Nell'interfaccia classica, le impostazioni Jira si trovano aprendo il modulo Modifica Prodotto o Modifica Engagement. Pulsante "**📝 Modifica**" sotto **Impostazioni** nella pagina:

![immagine](images/Add_a_Connected_Jira_Project_to_a_Product.png)

#### Elenco delle impostazioni Jira

Le impostazioni Jira si trovano verso la fine della pagina Impostazioni del Prodotto.

![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_2.png)

#### Istanza Jira

Se sono presenti più istanze Jira configurate, per prodotti o team separati all'interno della propria organizzazione, è possibile indicare in quale Spazio Jira si desidera che DefectDojo crei i Problemi. Selezionare un progetto dal menu a discesa.

Se questo menu non elenca alcuna istanza Jira, verificare che tali progetti siano collegati nella Configurazione Jira globale di DefectDojo, all'indirizzo yourcompany.defectdojo.com/jira.

#### Chiave del progetto

Questa è la chiave dello Spazio che si desidera utilizzare con DefectDojo. La chiave dello Spazio per un dato progetto si trova nell'URL, oppure alla voce "Space key" indicata nelle Impostazioni dello Spazio.

![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Modello di problema

Qui è possibile stabilire quanti metadati di DefectDojo inviare a Jira. Selezionare una delle due opzioni:

* **jira\_full**: i Problemi terranno traccia di tutti i parametri di DefectDojo - una Descrizione completa, il CVE, la Gravità, ecc. Utile se è necessario il contesto completo del Riscontro in Jira (ad esempio, se la persona che lavora su questo Problema non ha accesso a DefectDojo).

Ecco un esempio di un Problema **jira\_full**:
​
![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** i Problemi terranno traccia solo del link a DefectDojo, dei link a Prodotto/Engagement/Test, e dei campi Segnalatore e Ambiente. Tutti gli altri campi vengono tracciati solo in DefectDojo. Utile se non è necessario il contesto completo del Riscontro in Jira (ad esempio, se la persona che lavora su questo Problema opera principalmente in DefectDojo e non ha bisogno del quadro completo anche in JIRA).

​Ecco un esempio di un Problema **jira\_limited**:​

![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Componente

Se si gestisce il proprio Spazio Jira utilizzando i Componenti, qui è possibile assegnare il Componente appropriato per DefectDojo. Per assegnare più di un Componente, inserire un elenco separato da virgole (ad esempio, `Security, DevSecOps`); ogni valore viene inviato a Jira come componente separato.

**Campi personalizzati**

Se non è necessario utilizzare Campi personalizzati con i problemi di DefectDojo, questo campo può essere lasciato come 'null'.

Tuttavia, se le impostazioni dello Spazio Jira **richiedono** l'uso di Campi personalizzati sui nuovi Problemi, sarà necessario codificare manualmente queste mappature.

**Jira Cloud consente ora di creare un valore predefinito per i Campi personalizzati direttamente all'interno dell'app. [Consultare la documentazione di Atlassian sui campi personalizzati](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) per maggiori informazioni su come configurarlo.**

Da notare che DefectDojo non può inviare alcun metadato specifico del Problema come Campo personalizzato, solo un valore predefinito. Questa sezione deve essere configurata solo se il proprio Spazio Jira **richiede che questi Campi personalizzati esistano** in ogni Problema dello Spazio.

Seguire **[questa guida](#custom-fields-in-jira)** per iniziare a utilizzare i Campi personalizzati.

**Etichette Jira**

Selezionare le etichette pertinenti con cui si desidera che il Problema venga creato in Jira, ad es. **DefectDojo**, **YourProductName..**

![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Assegnatario predefinito

Il nome dell'assegnatario predefinito in Jira. Se lasciato vuoto, DefectDojo seguirà il comportamento predefinito del proprio Spazio Jira durante la creazione dei Problemi.

### Opzioni aggiuntive del modulo

#### Abilita connessione con lo Spazio Jira

Le integrazioni Jira possono essere rimosse dalla propria istanza solo se non sono stati creati Problemi correlati. Se sono stati creati dei Problemi, non è possibile rimuovere completamente un'istanza Jira da DefectDojo.

Tuttavia, è possibile disabilitare la propria integrazione Jira disattivandola a livello di Prodotto. Questo non eliminerà né modificherà i ticket Jira esistenti creati da DefectDojo, ma disabiliterà eventuali aggiornamenti successivi.

#### Aggiungi ID vulnerabilità come etichetta Jira

Questa opzione consente di aggiungere automaticamente i dati dell'ID vulnerabilità come Etichetta Jira. Gli ID vulnerabilità vengono aggiunti ai Riscontri dai singoli strumenti di sicurezza - possono essere ID Common Vulnerabilities and Exposures (CVE) o un formato diverso, specifico dello strumento che segnala il Riscontro.

#### Abilita la mappatura Engagement-Epic (per i Prodotti)

In DefectDojo, gli Engagement rappresentano un insieme di attività. Ogni Engagement contiene uno o più Test, che contengono uno o più Riscontri che devono essere risolti. Gli Epic in Jira funzionano in modo simile, e questa casella di controllo consente di inviare gli Engagement a Jira come Epic.

* Un Engagement in DefectDojo - da notare i tre riscontri elencati in fondo.
​
![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* Come lo stesso Engagement diventa un Epic quando viene inviato a JIRA - i Riscontri dell'Engagement vengono inviati anch'essi e risiedono all'interno dell'Engagement come Problemi figlio.

![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Invia tutti i problemi

Se selezionato, DefectDojo invierà automaticamente a Jira, come Problemi, tutti i Riscontri Attivi e Verificati. Se non selezionato, tutti i Riscontri dovranno essere inviati manualmente a Jira.

#### Invia le Note

Se abilitato, i commenti di Jira verranno visualizzati sul Riscontro associato in DefectDojo, sotto le Note del problema (screenshot), e viceversa; le Note sui Riscontri verranno aggiunte al Problema Jira associato come Commenti.

#### Invia le notifiche SLA come commenti

Se abilitato, qualsiasi Problema che violi le regole del Service Level Agreement (SLA) di DefectDojo avrà dei commenti aggiunti al problema Jira che lo indicano. Questi commenti verranno pubblicati quotidianamente finché il Problema non viene risolto.

I Service Level Agreement possono essere configurati in **Configurazione \> Configurazione SLA** in DefectDojo e assegnati a ciascun Prodotto.

#### Invia notifiche di scadenza dell'Accettazione del rischio come commento?

Se abilitato, qualsiasi Problema la cui Accettazione del rischio di DefectDojo associata sta per scadere avrà un commento aggiunto al problema Jira che lo indica. Questi commenti verranno pubblicati quotidianamente finché il Problema non viene risolto.

### Impostazioni Jira a livello di Engagement

Di conseguenza, Engagement diversi all'interno di uno stesso Prodotto possono avere impostazioni Jira sottostanti diverse. Per impostazione predefinita, gli Engagement '**erediteranno le impostazioni Jira dal prodotto**', il che significa che condivideranno le stesse impostazioni Jira del Prodotto a cui sono annidati.

Tuttavia, è possibile modificare **Chiave del progetto**, **Modello di problema, Campi personalizzati, Etichette Jira, Assegnatario predefinito** di un Engagement affinché siano diversi dalle impostazioni predefinite del Prodotto.

È possibile accedere a questa pagina dalla pagina **Modifica Engagement**: **your\-instance.defectdojo.com/engagement/\[id]/edit**.

La pagina Modifica Engagement si trova nella pagina dell'Engagement, facendo clic sul menu ☰ accanto alla Descrizione dell'engagement.

![immagine](images/Creating_Issues_in_Jira_5.png)

## Passaggio 4: configurare la sincronizzazione bidirezionale: Webhook Jira

L'integrazione Jira consente la sincronizzazione bidirezionale tramite webhook. DefectDojo riceve le notifiche di Jira a un indirizzo univoco, il che può consentire di ricevere sui Riscontri i commenti di Jira, oppure di risolvere i Riscontri tramite Jira, a seconda della propria configurazione.

### Individuare l'URL del Webhook Jira

Il Webhook Jira è composto dall'URL di DefectDojo e dal **segreto webhook Jira** generato nel [Passaggio 1](#step-1-enable-the-jira-integration-in-system-settings). Entrambi sono mostrati nella pagina ⚙️ **Configurazione \> Impostazioni di sistema**, accanto al campo **segreto webhook Jira** (vedere lo screenshot nel Passaggio 1).

È inoltre necessario selezionare **Abilita webhook JIRA** nella stessa pagina prima che DefectDojo elabori le notifiche Jira in arrivo. I webhook in arrivo vengono ignorati se una delle due opzioni, quella casella oppure **Abilita integrazione JIRA**, non è selezionata.

### Creare il Webhook Jira

1. Visitare `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Fare clic su 'Create a Webhook'.
3. Nel campo denominato 'URL' inserire: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. Il valore del segreto webhook Jira è indicato accanto al campo **segreto webhook Jira**, come descritto sopra.
4. In 'Comments' abilitare 'Created'. In Issue abilitare 'Updated'.
5. Assicurarsi che la propria istanza JIRA si fidi del certificato SSL utilizzato dalla propria istanza DefectDojo. Per JIRA Cloud, DefectDojo deve utilizzare [un certificato SSL/TLS valido, firmato da un'autorità di certificazione riconosciuta a livello globale](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Da notare che non è necessario creare un Secret all'interno di Jira per utilizzare questo webhook. Il Secret è integrato nell'URL di DefectDojo, quindi è sufficiente aggiungere l'URL completo al modulo del Webhook Jira.

Le richieste webhook in arrivo vengono autenticate tramite il secret contenuto in tale URL, quindi trattare l'URL completo come una credenziale e mantenerlo privato.

#### Verifica del webhook

Una volta che sono stati creati uno o più Problemi a partire dai Riscontri di DefectDojo, è possibile verificare il Webhook aggiungendo un Commento a uno di quei Riscontri. Il Commento dovrebbe essere ricevuto dal webhook Jira come nota.

Se questo non funziona correttamente, potrebbe essere dovuto a un problema del Firewall sulla propria istanza Jira che blocca il Webhook.

* Le Regole del firewall di DefectDojo includono una casella di controllo per **Jira Cloud**, che deve essere abilitata prima che DefectDojo possa ricevere i messaggi Webhook da Jira.

### Alternativa: utilizzare Automazione di Jira (Invia richiesta web)

Alcune istanze Jira non consentono i webhook di sistema in `/plugins/servlet/webhooks` — ad esempio, quando quell'area di amministrazione è limitata e sono consentite solo le regole di **Automazione di Jira**. In questo caso è possibile ottenere la stessa sincronizzazione bidirezionale utilizzando l'azione **Invia richiesta web** di Automation, che effettua una richiesta allo stesso endpoint webhook di DefectDojo.

L'endpoint webhook di DefectDojo accetta qualsiasi richiesta HTTP `POST` con `Content-Type: application/json` e un secret valido nel percorso dell'URL. **Non** richiede che la richiesta abbia origine dal meccanismo di webhook di sistema di Jira, quindi l'azione "Invia richiesta web" di Automation funziona come alternativa diretta.

#### Prerequisiti

Si applicano gli stessi prerequisiti del webhook di sistema:

* **Abilita integrazione JIRA** e **Abilita webhook JIRA** sono entrambi selezionati nella pagina ⚙️ **Configurazione \> Impostazioni di sistema**.
* Nella stessa pagina è impostato un **segreto webhook Jira** non vuoto. Il secret può contenere solo i caratteri `A-Z`, `a-z`, `0-9`, `_` e `-`.
* Il Riscontro (o il Gruppo di Riscontri) è già collegato al problema Jira. Se il problema non è collegato a un Riscontro di DefectDojo, la richiesta viene comunque accettata (HTTP `200`), ma non viene eseguita alcuna azione.

#### Come DefectDojo elabora la richiesta

* DefectDojo effettua una diramazione in base a un campo `webhookEvent` di primo livello. Vengono elaborati solo `"jira:issue_updated"` e `"comment_created"`; qualsiasi altro valore viene accettato e ignorato. Automation **non** aggiunge questo campo automaticamente, quindi è necessario includerlo personalmente nel corpo della richiesta.
* Per questo motivo, impostare il **Corpo** della richiesta su **Dati personalizzati** e fornire il JSON riportato di seguito. Le opzioni del corpo **Vuoto** e **Dati del problema Jira** non includono il campo `webhookEvent` richiesto, quindi DefectDojo le ignorerà.
* L'endpoint restituisce sempre HTTP `200`, indipendentemente dal fatto che un aggiornamento sia stato applicato o meno. L'esito positivo o negativo è visibile solo nel corpo della risposta e nei log di DefectDojo — un `200` nel log di controllo di Automation **non** conferma da solo che l'aggiornamento abbia raggiunto un Riscontro.

#### Regola 1 — Problema aggiornato

Creare una regola di Automation con:

* **Trigger:** *Transizione del problema* (o un altro trigger che si attiva quando cambiano i campi sincronizzati, ad es. *Valore del campo modificato* sullo Stato).
* **Azione:** *Invia richiesta web*
  * **URL della richiesta web:** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **Metodo HTTP:** `POST`
  * **Corpo della richiesta web:** *Dati personalizzati*
  * **Intestazioni:** `Content-Type: application/json`
  * **Dati personalizzati:**

```json
{
  "webhookEvent": "jira:issue_updated",
  "issue": {
    "id": "{{issue.id}}",
    "fields": {
      "updated": "{{issue.updated}}",
      "resolution": null,
      "status": { "statusCategory": { "key": "{{issue.status.statusCategory.key}}" } },
      "assignee": { "name": "{{issue.assignee.accountId}}", "displayName": "{{issue.assignee.displayName}}" }
    }
  }
}
```

Vincoli per gli aggiornamenti dei problemi:

* `issue.id` deve essere l'**ID numerico interno del problema Jira** (`{{issue.id}}`), non la chiave del problema (ad es. `PROJ-123`). DefectDojo associa l'aggiornamento a un Riscontro tramite questo ID numerico.
* I campi `resolution` e `updated` devono essere sempre presenti. `resolution` può essere `null`, ma se uno dei due campi manca, la richiesta viene accettata (`200`) e non viene elaborata, senza alcun avviso.
* La sincronizzazione dello stato e la mitigazione automatica sono determinate da `status.statusCategory.key`, i cui valori Jira sono `new` (Da fare), `indeterminate` (In corso) e `done` (Completato). Un Riscontro viene mitigato solo quando il problema è effettivamente chiuso, non semplicemente perché è presente un valore di risoluzione.

#### Regola 2 — Problema commentato

Creare una seconda regola di Automation con:

* **Trigger:** *Problema commentato*
* **Azione:** *Invia richiesta web* — stessi URL, metodo, intestazione e opzione del corpo *Dati personalizzati* della Regola 1, con questo corpo:

```json
{
  "webhookEvent": "comment_created",
  "comment": {
    "self": "https://<your-jira-host>/rest/api/2/issue/{{issue.id}}/comment/{{comment.id}}",
    "body": "{{comment.body}}",
    "updateAuthor": { "name": "{{comment.author.accountId}}", "displayName": "{{comment.author.displayName}}" }
  }
}
```

Vincoli per i commenti:

* Devono essere presenti sia `body` sia `updateAuthor`.
* DefectDojo ricava il problema di destinazione dall'URL `comment.self` — in particolare l'`<id>` nel segmento `.../issue/<id>/comment/...` — quindi `{{issue.id}}` (l'ID numerico) deve comparire lì.
* **Prevenzione dei loop:** se l'autore del commento corrisponde all'account Jira utilizzato da DefectDojo per pubblicare i propri commenti, DefectDojo ignora il commento per evitare un loop di eco. Se si desidera che *tutti* i commenti vengano acquisiti, eseguire la regola di Automation con un utente Jira **diverso** da quello configurato nell'istanza Jira di DefectDojo.

#### Una nota sugli smart values

Gli smart values mostrati sopra (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}`, e così via) sono i nomi standard di Jira Cloud, ma possono variare da un'istanza all'altra. Prima di passare in produzione, utilizzare l'anteprima del payload di Automation per verificare che ogni smart value corrisponda al valore atteso.

## Test dell'integrazione con Jira

#### Test 1: i Riscontri vengono inviati correttamente a Jira?

Per verificare che l'integrazione con Jira funzioni correttamente, puoi aggiungere un nuovo Riscontro vuoto al Prodotto associato a Jira in DefectDojo. **Prodotto \> Riscontri \> Aggiungi nuovo riscontro.**

Aggiungi il titolo, la gravità e la descrizione che preferisci, quindi fai clic su "Finished". Il Riscontro dovrebbe comparire come Issue in Jira con tutti i metadati pertinenti.

Se gli Issue di Jira non vengono creati correttamente, controlla le tue Notifiche per eventuali codici di errore.

* Verifica che l'Utente Jira associato alla Configurazione Jira di DefectDojo disponga dei permessi per creare e aggiornare gli issue in quello specifico Jira Space.

#### Test 2: i Webhook di Jira vengono inviati a DefectDojo

Per verificare i Webhook di Jira, aggiungi una Nota a un Riscontro che esiste anche in JIRA come Issue (ad esempio, l'Issue di test della sezione precedente).

Se i webhook sono configurati correttamente, dovresti vedere la Nota in Jira come commento sull'issue.

Se questo non funziona correttamente, potrebbe essere dovuto a un problema di Firewall sulla tua istanza Jira che blocca il Webhook.

* Le regole del Firewall di DefectDojo includono una casella di controllo per **Jira Cloud,** che deve essere abilitata prima che DefectDojo possa ricevere i messaggi Webhook da Jira.

## Disconnessione da Jira

Le integrazioni Jira possono essere rimosse dalla tua istanza solo se non sono stati creati Issue correlati. Se sono stati creati degli Issue, non è possibile rimuovere completamente un'istanza Jira da DefectDojo.

Tuttavia, puoi disabilitare l'integrazione con Jira disattivandola a livello di Prodotto. Dal modulo **Edit Product** puoi deselezionare l'opzione "Enable Connection With Jira Space". Questo non eliminerà né modificherà i ticket Jira esistenti creati da DefectDojo, ma disabiliterà eventuali aggiornamenti futuri.

# Invio dei Riscontri a Jira

## Invio dei Riscontri a Jira
Un Prodotto con un mapping JIRA può inviare i Riscontri a Jira come Issue. Questo può essere gestito in due modi diversi:

* I Riscontri possono essere creati come Issue manualmente, per\-Riscontro.
* I Riscontri possono essere inviati automaticamente se l'opzione '**Push All Issues**' è abilitata su un Prodotto. (Questo vale solo per i Riscontri che sono **Attivi** e **Verificati**).

Inoltre, hai la possibilità di inviare Gruppi di Riscontri a Jira invece dei singoli Riscontri. Questo creerà un unico Issue contenente molti Riscontri DefectDojo correlati.

### Invio manuale di un Riscontro

1. Dalla pagina di un Riscontro in DefectDojo, vai alla sezione **JIRA**. Se il Riscontro non esiste già in JIRA come Issue, l'intestazione JIRA avrà il valore '**None**'.
​
2. Facendo clic sulla freccia accanto al valore **None** verrà creato un nuovo issue Jira. Lo stato in cui viene creato l'issue dipenderà dal workflow del tuo team e dalla configurazione Jira con DefectDojo. Se il Riscontro non compare, aggiorna la pagina.
​
![immagine](images/Creating_Issues_in_Jira.png)

3. Una volta creato l'Issue, DefectDojo creerà un link all'issue composto dalla key di Jira e dall'Issue ID. Questo link avrà anche un cestino rosso accanto, per permetterti di eliminare l'Issue da Jira.
​
![immagine](images/Creating_Issues_in_Jira_2.png)

4. Facendo di nuovo clic sulla freccia verranno inviate a Jira tutte le modifiche apportate a un issue, aggiornando di conseguenza l'Issue Jira. Se l'opzione '**Push All Issues**' è abilitata sul Prodotto associato al Riscontro, questo processo avverrà automaticamente.

### Commenti di Jira

* Se viene aggiunto un commento a un Issue Jira, lo stesso commento verrà aggiunto al Riscontro, nella sezione **Note**.
* Allo stesso modo, se viene aggiunta una Nota a un Riscontro, la Nota verrà aggiunta all'issue Jira come commento.

### Cambi di Status in Jira

La Configurazione Jira su DefectDojo include voci per due Transition di Jira che attiveranno un cambio di stato su un Riscontro.

* Quando la **'Close' Transition** viene eseguita su Jira, anche il Riscontro associato si chiuderà, venendo contrassegnato come **Inattivo** e **Mitigato** su DefectDojo. DefectDojo registrerà questa modifica nella pagina del Riscontro, sotto l'intestazione **Mitigato da**.
​
![immagine](images/Creating_Issues_in_Jira_3.png)

* Quando la **'Reopen' Transition** viene eseguita sull'Issue Jira, il Riscontro associato verrà impostato come **Attivo** su DefectDojo e perderà lo stato **Mitigato**.

### Mappatura delle Resolution di Jira su Accettazione del rischio / Falso positivo

Oltre alle transition Close / Reopen, la Configurazione Jira include campi facoltativi che ti permettono di mappare una **Resolution** di Jira su uno stato del Riscontro in DefectDojo. Questi vengono impostati durante la procedura **Add Jira Configuration (Express)** (passaggi 6 e 7) e possono essere modificati in seguito nella Configurazione Jira:

* **Risk Accepted Finding Mapping Resolution** — quando un issue Jira viene chiuso con questa Resolution, il Riscontro collegato diventa Rischio accettato in DefectDojo.
* **False Positive Finding Mapping Resolution** — quando un issue Jira viene chiuso con questa Resolution, il Riscontro collegato diventa Falso positivo in DefectDojo.

#### Status vs Resolution: un punto di confusione comune

Questi campi mappano la **Resolution** di Jira, non lo **Status** di Jira. Status e Resolution sono due concetti Jira indipendenti: lo Status descrive a che punto si trova l'issue nel workflow (Open, In Progress, Done), mentre la Resolution descrive come è stato risolto (Fixed, Won't Do, Duplicate, False Positive, ecc.).

Un errore comune è che una transition del workflow di Jira può cambiare lo Status in "Done" *senza* impostare alcuna Resolution. Quando ciò accade, il mapping delle resolution di DefectDojo non si attiva mai — il Riscontro viene invece contrassegnato come **Mitigato** dal comportamento standard della **'Close' Transition** descritto sopra, non come Rischio accettato o Falso positivo.

#### Prerequisito: un post-function "Set issue resolution" sulla transition del workflow di Jira

Il motore di workflow di Jira non popola automaticamente il campo Resolution. Ogni transition che deve chiudere un issue con una Resolution specifica necessita di un post-function **Set issue resolution** configurato sulla transition stessa. Senza quel post-function, l'issue passa al nuovo Status ma la Resolution resta vuota, e il mapping di DefectDojo non ha nulla con cui corrispondere.

Un amministratore Jira può aggiungere questo post-function da **Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution**.

## Invio dei Gruppi di Riscontri come Issue Jira

Se hai i Gruppi di Riscontri abilitati, puoi inviare un Gruppo di Riscontri a Jira come un singolo Issue anziché come Issue separati per ciascun Riscontro.

L'Issue Jira associato a un Gruppo di Riscontri non può però essere gestito o eliminato da DefectDojo. Deve essere eliminato direttamente dall'istanza Jira.

### Creazione e invio automatico dei Gruppi di Riscontri

Con Auto\-Push To Jira abilitato e un'opzione Group By selezionata durante l'import:

Finché i Gruppi di Riscontri vengono creati correttamente, sarà il Gruppo di Riscontri a essere inviato automaticamente a Jira come Issue, e non i singoli Riscontri.

![immagine](images/Creating_Issues_in_Jira_4.png)

## Campi personalizzati in Jira
<span style="background: rgba(243, 122, 78,0.5">Al momento DefectDojo non supporta il passaggio di informazioni specifiche dell'Issue in questi campi personalizzati \- questi campi dovranno essere aggiornati manualmente in Jira dopo la creazione dell'issue. Ogni campo personalizzato verrà creato da DefectDojo solo con un valore predefinito.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud ora ti permette di creare un valore predefinito per i campi personalizzati direttamente nell'app. [Consulta la documentazione di Atlassian sui campi personalizzati](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) per maggiori informazioni su come configurarlo.</span>

I Jira Issue Type predefiniti di DefectDojo (**Bug, Task, Story** e **Epic)** sono già pronti all'uso. I campi dati di DefectDojo vengono mappati automaticamente sui campi corrispondenti in Jira. Per impostazione predefinita, DefectDojo assegna Priority, Labels e un Reporter a ogni nuovo Issue che crea.

Alcune configurazioni Jira richiedono che vengano gestiti campi personalizzati aggiuntivi prima che un issue possa essere creato. Questo procedimento ti permetterà di gestire questi campi personalizzati nella tua integrazione DefectDojo \-\> Jira, garantendo che gli issue vengano creati correttamente. Questi campi personalizzati verranno aggiunti a tutte le chiamate API inviate da DefectDojo a un'istanza Jira collegata.

Se non utilizzi già i campi personalizzati in Jira, non è necessario seguire questo procedimento.

1. Annotare i nomi dei tuoi campi personalizzati in Jira (**Jira UI**)
2. Determinare i valori key per i nuovi campi personalizzati (Jira Field Spec Endpoint)
3. Individuare i dati accettabili per ciascun campo personalizzato, usando i valori key come riferimento (Jira Issue Endpoint)
4. Creare un blocco JSON di Field Reference per tenere traccia di tutte le key dei campi personalizzati e dei dati accettabili (Jira Issue Endpoint)
5. Salvare il blocco JSON nel Prodotto DefectDojo associato, per permettere la creazione dei campi personalizzati da Jira (DefectDojo UI)
6. Testare il lavoro svolto e verificare che tutti i dati richiesti arrivino correttamente da Jira

#### Passaggio 1: annota i nomi dei tuoi campi personalizzati in Jira

Jira supporta diversi tipi di Context Field, tra cui Date Picker, Custom Label e Radio Button. Ognuno di questi Context Field avrà un valore key diverso, reperibile nella Jira API.

Annota i nomi di ciascun campo personalizzato richiesto, perché dovrai cercarli nella Jira API nel passaggio successivo.

**Esempio di elenco di campi personalizzati (i nomi dei tuoi campi personalizzati saranno diversi):**

* DefectDojo Custom URL Field
* Un altro esempio di campo personalizzato
* ...

#### Passaggio 2: trova i valori key dei tuoi campi personalizzati di Jira

Inizia questo procedimento accedendo al Field Spec URL della tua intera istanza Jira.

Ecco un esempio di Field Spec URL:

`https://yourcompany-example.atlassian.net/rest/api/2/field`

L'API restituirà una lunga stringa JSON, che dovrebbe essere formattata in un testo leggibile (usando un editor di codice, un'estensione del browser o <https://jsonformatter.org/>).

Il JSON restituito da questo URL conterrà tutti i campi personalizzati di Jira, molti dei quali irrilevanti per DefectDojo e con valore `"Null"`. Ogni oggetto in questa risposta API corrisponde a un campo diverso in Jira. Dovrai cercare gli oggetti che hanno attributi `"name"` corrispondenti ai nomi di ciascun campo personalizzato che hai creato nella Jira UI, e poi annotare il valore del loro attributo "key".

![immagine](images/Using_Custom_Fields.png)

Una volta trovato l'oggetto corrispondente nell'output JSON, puoi determinare il valore "key" \- in questo caso, è `customfield_10050`.

Jira genera valori key diversi per ogni campo personalizzato, ma questi valori key non cambiano una volta creati. Se in futuro crei un altro campo personalizzato, avrà un nuovo valore key.

**Ampliando il nostro elenco di campi personalizzati:**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Un altro esempio di campo personalizzato" \= customfield\_12345
* ...

#### Passaggio 3 \- trova i campi personalizzati su un Issue Jira

Individua un Issue in Jira che contenga i campi personalizzati annotati nel Passaggio 2\. Copia la Issue Key per il titolo (dovrebbe assomigliare a "`EXAMPLE-123`") e vai al seguente URL:

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

Questo restituirà un'altra stringa JSON.

Come prima, l'output dell'API conterrà molti parametri oggetto `customfield_##` con valori `null` \- questi sono campi personalizzati che Jira aggiunge per impostazione predefinita, non rilevanti per questo issue. Conterrà anche valori `customfield_##` che corrispondono ai valori key dei campi personalizzati trovati nel passaggio precedente. A differenza dell'output del Field Spec, qui non vedrai nomi che identificano questi campi personalizzati, motivo per cui dovevi annotare i valori key nel Passaggio 2\.

![immagine](images/Using_Custom_Fields_2.png)

**Example:**
Sappiamo che `customfield_10050` rappresenta il DefectDojo Custom URL Field perché lo abbiamo annotato nel Passaggio 2\. Possiamo ora vedere che `customfield_10050` contiene un valore `"https://google.com"` nell'issue `EXAMPLE-123`.

#### Passaggio 4 \- crea un Field Reference JSON da ogni key dei campi personalizzati di Jira

Ora dovrai prendere il valore di ciascuno dei campi personalizzati dal tuo elenco e memorizzarli in un oggetto JSON (da usare come riferimento). Puoi ignorare i campi personalizzati che non corrispondono al tuo elenco.

Questo oggetto JSON conterrà tutti i valori predefiniti per i nuovi Issue Jira. Ti consigliamo di usare nomi facili da riconoscere per il tuo team come valori 'predefiniti' da modificare: '`change-me.com`', '`Change this paragraph.`' ecc.

**Example:**

Dal passaggio 3, ora sappiamo che Jira si aspetta una stringa URL per "`customfield_10050`". Possiamo usare questa informazione per costruire il nostro oggetto JSON di esempio.

Supponiamo di aver individuato anche un campo di testo breve relativo a DefectDojo, identificato come "`customfield_67890`". Osserveremmo questo campo nel nostro secondo output dell'API, guarderemmo il valore associato e riporteremmo anche il valore memorizzato nel nostro oggetto JSON di esempio.
​
Il tuo oggetto JSON inizierà ad assomigliare a questo man mano che aggiungi altri campi personalizzati.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Ripeti questo procedimento finché tutti i campi personalizzati di Jira rilevanti per DefectDojo non sono stati aggiunti al tuo Field Reference JSON.

#### Tipi di dati \& sintassi di Jira

Alcuni campi, come i campi Date, possono corrispondere a più campi personalizzati in Jira. In tal caso, dovrai aggiungere entrambi i campi al tuo Field Reference JSON.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Altri campi, come il campo Label, potrebbero essere gestiti come un elenco di stringhe \- assicurati che il tuo Field Reference JSON utilizzi un formato che corrisponda all'output dell'API di Jira.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

Altri campi personalizzati potrebbero contenere informazioni aggiuntive, contestuali, che dovrebbero essere rimosse dal Field Reference. Ad esempio, il Custom Multichoice Field contiene un blocco aggiuntivo nell'output dell'API, che dovrai rimuovere, poiché questo blocco memorizza il valore attuale del campo.

* devi rimuovere l'oggetto aggiuntivo da questo campo:

```
"customfield_10047": [
    {
      "value": "A"
    },
    {
      "self": "example.url...",
      "value": "C",
      "id": "example ID"
    }
]
```
* in alternativa, puoi abbreviarlo come segue e ignorare la seconda parte:

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Esempio di Field Reference completato

Ecco un Field Reference JSON completo, con commenti in\-line che spiegano a cosa si riferisce ciascun campo personalizzato. Questo vuole essere un esempio onnicomprensivo. Il tuo JSON conterrà valori key e dati diversi, a seconda dei valori personalizzati che vuoi utilizzare durante la creazione dell'issue.

```
{
  "customfield_10050": "https://change-me.com",

  "customfield_10049": "This is a short text custom field",

// two different fields, but both correspond to the same custom date attribute
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",

// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],

// custom number field
  "customfield_10043": 0,

// custom paragraph field
  "customfield_10044": "This is a very long winded way to say CHANGE ME PLEASE",

// custom radio button field
  "customfield_10045": {
    "value": "radio button option"
  },

// custom multichoice field
  "customfield_10047": [
    {
      "value": "A"
    }
  ],

// custom checkbox field
  "customfield_10039": [
    {
      "value": "A"
    }
  ],

// custom select list (singlechoice) field
  "customfield_10048": {
    "value": "1"
  }
}
```

#### Passaggio 5 \- aggiungi i campi personalizzati a un Prodotto DefectDojo

Ora puoi aggiungere questi campi personalizzati al Prodotto DefectDojo associato, nella sezione Custom Fields. Di nuovo,

* Vai su Edit Product \- defectdojo.com/product/ID/edit .
* Vai su Custom fields e incolla il Field Reference JSON come testo semplice nella casella Custom Fields.
* Fai clic su 'Submit'.

#### Passaggio 6 \- testa i campi personalizzati di Jira da un nuovo Riscontro:

A questo punto, quando crei un nuovo Riscontro nel Prodotto associato a Jira, Jira creerà automaticamente tutti questi campi personalizzati in Jira in base al blocco JSON in esso contenuto. Questi campi personalizzati verranno creati con i valori predefiniti ("change\-me\-please", ecc.).

All'interno del Prodotto su DefectDojo, vai alla pagina Riscontri \> Aggiungi nuovo riscontro. Assicurati che il Riscontro sia Attivo e Verificato per garantire che venga inviato a Jira, quindi verifica lato Jira che i campi personalizzati siano stati creati correttamente senza incongruenze.
