---
title: Jira (Legacy)
description: Lavorare con l'integrazione Jira
weight: 1
audience: pro
aliases:
- /it/issue_tracking/jira/pro__jira_guide/
- /it/en/share_your_findings/jira_guide
---

> **Questa pagina documenta l'integrazione Jira legacy.** L'integrazione Jira per prodotto qui descritta è stata sostituita dal **[Connettore downstream Jira](/connectors/downstream/about/)**, disponibile su tutte le istanze di DefectDojo Pro e rappresenta il metodo consigliato per inviare i Riscontri a Jira. Nella barra laterale di Pro, **Connetti > Jira** mostra un badge `LEGACY` proprio per questo motivo — vedere [Badge dei menu](/navigation/pro__menu_badges/).
>
> **Se stai configurando Jira per la prima volta, inizia dal [Connettore downstream](/connectors/downstream/about/) invece che da questa guida.**
>
> **Stai già usando l'integrazione legacy?** DefectDojo Pro include una migrazione integrata che sposta la tua configurazione Jira classica esistente sui Connettori downstream, inclusi i ticket già inviati — vedere [Migrazione al Connettore downstream Jira](#migrating-to-the-jira-downstream-connector) più sotto.
>
> L'integrazione legacy continua a funzionare, e questa guida resta valida per essa.

L'integrazione Jira di DefectDojo può essere usata per inviare i dati dei Riscontri a uno o più Spazi Jira. Così facendo, puoi integrare DefectDojo nel tuo normale flusso di lavoro di sviluppo. Ecco alcuni esempi di come questo può funzionare:

* Il team AppSec può inviare selettivamente i Riscontri a uno Spazio Jira usato dagli sviluppatori, in modo che la correzione dei problemi possa essere opportunamente prioritizzata insieme al normale sviluppo. Gli sviluppatori su questa bacheca non hanno bisogno di accedere a DefectDojo - possono tenere tutto il loro lavoro in un unico posto.
* DefectDojo può inviare TUTTI i Riscontri a uno Spazio Jira bidirezionale usato dal team AppSec, il che consente loro di suddividere la convalida dei problemi. Questa bacheca resta sincronizzata con DefectDojo e permette flussi di lavoro di correzione complessi.
* DefectDojo può inviare selettivamente i Riscontri da singoli Prodotti e/o Engagement a Spazi Jira separati, per mantenere ogni cosa nel proprio contesto.

## Migrazione al Connettore downstream Jira

DefectDojo Pro può convertire per te una configurazione Jira classica esistente in una configurazione del Connettore downstream, invece di farti ricostruire tutto manualmente.

**Dove trovarla:** vai su **Connetti \> Downstream** per aprire la pagina **Connettori downstream**, e usa la scheda **Migrazione classica di Jira**. Fai clic su **Migra da Jira classico**, quindi conferma.

La scheda compare solo se esiste una configurazione Jira classica da migrare, oppure un'esecuzione precedente da segnalare — quindi un'istanza che non ha mai usato Jira classico non la vedrà. Una volta completata la migrazione di tutto, la scheda resta visibile ma il pulsante è disabilitato, perché non c'è più nulla da fare.

Per eseguire la migrazione sono necessari **permessi globali di livello Maintainer** (nello specifico, il permesso di modificare le integrazioni), e deve essere avviata da una sessione del browser con accesso effettuato — non può essere eseguita con un token API.

### Cosa succede ai ticket già inviati

**I tuoi ticket Jira esistenti vengono conservati e ricollegati — non restano orfani, e il connettore non ne apre di duplicati.** Ogni Riscontro che Jira classico aveva già inviato mantiene il proprio ticket, e il connettore prende in carico l'aggiornamento dello stesso ticket. I collegamenti sui Gruppi di riscontri vengono trasferiti allo stesso modo.

L'unica eccezione sono gli **Epic di Engagement**. Il Connettore downstream non ha alcun concetto di Epic, quindi i ticket Epic vengono segnalati negli avvisi della migrazione e lasciati invariati.

### Cosa viene migrato

* La connessione della tua **istanza** Jira — URL e credenziali — diventa un'istanza di integrazione Connettore downstream, mantenendo il proprio nome.
* Le **mappature di gravità** e le **mappature di stato** (le chiavi di transizione di apertura e chiusura) vengono trasferite.
* Ogni configurazione di **Progetto Jira** diventa una mappatura del tracker dei ticket, mantenendo la chiave di progetto e il tipo di ticket, e resta assegnata allo stesso Prodotto o Engagement.
* **Invia tutti i ticket** viene preservato: i progetti che lo avevano abilitato continuano a inviare automaticamente.
* **Campi personalizzati**, **campi di transizione di chiusura/riapertura**, **componente**, **assegnatario predefinito** ed **etichette** vengono convertiti in mappature di campo. Dove usavi *Aggiungi ID vulnerabilità come etichetta Jira*, questo diventa anche una mappatura di etichetta.
* Una directory di **modello di ticket personalizzato** diventa un modello di ticket. I modelli standard non vengono copiati, perché il connettore include già i propri equivalenti.

### Cosa non viene trasferito

Questi elementi vengono segnalati come avvisi nell'esecuzione della migrazione — non la bloccano. Cerca l'elenco *"cose che il connettore non può trasferire"* nei risultati.

* **Sincronizzazione inversa da Jira a DefectDojo.** Questo è il punto importante. Il Connettore downstream non sincronizza le modifiche *in senso inverso* da Jira, quindi le mappature di risoluzione che applicano Rischio accettato o Falso positivo a partire da una risoluzione Jira non vengono migrate. **Se ti affidi alla sincronizzazione inversa, lascia configurata l'istanza Jira classica** — la migrazione non la rimuove.
* **Mappatura Epic di Engagement** — il connettore non ha alcun concetto di Epic.
* **Invia note**, **commenti di notifica SLA** e **commenti di scadenza dell'accettazione del rischio** — il connettore non li pubblica su Jira.
* I campi personalizzati chiamati `summary`, `description`, `project`, `issuetype` o `status` — questi sono riservati dal connettore, e una mappatura di campo che ne usa uno viene ignorata.
* I valori dei campi personalizzati più lunghi di 512 caratteri — vengono ignorati anziché troncati.
* Un Progetto Jira non associato né a un Prodotto né a un Engagement non produce alcuna assegnazione.

### Cosa succede all'integrazione classica in seguito

**Niente viene inviato due volte.** Per ogni progetto che migra, la migrazione disattiva il progetto Jira classico corrispondente, quindi da quel momento in poi invia solo il connettore. Non è necessario disabilitare nulla manualmente.

La tua configurazione classica viene **conservata, non eliminata** — l'istanza, il progetto e i record dei ticket restano tutti presenti, con solo le impostazioni di invio disattivate. Questo è intenzionale: è ciò che rende la modifica reversibile, ed è ciò che mantiene funzionante la sincronizzazione inversa se ne hai bisogno.

**Per tornare indietro**, riattiva le impostazioni del progetto Jira classico e rimuovi la configurazione del connettore creata dalla migrazione. Non esiste un ripristino con un solo clic.

**Rieseguirla è sicuro.** La migrazione registra ciò che ha già convertito e lo salta in una seconda esecuzione, quindi nulla viene duplicato. Se un progetto o un'istanza fallisce, il resto viene comunque migrato — un progetto non riuscito viene lasciato in esecuzione sull'integrazione classica invece di essere disattivato, così continua a funzionare mentre indaghi.

### Durante l'esecuzione

La migrazione viene eseguita in background e segnala i progressi man mano che procede. Al termine ottieni un riepilogo — quanti connettori, mappature, assegnazioni, modelli e collegamenti ai ticket sono stati creati, quanti progetti classici sono stati disattivati e cosa è stato ignorato — insieme agli avvisi descritti sopra. Viene eseguita una sola migrazione alla volta.

# Configurazione di Jira

La configurazione di Jira richiede i seguenti passaggi:
1. Abilita l'integrazione Jira in System Settings. Finché non lo fai, il resto delle impostazioni Jira resta nascosto in tutto DefectDojo.
2. Connetti un'Istanza Jira, con un nome utente/password oppure con un token API. È possibile collegare più istanze.
3. Aggiungi quell'Istanza Jira a uno o più Prodotti o Engagement all'interno di DefectDojo.
4. Se desideri usare la sincronizzazione bidirezionale, crea un Webhook Jira che invierà gli aggiornamenti a DefectDojo.

## Passaggio 1: abilitare l'integrazione Jira in System Settings

L'integrazione Jira è disattivata per impostazione predefinita, e finché è disattivata DefectDojo nasconde ogni altro controllo Jira nell'interfaccia. Questa è la prima cosa da configurare: nessuno dei passaggi seguenti è disponibile finché non viene abilitata.

Finché l'integrazione è disabilitata, non è presente alcuna voce **Jira Instances** nella barra laterale, quindi non c'è modo di aggiungere un'Istanza Jira:

![immagine](images/jira-menu-hidden-pro.png)

### Abilitare l'integrazione

1. Vai su **Settings \> System \> System Settings** dalla barra laterale di DefectDojo. Sulle istanze che usano ancora il layout di menu precedente, questa voce si trova in un gruppo denominato in base al tuo pacchetto di licenza — **Pro Settings** oppure **Enterprise Settings**. Vedere [Il menu delle impostazioni](/navigation/pro__settings_menu/).
​
2. Nella sezione **Jira Integration Settings**, seleziona **Enable Jira Integration**.
​
3. Fai clic su **Invia**. **Jira Instances** compare immediatamente nella barra laterale, senza dover ricaricare la pagina:

![immagine](images/jira-enable-system-settings-pro.png)

### Cosa controlla questa impostazione

Abilitare **Enable Jira Integration** è ciò che fa comparire il resto dell'interfaccia Jira. Attivandola ottieni:

* il menu **Jira Instances**, dove le Istanze Jira vengono aggiunte e modificate
* la pagina **Jira Project Settings** nel menu ⚙️ dell'Asset, e le impostazioni Jira sugli Engagement
* le azioni **Invia a Jira** su Riscontri e Gruppi di riscontri, i campi Jira nei moduli del Riscontro e di modifica collettiva, e le colonne Jira negli elenchi di Asset, Engagement, Riscontro e Gruppo di riscontri (incluse le esportazioni CSV)

L'impostazione regola l'integrazione anche al di fuori dell'interfaccia: finché è disattivata, DefectDojo non invierà i Riscontri a Jira (incluse le richieste `push_to_jira` inviate tramite l'API), e i webhook Jira in arrivo vengono ignorati.

I restanti campi Jira in **Jira Integration Settings** (**Add Vulnerability ID as Jira Label**, **Enable Jira Web Hook**, **Disable Jira Web Hook Secret**, **Jira Web Hook Secret**, **Jira Minimum Severity**) restano visibili sia che l'integrazione sia attiva sia che sia disattivata, ma non hanno alcun effetto finché non viene abilitata.

## Passaggio 2: connettere un'Istanza Jira

Con l'integrazione abilitata, connettere un'Istanza Jira è il passaggio successivo nella configurazione dell'integrazione Jira di DefectDojo. Nota che Jira Service Management non è attualmente supportato.

#### Informazioni richieste da Jira

Atlassian utilizza metodi di autenticazione diversi tra Jira Cloud e Jira Data Center.

per **Jira Cloud** ti servirà:
* un URL Jira, ad es. https://yourcompany.atlassian.net/
* un account con i permessi per creare e aggiornare ticket nella tua istanza Jira. Può trattarsi di:
    * Una combinazione standard di **nome utente / password**
    * Una combinazione di **nome utente / token API**

per **Jira Data Center (o Server)** ti servirà:
* un URL Jira, ad es. https://jira.yourcompany.com
* un account con i permessi per creare e aggiornare ticket nella tua istanza Jira. Può trattarsi di:
    * Una combinazione standard di **nome utente / password**
    * Una combinazione di **indirizzo email / Personal Access Token**

Facoltativamente, puoi mappare:
* Transizioni Jira per attivare la riapertura e la chiusura dei Riscontri
* Risoluzioni Jira che possono applicare gli stati Rischio accettato e Falso positivo ai Riscontri (facoltativo)

Una singola connessione a un'Istanza Jira può gestire più Spazi Jira, purché l'account / token Jira usato da DefectDojo abbia il permesso di creare ticket nello Spazio Jira associato.

### Aggiungere un'Istanza Jira

1. Assicurati che **Enable Jira Integration** sia selezionata in System Settings, come descritto nel [Passaggio 1](#step-1-enable-the-jira-integration-in-system-settings). Il menu **Jira Instances** non compare nella barra laterale finché non lo è.

2. Vai alla pagina **Enterprise Settings \> Jira Instances \> + New Jira Instance** dalla barra laterale di DefectDojo.

![immagine](images/jira-instance-beta.png)

3. Scegli un **Configuration Name** per questa Istanza Jira da usare in DefectDojo. Questo nome è semplicemente un'etichetta per la connessione dell'Istanza in DefectDojo, e non deve necessariamente essere collegato ai dati Jira.

4. Seleziona l'URL dell'istanza Jira della tua azienda, probabilmente simile a `https://**yourcompany**.atlassian.net` se stai usando un'installazione Jira Cloud.

5. Inserisci un metodo di autenticazione appropriato nei campi Username / Password per Jira:
    * Per l'**autenticazione standard Jira con nome utente / password**, inserisci in questi campi uno Username Jira e la Password corrispondente.
    * Per l'autenticazione con il **token API dell'utente (Jira Cloud)**, inserisci lo Username con il corrispondente **token API** nel campo password.
    * Per l'autenticazione con un **Personal Access Token Jira (detto anche PAT, usato solo in Jira Data Center e Jira Server)**, inserisci il PAT nel campo password. Lo Username non viene usato per l'autenticazione con un PAT Jira, ma il campo è comunque obbligatorio in questo modulo, quindi puoi usare qui un valore segnaposto per identificare il tuo PAT.

Nota che l'utente associato a questa connessione deve avere il permesso di creare ticket e accedere ai dati nella tua istanza Jira.

6. Dovrai fornire i valori per un Epic Name ID, un Re-open Transition ID e un Close Transition ID. Questi valori possono essere modificati in seguito. Mentre sei connesso a Jira, puoi ottenere questi valori dai seguenti URL:
- **Epic Name ID**: visita `https://<YOUR JIRA URL>/rest/api/2/field` e cerca Epic Name. Copia il numero contenuto in `number` e incollalo qui. Se non hai un Epic Name ID associato al tuo Spazio in Jira (ad esempio perché usi uno Spazio a gestione di team), inserisci 0 in questo campo.
- **Re-open Transition ID**: visita `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` per trovare l'ID della tua istanza Jira. Incollalo nel campo Reopen Transition ID.
- **Close Transition ID**: visita `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` per trovare l'ID della tua istanza Jira. Incollalo nel campo Close Transition ID.

7. Seleziona il tipo di ticket predefinito con cui creare i ticket in Jira. Le opzioni sono **Bug, Task, Story** ed **Epic** (che sono tipi di ticket Jira standard), oltre a **Spike** e **Security**, che sono tipi di ticket personalizzati. Se vuoi usare un tipo di ticket diverso, contatta [support@defectdojo.com](mailto:support@defectdojo.com) per assistenza.

8. Seleziona il tuo Modello di ticket, che determinerà la Descrizione del ticket quando i ticket vengono creati in Jira.

I due tipi sono:
- **Jira\_full**, che include tutte le informazioni del Riscontro nei ticket Jira
- **Jira\_limited**, che include una quantità minore di informazioni e metadati del Riscontro.

Se lasci questo campo vuoto, verrà usato per impostazione predefinita **Jira\_full.** Se hai bisogno di un tipo diverso di modello, contatta [support@defectdojo.com](mailto:support@defectdojo.com).

9. Se lo desideri, inserisci il nome di una Risoluzione Jira che cambierà lo stato di un Riscontro in Rischio accettato o in Falso positivo (quando la Risoluzione viene attivata sul ticket).

Da qui puoi inviare il modulo. Se lo desideri, puoi personalizzare ulteriormente la tua integrazione Jira in Optional Fields. Facendo clic su questo pulsante potrai applicare testo generico ai ticket Jira o modificare le mappature di gravità di Jira.

## Passaggio 3: connettere un Prodotto o un Engagement a Jira

Ogni Prodotto o Engagement in DefectDojo ha le proprie impostazioni che regolano il modo in cui i Riscontri vengono convertiti in ticket JIRA. Da qui puoi decidere lo Spazio Jira associato e impostare il comportamento predefinito per la creazione di ticket, Epic, etichette e altri metadati JIRA.

### Aggiungere Jira a un Prodotto

Puoi trovare questa pagina facendo clic sul menu a forma di ingranaggio di un Prodotto ⚙️ e aprendo la pagina **Jira Project Settings**.

![immagine](images/jira-project-settings.png)

#### Istanza Jira

Se hai configurato più istanze di Jira, per prodotti o team separati all'interno della tua organizzazione, puoi indicare in quale Spazio Jira vuoi che DefectDojo crei i ticket. Seleziona uno Spazio dal menu a tendina.

Se questo menu non elenca alcuna istanza Jira, verifica che quegli Spazi siano collegati nella tua Configurazione Jira globale per DefectDojo, su yourcompany.defectdojo.com/jira.

#### Chiave del progetto

Questa è la chiave dello Spazio che vuoi usare con DefectDojo. La Space Key di un determinato Spazio si trova nell'URL. (In precedenza era chiamata **Jira Project Key**, ma da settembre 2025 in Jira viene chiamata **Space Key**).

![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Nome del tipo di ticket Epic

Il nome del tipo di ticket Epic in Jira. Per impostazione predefinita è "Epic", ma può essere modificato se la tua istanza Jira usa un nome diverso.

#### Modello di ticket

Qui puoi determinare quanti metadati di DefectDojo vuoi inviare a Jira. Seleziona una delle due opzioni:

* **jira\_full**: i ticket terranno traccia di tutti i parametri di DefectDojo, ovvero una Descrizione completa, CVE, Gravità, ecc. Utile se hai bisogno del contesto completo del Riscontro in Jira (ad esempio, se qualcuno che lavora su questo ticket non ha accesso a DefectDojo).

Ecco un esempio di ticket **jira\_full**:
​
![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** i ticket terranno traccia solo del link a DefectDojo, dei link a Prodotto/Engagement/Test, e dei campi Reporter ed Environment. Tutti gli altri campi vengono tracciati solo in DefectDojo. Utile se non hai bisogno del contesto completo del Riscontro in Jira (ad esempio, se qualcuno che lavora su questo ticket opera principalmente in DefectDojo e non ha bisogno di avere il quadro completo anche in JIRA.)

​Ecco un esempio di ticket **jira\_limited**:

![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Componente

Se gestisci il tuo Spazio Jira usando i Componenti, qui puoi assegnare il Componente appropriato per DefectDojo. Per assegnare più di un Componente, inserisci un elenco separato da virgole (ad esempio, `Security, DevSecOps`); ogni valore viene inviato a Jira come componente separato.

#### Campi personalizzati

Se non hai bisogno di usare Campi personalizzati con i ticket di DefectDojo, puoi lasciare questo campo come 'null'.

Tuttavia, se le impostazioni del tuo Spazio Jira **richiedono** l'uso di Campi personalizzati sui nuovi ticket, dovrai impostare queste mappature come valori fissi.

Nota che DefectDojo non può inviare come Campi personalizzati alcun metadato specifico del ticket, ma solo un valore predefinito. Questa sezione dovrebbe essere configurata solo se il tuo Spazio Jira **richiede che questi Campi personalizzati esistano** in ogni ticket del tuo Spazio.

Segui **[questa guida](#custom-fields-in-jira)** per iniziare a lavorare con i Campi personalizzati.

#### Campi di transizione di chiusura / riapertura

Alcuni workflow Jira **richiedono** che determinati campi siano impostati come parte di una transizione — ad esempio, un workflow che rifiuta di chiudere un ticket a meno che non vengano forniti un campo Risoluzione e un campo di giustificazione nella schermata di chiusura. L'impostazione Campi personalizzati descritta sopra si applica solo quando un ticket viene *creato*, quindi non può soddisfare questi workflow.

Senza queste impostazioni, DefectDojo invia le transizioni di chiusura / riapertura senza alcun campo. Un workflow che richiede dei campi rifiuterà quella transizione, e il Riscontro e il ticket Jira si disallineeranno: il Riscontro risulta Mitigato in DefectDojo mentre il ticket resta aperto in Jira.

Le impostazioni **Campi di transizione di chiusura** e **Campi di transizione di riapertura** accettano un oggetto JSON che viene inviato come payload `fields` della chiamata di transizione di chiusura / riapertura. Ad esempio, per chiudere i ticket con una Risoluzione *Won't Fix* più un valore di giustificazione:

```json
{
    "resolution": {"name": "Won't Fix"},
    "customfield_10200": "Risk accepted by security team #report-false-positive"
}
```

Lascia queste impostazioni come 'null' se il tuo workflow Jira non richiede campi sulle transizioni.

**Di quali campi hai bisogno?**

* Chiedi al tuo amministratore Jira quali campi sono presenti nelle **schermate di transizione** di chiusura / riapertura, e quali di essi sono imposti da un validatore. Il JSON configurato deve soddisfare **ogni** campo obbligatorio: se manca dal payload anche un solo campo obbligatorio, Jira rifiuta l'intera transizione e non imposta nulla — fornire solo alcuni dei campi obbligatori non è sufficiente.
* Al contrario, i campi devono essere presenti **nella schermata di transizione** per poter essere inviati: Jira rifiuta le transizioni che tentano di impostare campi non presenti nella schermata di quella transizione.
* Sui workflow creati con l'editor di workflow attuale di Jira Cloud, Jira compila automaticamente la Risoluzione predefinita del sito quando un ticket passa a uno stato della categoria "completato". Quindi, una Risoluzione obbligatoria da sola non bloccherà lì una transizione semplice, e l'uso pratico di `"resolution"` in questo payload è scegliere un valore *significativo* (ad esempio *False Positive*) invece di quello predefinito del sito. I workflow creati con l'editor classico, o con app di validazione del marketplace, possono comunque richiedere obbligatoriamente la Risoluzione.
* Le transizioni di riapertura in genere azzerano la Risoluzione tramite il workflow stesso, quindi **Campi di transizione di riapertura** di solito richiede solo i campi personalizzati richiesti dal tuo workflow.

**Note:**

* Lo stesso JSON viene inviato per *ogni* transizione di chiusura (o riapertura) per il Prodotto o l'Engagement — i valori sono statici e non variano per singolo Riscontro. Se hai bisogno di campi diversi in base all'esito (ad esempio, una Risoluzione diversa per i Riscontri Falso positivo rispetto a quelli corretti), usa il DefectDojo Pro Jira Integrator, che supporta mappature di campo per transizione in base allo stato.
* I valori usano lo stesso formato della REST API di Jira: stringhe per i campi di testo, `{"name": ...}` per le risoluzioni, `[{"name": ...}]` per i campi a selezione multipla, e così via.
* Se le transizioni sono state rifiutate mentre queste impostazioni erano mancanti o incomplete, correggere le impostazioni ripara il disallineamento: il successivo invio di stato per il Riscontro ritenta la transizione con i campi configurati.
* Entrambe le impostazioni sono disponibili anche sull'endpoint REST `/api/v2/jira_projects/` (`close_transition_fields` / `reopen_transition_fields`), quindi possono essere gestite tramite l'API.
* Questi campi vengono applicati anche quando DefectDojo chiude un ticket perché il relativo Riscontro è stato **eliminato** — i valori vengono acquisiti nel momento in cui la chiusura viene messa in coda.

#### Etichette Jira

Seleziona le etichette pertinenti con cui vuoi che il ticket venga creato in Jira, ad es. **DefectDojo**, **YourProductName..**

![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Assegnatario predefinito

Il nome dell'assegnatario predefinito in Jira. Se lasciato vuoto, DefectDojo seguirà il comportamento predefinito del tuo Spazio Jira durante la creazione dei ticket.

### Jira Project Settings

#### Abilitato

Questo interruttore controlla se DefectDojo invia i Riscontri a Jira per questo Prodotto. Disabilitarlo non eliminerà né modificherà i ticket Jira esistenti creati da DefectDojo, ma impedirà ulteriori aggiornamenti o la creazione di nuovi ticket.

Le integrazioni Jira possono essere rimosse dalla tua istanza solo se non sono stati creati ticket correlati. Se sono stati creati dei ticket, non è possibile rimuovere completamente un'Istanza Jira da DefectDojo.

#### Aggiungere l'ID vulnerabilità come etichetta Jira

Questo ti consente di aggiungere automaticamente i dati dell'ID vulnerabilità come Etichetta Jira. Gli ID vulnerabilità vengono aggiunti ai Riscontri dai singoli strumenti di sicurezza, e possono essere ID Common Vulnerabilities and Exposures (CVE) oppure un formato diverso, specifico dello strumento che segnala il Riscontro.

#### Invia tutti i ticket

Se selezionata, DefectDojo invierà automaticamente a Jira come ticket tutti i Riscontri con stato Attivo e Verificato. Se lasciata deselezionata, tutti i Riscontri dovranno essere inviati a Jira manualmente (singolarmente o tramite invio collettivo).

Quando questa impostazione è abilitata, i ticket Jira continueranno a sincronizzarsi con DefectDojo anche se lo stato del Riscontro cambia.

#### Abilitare la mappatura Epic dell'Engagement

In DefectDojo, gli Engagement rappresentano un insieme di lavoro. Ogni Engagement contiene uno o più Test, che contengono uno o più Riscontri che devono essere mitigati. Gli Epic in Jira funzionano in modo simile, e questa casella di controllo ti consente di inviare gli Engagement a Jira come Epic.

* Un Engagement in DefectDojo, nota i tre Riscontri elencati in fondo.
​
![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* Come lo stesso Engagement diventa un Epic quando viene inviato a JIRA: anche i Riscontri dell'Engagement vengono inviati, e risiedono all'interno dell'Engagement come ticket figli.

![immagine](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Invia note

Se abilitata, i commenti di Jira compariranno sul Riscontro associato in DefectDojo, sotto Note, e viceversa; le Note sui Riscontri verranno aggiunte al ticket Jira associato come Commenti.

#### Invia le notifiche SLA come commenti

Se abilitata, su qualsiasi ticket che viola le regole di Service Level Agreement di DefectDojo verranno aggiunti dei commenti che lo indicano nel ticket Jira. Questi commenti verranno pubblicati quotidianamente finché il ticket non viene risolto.

I Service Level Agreement possono essere configurati in **Configuration \> SLA Configuration** in DefectDojo e assegnati a ciascun Prodotto.

#### Invia le notifiche di scadenza dell'accettazione del rischio come commento

Se abilitata, su qualsiasi ticket la cui Accettazione del rischio di DefectDojo associata scade verrà aggiunto un commento che lo indica nel ticket Jira. Questi commenti verranno pubblicati quotidianamente finché il ticket non viene risolto.

### Impostazioni Jira a livello di Engagement

Per impostazione predefinita, gli Engagement **ereditano le impostazioni Jira dal proprio Prodotto**. Tuttavia, puoi sovrascrivere le impostazioni Jira per i singoli Engagement.

Per accedere alle impostazioni Jira a livello di Engagement, fai clic sul menu a forma di ingranaggio ⚙️ su un Engagement e apri la pagina **Jira Project Settings**.

Da qui puoi deselezionare **Eredita dal Prodotto** e fornire valori specifici per l'Engagement per: **Chiave del progetto**, **Modello di ticket, Campi personalizzati, Etichette Jira, Assegnatario predefinito**, e altre impostazioni.

Nota che una volta che un Engagement ha un proprio progetto Jira assegnato, non può più ereditare dal Prodotto.

![immagine](images/Creating_Issues_in_Jira_5.png)

## Passaggio 4: configurare la sincronizzazione bidirezionale: webhook Jira

L'integrazione con Jira consente la sincronizzazione bidirezionale tramite webhook. DefectDojo riceve le notifiche di Jira a un indirizzo univoco, il che consente di ricevere commenti di Jira sui Riscontri, oppure di risolvere i Riscontri tramite Jira, a seconda della configurazione.

### Individuazione dell'URL del webhook Jira

Il webhook Jira si trova nel modulo delle impostazioni di sistema, sotto **Jira Integration Settings**: **Enterprise Settings \> System Settings** nella barra laterale.

È inoltre necessario selezionare **Enable Jira Web Hook** nella stessa pagina prima che DefectDojo possa elaborare le notifiche Jira in arrivo. I webhook in arrivo vengono ignorati se questa casella oppure **Enable Jira Integration** (vedere [Passaggio 1](#step-1-enable-the-jira-integration-in-system-settings)) non sono selezionate.

![image](images/Configuring_the_Jira_DefectDojo_Webhook.png)

### Creazione del webhook Jira

1. Visitare `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Fare clic su «Create a Webhook».
3. Nel campo denominato «URL» inserire: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. Il Web Hook Secret è indicato in Jira Integration Settings, come illustrato sopra.
4. In «Comments» attivare «Created». In Issue attivare «Updated».
5. Assicurarsi che l'istanza JIRA sia configurata per considerare attendibile il certificato SSL utilizzato dall'istanza DefectDojo. Per JIRA Cloud, DefectDojo deve utilizzare [un certificato SSL/TLS valido, firmato da un'autorità di certificazione riconosciuta a livello globale](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Da notare che non è necessario creare un Secret all'interno di Jira per utilizzare questo webhook. Il Secret è integrato nell'URL di DefectDojo, quindi è sufficiente aggiungere l'URL completo al modulo del webhook Jira.

Le richieste webhook in arrivo vengono autenticate tramite il secret contenuto in tale URL: trattare quindi l'URL completo come una credenziale e mantenerlo riservato.

#### Test del webhook

Una volta create una o più Issue a partire dai Riscontri di DefectDojo, è possibile testare il webhook aggiungendo un commento a uno di questi Riscontri. Il commento dovrebbe essere ricevuto dal webhook Jira come nota.

Se questo non funziona correttamente, potrebbe trattarsi di un problema del firewall sull'istanza Jira che blocca il webhook.

* Le regole firewall di DefectDojo includono una casella di controllo per **Jira Cloud,** che deve essere abilitata prima che DefectDojo possa ricevere i messaggi webhook da Jira.

### Alternativa: utilizzare Jira Automation (Send web request)

Alcune istanze Jira non consentono i webhook di sistema in `/plugins/servlet/webhooks` — ad esempio quando quell'area di amministrazione è limitata e sono ammesse solo le regole **Jira Automation**. In tal caso è possibile ottenere la stessa sincronizzazione bidirezionale usando l'azione **Send web request** di Automation, che invia una richiesta allo stesso endpoint webhook di DefectDojo.

L'endpoint webhook di DefectDojo accetta qualsiasi richiesta HTTP `POST` con `Content-Type: application/json` e un secret valido nel percorso dell'URL. **Non** richiede che la richiesta abbia origine dal meccanismo di webhook di sistema di Jira, quindi l'azione «Send web request» di Automation funziona come alternativa diretta.

#### Prerequisiti

Si applicano gli stessi prerequisiti del webhook di sistema:

* **Enable JIRA integration** e **Enable JIRA web hook** sono entrambe selezionate nella pagina ⚙️ **Configuration \> System Settings**.
* Nella stessa pagina è impostato un **Jira webhook secret** non vuoto. Il secret può contenere solo i caratteri `A-Z`, `a-z`, `0-9`, `_` e `-`.
* Il Riscontro (o il Gruppo di Riscontri) è già collegato all'issue Jira. Se l'issue non è collegata a un Riscontro DefectDojo, la richiesta viene comunque accettata (HTTP `200`) ma non viene eseguita alcuna azione.

#### Come DefectDojo elabora la richiesta

* DefectDojo si basa su un campo di primo livello `webhookEvent`. Vengono elaborati solo `"jira:issue_updated"` e `"comment_created"`; qualsiasi altro valore viene accettato e ignorato. Automation **non** aggiunge questo campo automaticamente, quindi è necessario includerlo personalmente nel corpo della richiesta.
* Per questo motivo, impostare **Body** della richiesta su **Custom data** e fornire il JSON riportato di seguito. Le opzioni di corpo **Empty** e **Jira issue data** non includono il campo `webhookEvent` richiesto, pertanto DefectDojo le ignorerà.
* L'endpoint restituisce sempre HTTP `200`, indipendentemente dal fatto che sia stato applicato un aggiornamento. L'esito positivo o negativo è visibile solo nel corpo della risposta e nei log di DefectDojo — un `200` nel log di controllo di Automation **non** conferma da solo che l'aggiornamento abbia raggiunto un Riscontro.

#### Regola 1 — Issue aggiornata

Creare una regola Automation con:

* **Trigger:** *Issue transitioned* (oppure un altro trigger che si attiva quando cambiano i campi sincronizzati, ad es. *Field value changed* su Status).
* **Action:** *Send web request*
  * **Web request URL:** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **HTTP method:** `POST`
  * **Web request body:** *Custom data*
  * **Headers:** `Content-Type: application/json`
  * **Custom data:**

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

Vincoli per gli aggiornamenti delle issue:

* `issue.id` deve essere l'**ID numerico interno dell'issue Jira** (`{{issue.id}}`), non la chiave dell'issue (ad es. `PROJ-123`). DefectDojo associa l'aggiornamento a un Riscontro tramite questo ID numerico.
* I campi `resolution` e `updated` devono essere sempre presenti. `resolution` può essere `null`, ma se uno dei due campi manca, la richiesta viene accettata (`200`) e non viene elaborata, senza alcun avviso.
* La sincronizzazione dello stato e la mitigazione automatica sono determinate da `status.statusCategory.key`, i cui valori Jira sono `new` (To Do), `indeterminate` (In Progress) e `done` (Done). Un Riscontro viene mitigato solo quando l'issue è effettivamente chiusa, non semplicemente perché è presente un valore di resolution.

#### Regola 2 — Issue commentata

Creare una seconda regola Automation con:

* **Trigger:** *Issue commented*
* **Action:** *Send web request* — stessi URL, metodo, header e opzione di corpo *Custom data* della Regola 1, con questo corpo:

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
* DefectDojo ricava l'issue di destinazione dall'URL `comment.self` — nello specifico il `<id>` nel segmento `.../issue/<id>/comment/...` — pertanto `{{issue.id}}` (l'ID numerico) deve comparire lì.
* **Prevenzione dei loop:** se l'autore del commento corrisponde all'account Jira che DefectDojo utilizza per pubblicare i propri commenti, DefectDojo ignora il commento per evitare un loop di eco. Per ingerire *tutti* i commenti, eseguire la regola Automation con un utente Jira **diverso** da quello configurato nell'istanza Jira di DefectDojo.

#### Nota sugli smart values

Gli smart values mostrati sopra (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}`, e così via) sono i nomi standard di Jira Cloud, ma possono variare da un'istanza all'altra. Prima di andare in produzione, utilizzare l'anteprima del payload di Automation per verificare che ogni smart value venga risolto come previsto.

## Test dell'integrazione Jira

#### Test 1: i Riscontri vengono inviati correttamente a Jira?

Per verificare che l'integrazione Jira funzioni correttamente, è possibile aggiungere un nuovo Riscontro vuoto al Prodotto associato a Jira in DefectDojo. **Prodotto \> Riscontri \> Add New Finding.**

Aggiungere il titolo, la gravità e la descrizione desiderati, quindi fare clic su «Finished». Il Riscontro dovrebbe comparire come Issue in Jira con tutti i metadati pertinenti.

Se le Issue Jira non vengono create correttamente, controllare le notifiche per individuare eventuali codici di errore.

* Verificare che l'utente Jira associato alla configurazione Jira di DefectDojo disponga dei permessi per creare e aggiornare issue in quello specifico spazio Jira.

#### Test 2: i webhook Jira inviano dati a DefectDojo

Per testare i webhook Jira, aggiungere una Nota a un Riscontro che esiste anche in JIRA come Issue (ad esempio, l'issue di test della sezione precedente).

Se i webhook sono configurati correttamente, la Nota dovrebbe comparire in Jira come commento sull'issue.

Se questo non funziona correttamente, potrebbe trattarsi di un problema del firewall sull'istanza Jira che blocca il webhook.

* Le regole firewall di DefectDojo includono una casella di controllo per **Jira Cloud,** che deve essere abilitata prima che DefectDojo possa ricevere i messaggi webhook da Jira.

## Disconnessione da Jira

Le integrazioni Jira possono essere rimosse dall'istanza solo se non sono state create Issue correlate. Se sono state create Issue, non è possibile rimuovere completamente un'istanza Jira da DefectDojo.

È tuttavia possibile disabilitare l'integrazione Jira disattivandola a livello di Prodotto. Nella pagina **Jira Project Settings** (accessibile tramite il menu ⚙️ Gear su un Prodotto), deselezionare l'interruttore **Enabled**. Questa operazione non elimina né modifica alcun ticket Jira esistente creato da DefectDojo, ma disabilita eventuali aggiornamenti futuri.

# Invio dei Riscontri a Jira

Un Prodotto con un mapping JIRA può inviare i Riscontri a Jira come Issue utilizzando diversi metodi. È possibile inviare i Riscontri singolarmente, in blocco, come Gruppi di Riscontri, oppure automaticamente.

## Invio di un singolo Riscontro

1. Aprire il Riscontro che si desidera inviare.
2. Fare clic su **☰ Finding Menu** e selezionare **Push to Jira**.
3. Confermare l'invio quando richiesto. DefectDojo creerà un'Issue Jira e la collegherà al Riscontro.

Una volta creata l'Issue, DefectDojo mostrerà un link all'Issue Jira nella pagina del Riscontro.

![image](images/Creating_Issues_in_Jira_2.png)

È anche possibile selezionare la casella **Push to Jira** durante la modifica di un Riscontro tramite il modulo **Edit Finding**. Quando il Riscontro viene salvato, verrà inviato a Jira.

### Aggiornamento di un'Issue Jira collegata

Se un Riscontro ha già un'Issue Jira collegata, selezionando nuovamente **Push to Jira** si aggiorna l'Issue Jira esistente con le modifiche effettuate in DefectDojo. Se **Push All Issues** è abilitato sul Prodotto, questa sincronizzazione avviene automaticamente.

### Scollegamento di un Riscontro da Jira

Per rimuovere l'associazione tra un Riscontro e la sua Issue Jira, fare clic su **☰ Finding Menu** e selezionare **Unlink From Jira**. Questo rimuove il collegamento in DefectDojo ma non elimina l'Issue Jira stessa.

## Invio in blocco dei Riscontri

È possibile inviare più Riscontri a Jira contemporaneamente utilizzando il modulo Bulk Update:

1. Da un elenco di Riscontri, selezionare i Riscontri che si desidera inviare utilizzando le caselle di controllo.
2. Aprire il modulo **Bulk Update**.
3. In **Jira Settings**, selezionare la casella **Push to Jira**.
4. Fare clic su **Submit**.

I Riscontri selezionati verranno messi in coda per l'invio a Jira. DefectDojo mostrerà un messaggio di conferma che indica quanti Riscontri sono stati messi in coda.

## Invio degli Engagement come Epic

Se **Enable Engagement Epic Mapping** è attivato nelle Jira Project Settings, è possibile inviare un Engagement a Jira come Epic. I Riscontri dell'Engagement verranno inviati come Child Issue all'interno di tale Epic.

Per inviare un Engagement come Epic:

1. Aprire l'Engagement che si desidera inviare.
2. Fare clic su **☰ Engagement Menu** e selezionare **Push to Jira**.
3. Facoltativamente, indicare un **Epic Name** (per impostazione predefinita corrisponde al nome dell'Engagement se lasciato vuoto) e una **Epic Priority**.
4. Selezionare **Push to Jira (Create Epic)** e inviare il modulo.

## Invio dei Gruppi di Riscontri come Issue Jira

Se i Gruppi di Riscontri sono abilitati, è possibile inviare un Gruppo di Riscontri a Jira come Issue singola anziché come Issue separate per ciascun Riscontro.

Per inviare un Gruppo di Riscontri:

1. Aprire il Gruppo di Riscontri.
2. Fare clic su **☰ Finding Group Menu** e selezionare **Push to Jira**, oppure selezionare la casella **Push to Jira** durante la modifica del Gruppo di Riscontri.

Se è necessaria la rimozione, l'Issue Jira associata a un Gruppo di Riscontri deve essere eliminata direttamente dall'istanza Jira.

### Creazione e invio automatico dei Gruppi di Riscontri

Con **Push All Issues** abilitato sul Prodotto, e un'opzione **Group By** selezionata in fase di import:

Finché i Gruppi di Riscontri vengono creati correttamente, è il Gruppo di Riscontri a essere inviato automaticamente a Jira come Issue, non i singoli Riscontri.

![image](images/Creating_Issues_in_Jira_4.png)

## Comportamento dell'invio automatico

DefectDojo può inviare automaticamente Riscontri e aggiornamenti a Jira in diversi scenari:

### Push All Issues

Quando l'impostazione **Push All Issues** è abilitata nelle Jira Project Settings di un Prodotto, DefectDojo creerà automaticamente Issue Jira per tutti i Riscontri Attivi e Verificati. Questo include i Riscontri creati tramite import di una scansione. Una volta creata un'Issue Jira, questa continuerà a sincronizzarsi con DefectDojo anche se lo stato del Riscontro cambia.

### Sincronizzazione automatica ai cambiamenti di stato

Quando è abilitata l'impostazione **Push All Issues** oppure l'impostazione di sistema **Finding Jira Sync**, DefectDojo aggiornerà automaticamente le Issue Jira collegate quando vengono eseguite determinate azioni sui Riscontri:

* **Request Review** \- Viene aggiunto un commento all'Issue Jira collegata (oppure all'Issue Jira del Gruppo di Riscontri, se il Riscontro appartiene a un gruppo).
* **Clear Review** \- Viene aggiunto un commento all'Issue Jira collegata.
* **Close Finding** \- L'Issue Jira collegata viene aggiornata per riflettere la chiusura. Se **Push Notes** è abilitato, viene aggiunto anche un commento.

## Commenti e Note di Jira

Quando **Push Notes** è abilitato nelle Jira Project Settings:

* Se un commento viene aggiunto a un'Issue Jira, lo stesso commento verrà aggiunto al Riscontro, nella sezione **Note**.
* Allo stesso modo, se una Nota viene aggiunta a un Riscontro, la Nota verrà aggiunta all'issue Jira come commento.

## Cambiamenti di stato Jira

La configurazione dell'istanza Jira include voci per due Transizioni Jira che attivano un cambiamento di stato su un Riscontro.

* Quando su Jira viene eseguita la **transizione «Close»**, anche il Riscontro associato si chiude e viene contrassegnato come **Inattivo** e **Mitigato** su DefectDojo. DefectDojo registrerà questa modifica nella pagina del Riscontro, sotto la voce **Mitigato da**.
​
![image](images/Creating_Issues_in_Jira_3.png)

* Quando sull'Issue Jira viene eseguita la **transizione «Reopen»**, il Riscontro associato verrà impostato come **Attivo** su DefectDojo, perdendo il suo stato **Mitigato**.

## Mappatura delle Resolution di Jira su Accettazione del rischio / Falso positivo

La configurazione dell'istanza Jira include due campi facoltativi che consentono di mappare una **Resolution** di Jira su uno stato del Riscontro di DefectDojo:

* **Risk Accepted Finding Mapping Resolution** — quando un'issue Jira viene chiusa con questa Resolution, il Riscontro collegato diventa Rischio accettato in DefectDojo.
* **False Positive Finding Mapping Resolution** — quando un'issue Jira viene chiusa con questa Resolution, il Riscontro collegato diventa Falso positivo in DefectDojo.

### Status contro Resolution: un punto di confusione comune

Questi campi mappano la **Resolution** di Jira, non lo **Status** di Jira. Status e Resolution sono due concetti Jira indipendenti: lo Status descrive in quale punto del workflow si trova l'issue (Open, In Progress, Done), mentre la Resolution descrive il modo in cui è stata risolta (Fixed, Won't Do, Duplicate, False Positive, ecc.).

### Prerequisito: una post-funzione «Set issue resolution» sulla transizione del workflow Jira

Il motore dei workflow di Jira non compila automaticamente il campo Resolution. Ogni transizione che deve chiudere un'issue con una Resolution specifica richiede una post-funzione **Set issue resolution** configurata sulla transizione stessa. Senza questa post-funzione, l'issue passa al nuovo Status ma la Resolution resta vuota, e la mappatura di DefectDojo non ha nulla con cui corrispondere.

Un amministratore Jira può aggiungere questa post-funzione da **Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution**.

# Campi personalizzati in Jira

<span style="background: rgba(243, 122, 78,0.5">DefectDojo attualmente non supporta il passaggio di informazioni specifiche dell'Issue in questi campi personalizzati \- questi campi dovranno essere aggiornati manualmente in Jira dopo la creazione dell'issue. Ogni campo personalizzato verrà creato da DefectDojo solo con un valore predefinito.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud ora consente di creare un valore predefinito per i campi personalizzati direttamente in-app. [Consultare la documentazione di Atlassian sui campi personalizzati](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) per maggiori informazioni su come configurare questa funzionalità.</span>

I tipi di Issue Jira integrati di DefectDojo (**Bug, Task, Story** ed **Epic)** sono configurati per funzionare «pronti all'uso». I campi dati di DefectDojo verranno mappati automaticamente sui campi corrispondenti in Jira. Per impostazione predefinita, DefectDojo assegnerà Priority, Labels e un Reporter a ogni nuova Issue che crea.

Alcune configurazioni Jira richiedono che vengano gestiti campi personalizzati aggiuntivi prima che un'issue possa essere creata. Questo processo consente di gestire questi campi personalizzati nell'integrazione DefectDojo \-\> Jira, garantendo che le issue vengano create correttamente. Questi campi personalizzati verranno aggiunti a tutte le chiamate API inviate da DefectDojo a un'istanza Jira collegata.

Se non si utilizzano già campi personalizzati in Jira, non è necessario seguire questo processo.

1. Registrazione dei nomi dei campi personalizzati in Jira (**interfaccia Jira**)
2. Determinazione dei valori Key per i nuovi campi personalizzati (Jira Field Spec Endpoint)
3. Individuazione dei dati accettabili per ciascun campo personalizzato, usando i valori Key come riferimento (Jira Issue Endpoint)
4. Creazione di un blocco JSON di riferimento dei campi per tenere traccia di tutte le Key dei campi personalizzati e dei dati accettabili (Jira Issue Endpoint)
5. Memorizzazione del blocco JSON nel Prodotto DefectDojo associato, per consentire la creazione dei campi personalizzati da Jira (interfaccia DefectDojo)
6. Verifica del lavoro svolto, assicurandosi che tutti i dati richiesti fluiscano correttamente da Jira

#### Passaggio 1: registrare i nomi dei campi personalizzati in Jira

Jira supporta diversi Context Field, tra cui selettori di data, etichette personalizzate e pulsanti di opzione. Ciascuno di questi Context Field avrà un valore Key diverso, reperibile nell'API di Jira.

Annotare i nomi di ciascun campo personalizzato richiesto, poiché sarà necessario cercarli nell'API di Jira nel passaggio successivo.

**Esempio di elenco di campi personalizzati (i nomi dei campi personalizzati saranno diversi):**

* DefectDojo Custom URL Field
* Un altro esempio di campo personalizzato
* ...

#### Passaggio 2: individuare i valori Key dei campi personalizzati di Jira

Iniziare questo processo accedendo all'URL Field Spec dell'intera istanza Jira.

Ecco un esempio di URL Field Spec:

`https://yourcompany-example.atlassian.net/rest/api/2/field`

L'API restituirà una lunga stringa JSON, che dovrà essere formattata in testo leggibile (utilizzando un editor di codice, un'estensione del browser oppure <https://jsonformatter.org/>).

Il JSON restituito da questo URL conterrà tutti i campi personalizzati di Jira, la maggior parte dei quali non è rilevante per DefectDojo e presenta valori `"Null"`. Ogni oggetto in questa risposta API corrisponde a un campo diverso in Jira. Sarà necessario cercare gli oggetti il cui attributo `"name"` corrisponde ai nomi di ciascun campo personalizzato creato nell'interfaccia Jira, e quindi annotare il valore del relativo attributo "key".

![image](images/Using_Custom_Fields.png)

Una volta trovato l'oggetto corrispondente nell'output JSON, è possibile determinare il valore "key" \- in questo caso si tratta di `customfield_10050`.

Jira genera valori Key diversi per ciascun campo personalizzato, ma questi valori Key non cambiano una volta creati. Se in futuro si crea un altro campo personalizzato, questo avrà un nuovo valore Key.

**Espansione dell'elenco di campi personalizzati:**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Un altro esempio di campo personalizzato" \= customfield\_12345
* ...

#### Passaggio 3 \- Individuazione dei campi personalizzati in un'Issue Jira

Individuare un'Issue in Jira che contenga i campi personalizzati annotati nel Passaggio 2\. Copiare la chiave dell'Issue dal titolo (dovrebbe avere un aspetto simile a "`EXAMPLE-123`") e accedere al seguente URL:

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

Verrà restituita un'altra stringa JSON.

Come in precedenza, l'output dell'API conterrà numerosi parametri oggetto `customfield_##` con valori `null` \- si tratta di campi personalizzati che Jira aggiunge per impostazione predefinita, non rilevanti per questa issue. Conterrà anche valori `customfield_##` che corrispondono ai valori Key dei campi personalizzati individuati nel passaggio precedente. A differenza dell'output di Field Spec, non si vedranno nomi che identificano questi campi personalizzati, motivo per cui è stato necessario annotare i valori key nel Passaggio 2\.

![image](images/Using_Custom_Fields_2.png)

**Esempio:**
Si sa che `customfield_10050` rappresenta il DefectDojo Custom URL Field poiché è stato annotato nel Passaggio 2\. È ora possibile vedere che `customfield_10050` contiene un valore `"https://google.com"` nell'issue `EXAMPLE-123`.

#### Passaggio 4 \- Creazione di un riferimento JSON dei campi a partire da ogni Key dei campi personalizzati di Jira

Sarà ora necessario prendere il valore di ciascuno dei campi personalizzati del proprio elenco e memorizzarli in un oggetto JSON (da utilizzare come riferimento). È possibile ignorare qualsiasi campo personalizzato che non corrisponda al proprio elenco.

Questo oggetto JSON conterrà tutti i valori predefiniti per le nuove Issue Jira. Si consiglia di usare nomi facili da riconoscere per il proprio team come valori "predefiniti" da modificare: '`change-me.com`', '`Change this paragraph.`' ecc.

**Esempio:**

Dal Passaggio 3, si sa ora che Jira si aspetta una stringa URL per "`customfield_10050`". È possibile usare questo per costruire l'oggetto JSON di esempio.

Si supponga di aver individuato anche un campo di testo breve relativo a DefectDojo, identificato come "`customfield_67890`". Si esaminerebbe questo campo nel secondo output dell'API, si osserverebbe il valore associato e si farebbe riferimento al valore memorizzato anche nell'oggetto JSON di esempio.
​
L'oggetto JSON inizierà ad assomigliare a questo man mano che vi si aggiungono altri campi personalizzati.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Ripetere questo processo finché tutti i campi personalizzati di Jira rilevanti per DefectDojo non sono stati aggiunti al riferimento JSON dei campi.

#### Tipi di dati \& sintassi Jira

Alcuni campi, come i campi data, possono riguardare più campi personalizzati in Jira. In tal caso, sarà necessario aggiungere entrambi i campi al riferimento JSON dei campi.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Altri campi, come il campo Label, possono essere tracciati come un elenco di stringhe \- assicurarsi che il riferimento JSON dei campi utilizzi un formato corrispondente all'output dell'API di Jira.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

Altri campi personalizzati possono contenere informazioni aggiuntive e contestuali che dovrebbero essere rimosse dal riferimento dei campi. Ad esempio, il campo Custom Multichoice contiene un blocco aggiuntivo nell'output dell'API, che dovrà essere rimosso, poiché questo blocco memorizza il valore corrente del campo.

* è necessario rimuovere l'oggetto aggiuntivo da questo campo:

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
* in alternativa, è possibile abbreviarlo come segue e ignorare la seconda parte:

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Esempio di riferimento dei campi completo

Ecco un riferimento JSON dei campi completo, con commenti in linea che spiegano a cosa si riferisce ciascun campo personalizzato. Questo vuole essere un esempio onnicomprensivo. Il JSON conterrà valori Key e dati diversi a seconda dei valori personalizzati che si desidera utilizzare durante la creazione dell'issue.

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

#### Passaggio 5 \- Aggiunta dei campi personalizzati a un Prodotto DefectDojo

È ora possibile aggiungere questi campi personalizzati al Prodotto DefectDojo associato, nella pagina Jira Project Settings (accessibile tramite il menu ⚙️ Gear sul Prodotto). Incollare il riferimento JSON dei campi come testo semplice nella casella **Custom Fields** e salvare.

#### Passaggio 6 \- Test dei campi personalizzati Jira da un nuovo Riscontro:

Ora, quando si crea un nuovo Riscontro nel Prodotto associato a Jira, Jira creerà automaticamente tutti questi campi personalizzati in Jira in base al blocco JSON in esso contenuto. Questi campi personalizzati verranno creati con i valori predefiniti ("change-me-please", ecc.).

All'interno del Prodotto su DefectDojo, accedere alla pagina Riscontri \> Add New Finding. Assicurarsi che il Riscontro sia Attivo che Verificato per garantire l'invio a Jira, quindi confermare lato Jira che i campi personalizzati sono stati creati correttamente, senza incongruenze.
