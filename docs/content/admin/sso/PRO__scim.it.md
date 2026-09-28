---
title: Provisioning SCIM
description: Effettua il provisioning e il deprovisioning degli utenti di DefectDojo
  Pro dal tuo identity provider
weight: 19
audience: pro
---

DefectDojo Pro supporta SCIM 2.0, che consente al tuo identity provider di creare, aggiornare e disattivare direttamente gli utenti di DefectDojo. Senza SCIM, DefectDojo viene a conoscenza di un utente solo quando questo effettua l'accesso, quindi rimuovere qualcuno dal tuo identity provider blocca gli accessi futuri ma lascia attivo il suo account DefectDojo.

SCIM è distinto dal single sign-on e lo completa. Il SSO decide chi può accedere; SCIM mantiene l'elenco stesso degli account allineato alla tua directory. La maggior parte dei clienti configura entrambi: SAML o OIDC per l'autenticazione, SCIM per il provisioning.

La configurazione di SCIM può essere eseguita solo da un **Superuser**.

## Cosa fa SCIM in DefectDojo

Quando colleghi un identity provider tramite SCIM, questo può:

* creare utenti DefectDojo quando qualcuno viene assegnato all'applicazione
* aggiornare nomi e indirizzi email quando cambiano nella directory
* disattivare gli utenti quando vengono rimossi dall'assegnazione o lasciano l'organizzazione
* creare gruppi e aggiungere o rimuovere i loro membri

Disattivare un utente tramite SCIM fa due cose contemporaneamente. L'account viene contrassegnato come inattivo, quindi l'utente non può più accedere, e i token API DefectDojo dell'utente vengono eliminati. L'offboarding chiude quindi entrambe le porte in un unico passaggio, ed è questo il motivo principale per usare SCIM anziché affidarsi solo al proprio identity provider.

Il record utente stesso viene conservato. I Riscontri, le note e la cronologia fanno riferimento alle persone che li hanno creati, quindi DefectDojo disattiva l'account invece di eliminarlo. Se la stessa persona ritorna, riattivarla tramite il tuo identity provider ripristina l'accesso senza alterare quella cronologia.

## Configurazione

1. Apri **Connect > Authorization** e seleziona **SCIM Provisioning**. SCIM è elencato insieme ai tuoi provider di accesso perché si collega allo stesso identity provider, ed è contrassegnato come **Provisioning** per distinguerlo dai provider che aggiungono un pulsante alla pagina di accesso.

2. Seleziona **Enable SCIM Provisioning** e invia. Finché questa opzione è disattivata, gli endpoint SCIM si comportano come se non esistessero, quindi un test di connessione dal tuo identity provider segnala l'indirizzo come non trovato.

3. Copia il **Tenant URL** mostrato nella pagina. È simile a questo:

   ```
   https://<your-instance>.cloud.defectdojo.com/scim/v2
   ```

4. Nel pannello **SCIM Tokens**, assegna al token un nome che indichi dove verrà utilizzato, ad esempio "Okta production", quindi seleziona **Generate Token**.

5. Copia il token dalla finestra di dialogo e incollalo nel tuo identity provider. DefectDojo memorizza solo un hash del token, quindi non può essere mostrato di nuovo. Se lo perdi, generane un altro e revoca quello vecchio.

Puoi mantenere attivo più di un token contemporaneamente. Per ruotarli, genera un nuovo token, aggiorna il tuo identity provider, quindi revoca quello vecchio. Non c'è alcun intervallo in cui il provisioning smette di funzionare.

Il pannello dei token registra quando ciascun token è stato usato l'ultima volta, un modo rapido per verificare che il tuo identity provider stia effettivamente raggiungendo DefectDojo.

## Okta

1. Nella Okta Admin Console, vai su **Applications > Browse App Catalog** e aggiungi **SCIM 2.0 Test App (Header Auth)**. Se hai già un'applicazione SAML per DefectDojo, puoi invece abilitare il provisioning su quell'applicazione.

2. Apri la scheda **Provisioning** e seleziona **Configure API Integration**.

3. Imposta **SCIM 2.0 Base Url** sul Tenant URL copiato in precedenza.

4. Imposta **API Token** su `Bearer <your token>`, includendo la parola `Bearer` e uno spazio singolo. Questo tipo di applicazione invia il valore testualmente come header Authorization.

5. Seleziona **Test API Credentials**, quindi salva.

6. In **Provisioning > To App**, abilita **Create Users**, **Update User Attributes** e **Deactivate Users**.

7. Assegna persone o gruppi all'applicazione. Okta cerca prima ogni persona in DefectDojo in base allo username e crea un account solo se non ne trova uno, quindi chiunque abbia già un account DefectDojo viene collegato anziché duplicato.

Per effettuare il push anche dei gruppi, apri la scheda **Push Groups** e aggiungi i gruppi che vuoi che DefectDojo replichi. Consulta [Gruppi](#groups) più sotto per sapere cosa ne fa DefectDojo.

## Microsoft Entra ID

1. Nell'Entra admin center, vai su **Enterprise applications > New application > Create your own application** e scegli l'opzione non-gallery. Se hai già un'applicazione per DefectDojo, usa quella.

2. Apri **Provisioning** e imposta **Provisioning Mode** su **Automatic**.

3. Imposta **Tenant URL** sul Tenant URL copiato in precedenza.

4. Imposta **Secret Token** sul tuo token SCIM. Entra lo invia come bearer token, quindi qui non aggiungere la parola `Bearer`.

5. Seleziona **Test Connection**, quindi salva.

6. Assegna utenti e gruppi in **Users and groups**, quindi avvia il provisioning.

Entra effettua il provisioning con un ciclo di circa 40 minuti. Durante la configurazione, **Provision on demand** applica immediatamente un singolo utente o gruppo, il che rende molto più rapido verificare che la configurazione funzioni.

## Cosa memorizza DefectDojo

DefectDojo mappa un piccolo insieme di attributi SCIM e ignora il resto.

| SCIM attribute | DefectDojo field |
|---|---|
| `userName` | Username |
| `name.givenName` | Nome |
| `name.familyName` | Cognome |
| `emails` | Indirizzo email |
| `active` | Se l'account è abilitato |
| `externalId` | Conservato in modo che il tuo identity provider possa far corrispondere il record in seguito |

Gli attributi che DefectDojo non modella, inclusi numeri di telefono, titoli professionali e l'estensione enterprise di SCIM, vengono accettati e ignorati anziché rifiutati. Mappare attributi aggiuntivi nel tuo identity provider è innocuo.

Due attributi meritano particolare attenzione:

**Username.** DefectDojo consente lettere, cifre e i caratteri `@ . + - _` in uno username. Se il tuo identity provider invia uno username contenente qualsiasi altro carattere, DefectDojo rifiuta quell'utente con un errore che indica il problema, invece di memorizzare silenziosamente uno username diverso. Memorizzare uno username alterato comprometterebbe la capacità del tuo provider di ritrovare in seguito l'account.

**Indirizzo email.** SCIM non lo richiede, e DefectDojo crea comunque l'utente senza di esso. Tieni presente che le notifiche di DefectDojo, inclusi report pianificati e avvisi, non hanno alcuna destinazione per un utente privo di indirizzo email. Mappa l'attributo `emails` a meno che tu non abbia un motivo per non farlo.

SCIM non imposta mai password e non concede mai lo stato di superuser o staff. Se il tuo identity provider è configurato per inviare password, DefectDojo le ignora. Gli utenti forniti in questo modo accedono tramite SSO.

## Gruppi

SCIM gestisce solo i gruppi che ha creato. I gruppi creati nell'interfaccia di DefectDojo, o arrivati tramite il group mapping di SAML o Azure AD, sono invisibili a SCIM e non possono essere rinominati, svuotati o eliminati dal tuo identity provider.

Questo è importante perché il push dei gruppi è per natura una sostituzione completa. Se un identity provider potesse adottare un gruppo esistente, la sua sincronizzazione successiva sostituirebbe l'appartenenza accuratamente scelta di quel gruppo con qualunque cosa contenga la directory. Il push di un gruppo il cui nome è già utilizzato fallisce quindi con un messaggio che spiega il conflitto. Per cedere un gruppo esistente al tuo identity provider, rinomina uno dei due, oppure elimina il gruppo DefectDojo e lascia che il provider lo ricrei.

All'interno di un gruppo gestito da SCIM, l'appartenenza appartiene al tuo identity provider e i ruoli appartengono a DefectDojo:

* A un membro appena aggiunto viene assegnato il ruolo **Reader**.
* Se promuovi qualcuno a un ruolo superiore in DefectDojo, le sincronizzazioni successive non modificano quel ruolo.
* Chiunque venga aggiunto manualmente a un gruppo gestito da SCIM viene rimosso alla sincronizzazione successiva, perché l'identity provider è la fonte di verità su chi appartiene al gruppo.

Eliminare un gruppo tramite SCIM rimuove il gruppo e le relative appartenenze. Non elimina mai le persone che ne facevano parte.

## Protezione dell'accesso amministrativo

Per impostazione predefinita, SCIM non disattiva un account superuser. L'errore più comune in qualsiasi configurazione di provisioning è un identity provider con un ambito più ampio del previsto, e i superuser sono il modo per rientrare in DefectDojo quando qualcosa va storto.

Se vuoi che il tuo identity provider gestisca anche i superuser, abilita **Allow SCIM to deactivate superusers** nella pagina delle impostazioni SCIM. Anche in questo caso, DefectDojo rifiuta di disattivare l'ultimo superuser attivo rimasto, così il provisioning non può lasciare l'istanza priva di un amministratore.

## Limitazioni

* Un identity provider per istanza DefectDojo.
* Il filtraggio è supportato su `userName`, `displayName`, `externalId` e `id`, usando un singolo confronto di uguaglianza. Questo copre ciò che Okta ed Entra inviano quando abbinano i record. Filtri più complessi vengono rifiutati con un errore che lo indica.
* Le operazioni bulk, l'ordinamento e l'endpoint `/Me` non sono implementati.
* Le appartenenze ai gruppi vengono gestite tramite l'endpoint Groups. Inviare l'appartenenza a un gruppo su un record utente non ha alcun effetto, in linea con il comportamento di entrambi i provider.

## Risoluzione dei problemi

**Il test di connessione segnala "not found".** SCIM è disattivato, oppure l'istanza non ne ha la licenza. Verifica che **Enable SCIM Provisioning** sia attivo e che il tuo abbonamento includa il SSO. L'intero indirizzo SCIM si comporta come se non esistesse finché entrambe le condizioni non sono vere.

**Il test di connessione segnala un errore di autenticazione.** Il token è errato, oppure è stato revocato. Generane uno nuovo e aggiorna il tuo identity provider. In Okta, verifica che il valore inizi con `Bearer ` e uno spazio; in Entra, verifica che non sia così.

**Il provisioning di un utente fallisce con un errore relativo allo username.** Lo username contiene caratteri non consentiti da DefectDojo. Cambia l'attributo che il tuo identity provider mappa su `userName`, il più delle volte facendolo corrispondere all'indirizzo email dell'utente o allo user principal name.

**Il push di un gruppo fallisce, segnalando che esiste già un gruppo con quel nome.** Un gruppo DefectDojo con quel nome è stato creato altrove. Consulta [Gruppi](#groups) più sopra.

**Il provisioning di un membro del gruppo fallisce.** La persona non è ancora stata fornita a DefectDojo. Assegnala all'applicazione, e l'appartenenza andrà a buon fine al ciclo successivo.

**Inizia da Diagnostics.** Le richieste SCIM rifiutate vengono registrate in **Connect > Diagnostics**, con l'endpoint, lo stato e il messaggio restituito da DefectDojo. Questo è di solito più rapido che leggere il log del tuo identity provider, ed è l'unico punto che mostra entrambi i lati dello scambio. Il provisioning riuscito non viene registrato lì; le modifiche a utenti e gruppi compaiono invece nella cronologia di audit.

**Tutto segnala successo, ma non compare nulla in DefectDojo.** Verifica che il Tenant URL termini con `/scim/v2` senza slash finale, e che il tuo identity provider stia effettivamente raggiungendo la tua istanza. La colonna **Last Used** nel pannello SCIM Tokens mostra se è arrivata una qualche richiesta.

**Utenti DefectDojo Pro:** se la tua istanza limita l'accesso in base all'indirizzo IP, aggiungi gli indirizzi del tuo identity provider all'allowlist del firewall prima di configurare SCIM. Consulta [Regole del firewall](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings).
