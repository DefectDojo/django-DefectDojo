---
title: Impostare le autorizzazioni di un utente
description: Come assegnare ruoli e autorizzazioni a un utente, oltre allo stato di
  superuser
weight: 2
audience: pro
aliases:
- /it/en/customize_dojo/user_management/set_user_permissions
---

> **Funzionalità di DefectDojo Pro.** Il sistema RBAC Membri / Gruppi / Ruoli globali descritto in questa pagina fa parte di DefectDojo Pro. La versione open source di DefectDojo utilizza il modello [Utenti autorizzati](../os__authorized_users/) — consulta quella pagina per il controllo degli accessi nella versione open source, e le [note di aggiornamento alla 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) se stai passando da un'edizione all'altra.

## Introduzione ai tipi di autorizzazione

I singoli utenti dispongono di quattro diversi tipi di autorizzazione che possono essere loro assegnati:

* Gli utenti possono essere assegnati come **Membri di Prodotti o Tipi di prodotto**. Questo consente loro di visualizzare e interagire con i tipi di dati (Tipi di prodotto, Prodotti, Engagement, Test e Riscontri) in DefectDojo in base al ruolo che viene loro assegnato sullo specifico Prodotto. Gli utenti possono avere più appartenenze a Prodotti o Tipi di prodotto, con diversi livelli di accesso.  
​
* Gli utenti possono anche avere **Autorizzazioni di configurazione** assegnate, che consentono loro di accedere alle pagine di configurazione di DefectDojo. Le Autorizzazioni di configurazione non sono legate a Prodotti o Tipi di prodotto.  
​
* Agli utenti possono essere assegnati **Ruoli globali**, che conferiscono loro un livello di accesso standardizzato a tutti i Prodotti e Tipi di prodotto.  
​
* Gli utenti possono essere impostati come **Superuser**: ruoli di livello amministratore che conferiscono loro il controllo e l'accesso a tutti i dati e la configurazione di DefectDojo.

È inoltre possibile creare Gruppi se si desidera assegnare contemporaneamente l'appartenenza a un Prodotto, le Autorizzazioni di configurazione o i Ruoli globali a un gruppo di utenti. Se in DefectDojo è presente un numero elevato di utenti, ad esempio un team di test dedicato a un determinato Prodotto, i Gruppi possono essere una funzionalità più utile.

## Superuser e Ruoli globali

Parte della configurazione del controllo degli accessi basato sui ruoli (RBAC) potrebbe richiedere la creazione di Superuser aggiuntivi, o di utenti con Ruoli globali.

* I Superuser (Admin) non hanno limitazioni nel sistema. Possono modificare tutte le impostazioni, gestire gli utenti e avere accesso in lettura/scrittura a tutti i dati. Possono anche modificare le regole di accesso per tutti gli utenti di DefectDojo. I Superuser riceveranno inoltre notifiche per tutti i problemi e gli avvisi di sistema.
* Gli utenti con Ruoli globali possono visualizzare e interagire con qualsiasi tipo di dati (Tipi di prodotto, Prodotti, Engagement, Test e Riscontri) in DefectDojo in base al Ruolo loro assegnato. Per maggiori informazioni su ciascun Ruolo e sui relativi privilegi, consulta il nostro articolo di Introduzione ai Ruoli.
* Agli utenti possono anche essere assegnate specifiche Autorizzazioni di configurazione, che consentono loro di accedere a determinate pagine di configurazione di DefectDojo. Per impostazione predefinita, gli utenti non dispongono di alcuna Autorizzazione di configurazione.

Per impostazione predefinita, il primo account creato su una nuova istanza di DefectDojo avrà i permessi di Superuser. Questo utente potrà modificare le autorizzazioni di tutti gli utenti di DefectDojo successivi. Solo un Superuser esistente può aggiungere un altro superuser, o assegnare un Ruolo globale a un utente.

### Assegnare lo stato di Superuser o Ruolo globale a un utente esistente

1. Vai alla pagina 👤 Users \> Users nella barra laterale. Vedrai un elenco di tutti gli account registrati su DefectDojo, insieme allo stato Attivo di ciascun account, ai Ruoli globali e ad altri dati utente rilevanti.  
​
![image](images/Set_a_User's_Permissions.png)
​
2. Fai clic sul nome dell'account a cui vuoi concedere i privilegi di Superuser. Questo ti porterà alla sua pagina Utente.  
​
3. Dalla sezione Informazioni predefinite della pagina Utente, apri il menu ☰ e seleziona Modifica.  
​
![image](images/Set_a_User's_Permissions_2.png)

4. Dalla pagina Modifica utente:   
​  
Per lo stato di Superuser, seleziona la casella ☑️ Stato Superuser, presente nelle Informazioni predefinite dell'utente.  
​  
Per assegnare un Ruolo globale, selezionane uno dal menu a discesa Ruolo globale in fondo alla pagina.  
​
![image](images/Set_a_User's_Permissions_3.png)
​
5. Fai clic su Invia per confermare le modifiche.  

## Appartenenza a Prodotto e Tipo di prodotto

Per impostazione predefinita, qualsiasi nuovo account creato su DefectDojo non avrà l'autorizzazione a visualizzare alcun dato a livello di Prodotto. Sarà necessario assegnare loro l'appartenenza a ciascun Prodotto che desiderano visualizzare e con cui vogliono interagire.

* L'appartenenza a Prodotto e Tipo di prodotto può essere configurata solo da **Superuser, Maintainer o Owner**.
* I **Maintainer e Owner** possono configurare l'appartenenza solo sui Prodotti/Tipi di prodotto a cui sono già assegnati.
* I **Maintainer e Owner globali** possono configurare l'appartenenza su qualsiasi Prodotto o Tipo di prodotto, così come i **Superuser**.

Gli utenti possono avere contemporaneamente due tipi di appartenenza a livello di **Prodotto**:

* Il Ruolo conferito dalla loro appartenenza al Tipo di prodotto sottostante, se applicabile
* Il loro Ruolo specifico per il Prodotto, se esistente.

Se un utente è già stato aggiunto come membro di un Tipo di prodotto e non necessita di un ulteriore livello di autorizzazioni su uno specifico Prodotto, non è necessario aggiungerlo come Membro del Prodotto.

### Aggiungere un nuovo Membro

1. Vai al Prodotto o Tipo di prodotto a cui vuoi assegnare un utente. Puoi selezionare il Prodotto dall'elenco in **Products \> All Products**.

![image](images/Set_a_User's_Permissions_4.png)

2. Individua l'intestazione **Members**, fai clic sul menu **☰** e seleziona **\+ Add Users**.
3. Questo ti porterà a una pagina in cui puoi **registrare nuovi Membri**. Seleziona un Utente dal menu a discesa Users.
4. Seleziona il Ruolo che vuoi assegnare a quell'Utente su questo Prodotto o Tipo di prodotto: **API Importer, Reader, Writer, Maintainer** o **Owner.**  
​
![image](images/Set_a_User's_Permissions_5.png)

Gli utenti non possono essere assegnati come Membri su un Prodotto o Tipo di prodotto senza avere anche un Ruolo. Se non sei sicuro di quale Ruolo assegnare a un nuovo utente, **Reader** è una buona opzione 'predefinita'. Questo manterrà sicuro lo stato del tuo Prodotto finché non prenderai la decisione finale sul suo Ruolo.

### Modificare o eliminare un Membro

Ai Membri può essere modificato il Ruolo all'interno di un Prodotto o Tipo di prodotto.

Nella pagina **Product** o **Product Type**, vai all'intestazione **Members** e fai clic sul pulsante **⋮** accanto all'Utente che vuoi Modificare o Eliminare.

![image](images/Set_a_User's_Permissions_6.png)

📝 **Edit** ti porterà alla schermata **Edit Member**, dove puoi cambiare il **Ruolo** di questo utente (da **API Importer, Reader, Writer, Maintainer** o **Owner** a una scelta diversa).

🗑️ **Delete** rimuove completamente l'appartenenza di un Utente. Non rimuoverà alcun contributo o modifica apportata dall'Utente al Prodotto o Tipo di prodotto.

* Se non riesci a Modificare o Eliminare l'appartenenza di un utente (il pulsante **⋮** non è visibile), è perché tale appartenenza gli è conferita a livello di **Product Type**.
* Un utente può avere due livelli di appartenenza all'interno di un Prodotto: uno assegnato a livello di **Product Type** e un altro assegnato a livello di **Product**.

#### Aggiungere un ruolo Prodotto aggiuntivo a un utente con un ruolo Tipo di prodotto correlato

Se un Utente ha un Ruolo a livello di Tipo di prodotto, gli verrà assegnata anche l'appartenenza con questo Ruolo a ogni Prodotto sottostante all'interno della categoria. Tuttavia, se vuoi che questo Utente abbia un Ruolo speciale su uno specifico Prodotto all'interno di quel Tipo di prodotto, puoi assegnargli un Ruolo aggiuntivo a livello di Prodotto.

1. Dalla pagina del Prodotto, vai all'intestazione **Members**, fai clic sul menu **☰** e seleziona **\+ Add Users** (come se stessi aggiungendo un nuovo Utente al Prodotto).
2. Seleziona il nome dell'Utente dal menu a discesa e seleziona il Ruolo Prodotto che vuoi assegnare a quell'Utente.

Un Ruolo Prodotto avrà la precedenza sul Ruolo standard del Tipo di prodotto o sul Ruolo globale di un utente. Ad esempio, se un Utente ha un Ruolo Tipo di prodotto di **Reader**, ma è anche assegnato come **Owner** su un Prodotto annidato in quel Tipo di prodotto, avrà ulteriori permessi da **Owner** aggiunti solo per quel Prodotto.

Tuttavia, questo non funziona al contrario. Se un Utente ha un Ruolo Tipo di prodotto o un Ruolo globale di **Owner**, assegnargli un ruolo **Reader** su un particolare Prodotto non gli toglierà i permessi da **Owner**. **I Ruoli non possono togliere le autorizzazioni concesse a un Utente da altri Ruoli, possono solo aggiungerne di ulteriori.**

## Autorizzazioni di configurazione

Molte finestre di configurazione ed endpoint API possono essere abilitati per utenti o gruppi di utenti, indipendentemente dal loro stato di superuser. Queste Autorizzazioni di configurazione consentono agli utenti normali di accedere e contribuire a parti di DefectDojo al di fuori della loro normale assegnazione di Prodotto o Ruolo Prodotto.

Le Autorizzazioni di configurazione non sono legate a uno specifico Prodotto o Tipo di prodotto: gli utenti possono avere Autorizzazioni di configurazione assegnate senza bisogno di altri stati o dell'appartenenza a Prodotto/Tipo di prodotto.  
​
### Elenco delle Autorizzazioni di configurazione

* **Credential Manager:** Accesso alla pagina ⚙️Configuration \> Credential Manager
* **Development Environments:** Gestione dell'elenco Engagements \> Environments
* **Finding Templates:** Accesso alla pagina Findings \> Finding Templates
* **Groups**: Accesso alla pagina 👤Users \> Groups
* **Jira Instances:** Accesso alla pagina ⚙️Configuration \> JIRA
* **Language Types**: Accesso all'endpoint API [Language Types](/automation/api/languages/)
* **Login Banner**: Modifica della pagina ⚙️Configuration \> Login Banner
* **Announcements**: Accesso a ⚙️Configuration \> Announcements
* **Note Types:** Accesso alla pagina ⚙️Configuration \> Note Types
* **Product Types:** n/d
* **Questionnaires**: Accesso alla pagina Questionnaires \> All Questionnaires
* **Questions**: Accesso alla pagina Questionnaires \> Questions
* **Regulations**: Accesso alla pagina ⚙️Configuration \> Regulations
* **SLA Configuration:** Accesso alla pagina ⚙️Configuration \> SLA Configuration
* **Test Types:** Aggiunta o modifica di un Test Type (in Engagements \> Test Types)
* **Tool Configuration:** Accesso alla pagina **⚙️Configuration \> Tool Types**
* **Tool Types:** Accesso alla pagina ⚙️Configuration \> Tool Types
* **Users:** Accesso alla pagina 👤Users \> Users

### Aggiungere Autorizzazioni di configurazione a un utente

**Solo i Superuser possono aggiungere Autorizzazioni di configurazione a un utente**.

1. Vai alla pagina 👤 Users \> Users nella barra laterale. Vedrai un elenco di tutti gli account registrati su DefectDojo, insieme allo stato Attivo di ciascun account, ai Ruoli globali e ad altri dati utente rilevanti.  
​
![image](images/Set_a_User's_Permissions_7.png)

2. Fai clic sul nome dell'account che desideri modificare.  
​
3. Vai all'elenco delle Autorizzazioni di configurazione. Si trova sul lato destro della pagina Utente.  
​
4. Seleziona le Autorizzazioni di configurazione utente che desideri aggiungere.  
​
Per una descrizione dettagliata delle Autorizzazioni di configurazione utente, consulta il nostro [Elenco delle autorizzazioni](../user_permission_chart/).
