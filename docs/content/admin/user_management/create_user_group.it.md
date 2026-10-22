---
title: 'Condividi le autorizzazioni: Gruppi di utenti'
description: Condividi e gestisci le autorizzazioni per molti utenti in DefectDojo
  Pro
weight: 3
audience: pro
aliases:
- /it/en/customize_dojo/user_management/create_user_group
---

> **Funzionalità di DefectDojo Pro.** I Gruppi di utenti e il sistema RBAC sottostante fanno parte di DefectDojo Pro. DefectDojo open-source utilizza il modello [Utenti autorizzati](../os__authorized_users/) — consulta quella pagina per il controllo degli accessi in open-source, e le [note di aggiornamento alla 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) se stai passando da un'edizione all'altra.

Se hai un numero significativo di utenti DefectDojo, potresti voler creare uno o più **Gruppi**, per impostare le stesse regole di controllo degli accessi basato sui ruoli (RBAC) per molti utenti contemporaneamente. Solo i Superuser possono creare Gruppi di utenti.

I Gruppi possono funzionare in più modi:

* Impostare uno, o più Ruoli a livello di Prodotto o Tipo di prodotto per tutti i Membri del Gruppo, consentendo un controllo specifico su quali Prodotti o Tipi di prodotto possono essere accessibili e modificabili dal Gruppo.
* Impostare un Ruolo globale per tutti i Membri del Gruppo, dando loro visibilità e accesso a tutti i Prodotti o Tipi di prodotto.
* Impostare Autorizzazioni di configurazione per un Gruppo, consentendo loro di modificare funzionalità specifiche di DefectDojo.

Per ulteriori informazioni sui Ruoli, consulta il nostro articolo **Introduzione ai Ruoli**.

## La pagina Tutti i gruppi

Dalla barra laterale, vai su 👤**Users \> Groups** per visualizzare un elenco di tutti i gruppi di utenti attivi e inattivi.

![image](images/Create_a_User_Group_for_shared_permissions.png)
Da qui, puoi creare, eliminare o visualizzare le tue singole pagine dei Gruppi.

Per gli utenti <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>, la pagina Tutti i gruppi dell'interfaccia Pro dispone di alcune opzioni aggiuntive.
* Puoi filtrare questa tabella per Nome del gruppo, Descrizione, Indirizzo e-mail, Ruolo globale, oltre che per il numero totale di Utenti, Tipi di prodotto e Prodotti associati al Gruppo.
* Puoi anche modificare le Autorizzazioni di un Gruppo o altre impostazioni facendo clic sul pulsante "⋮" accanto al Gruppo che desideri modificare.

![image](images/all_groups_pro.png)

## Visualizzazione di un gruppo

La visualizzazione di un gruppo mostra tutte le informazioni del Gruppo, come ID, nome, descrizione, ruolo globale, ecc. Vengono inoltre visualizzati i Membri del gruppo, i Tipi di prodotto e i Prodotti associati al gruppo. Inoltre, le autorizzazioni di configurazione legate a un Gruppo possono essere aggiornate direttamente dalla pagina "View Group".

Per gli utenti <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>, la vista Gruppo dell'interfaccia Pro consente di assegnare le modifiche alle Autorizzazioni di configurazione in modo leggermente diverso.

![image](images/group_view_pro_ui.png)

* Tutte le autorizzazioni di configurazione vengono visualizzate in un menu a discesa raggruppato in sottocategorie. Se la selezione delle autorizzazioni di configurazione è diversa dal valore attuale, viene visualizzato un pulsante "Update Configuration Permissions".

![image](images/groups_pro_configuration_permissions.png)

* Una volta selezionate alcune autorizzazioni aggiuntive, all'utente verrà chiesto di confermare di voler aggiornare le autorizzazioni per il gruppo selezionato prima che l'aggiornamento venga effettuato.

## Creare / Modificare un Gruppo di utenti

1. Vai alla pagina 👤**Users \> Groups** nella barra laterale. Vedrai un elenco di tutti i Gruppi di utenti esistenti, con il relativo Nome, Descrizione, Numero di utenti, Ruolo globale (se applicabile) ed Email.
​

![image](images/Create_a_User_Group_for_shared_permissions_2.png)

2. Fai clic sul **🛠️ button** accanto all'intestazione All Groups, e seleziona **\+ New Group.**
​

![image](images/Create_a_User_Group_for_shared_permissions_3.png)


3. Questo ti porterà a una pagina in cui puoi creare un nuovo Gruppo. Imposta il Nome per questo Gruppo, e aggiungi una Descrizione se lo desideri.

Puoi anche selezionare un Ruolo globale che desideri applicare a questo Gruppo, se lo desideri. Aggiungere un Ruolo globale al Gruppo darà a tutti i Membri del gruppo accesso a tutti i dati DefectDojo, insieme a un livello limitato di accesso in modifica a seconda del Ruolo globale scelto. Consulta il nostro articolo **Introduzione ai Ruoli** per maggiori informazioni.

L'account che crea inizialmente un Gruppo avrà un Ruolo Owner per il Gruppo per impostazione predefinita.

### Impostare un indirizzo email per ricevere i report

Il Weekly Digest è un report su tutti i Prodotti / Tipi di prodotto assegnati al Gruppo. Per far inviare un Digest settimanale, inserisci l'indirizzo email di destinazione che desideri utilizzare nel modulo Create / Edit Group.  I membri del Gruppo continueranno comunque a ricevere le notifiche come al solito.

### Visualizzazione della pagina di un Gruppo

Una volta creato un Gruppo, puoi accedervi selezionandolo nel menu elencato sotto **Users \> Groups.**

La pagina del Gruppo può essere personalizzata con una **Descrizione**. Presenta un elenco di tutti i **Membri del gruppo,** oltre ai **Prodotti, Tipi di prodotto**, e al **Ruolo** associato a ciascuno di essi**.**

Qui puoi anche vedere le **Autorizzazioni di configurazione** del Gruppo elencate.

## Gestire gli utenti di un Gruppo

L'appartenenza al Gruppo viene gestita dalla singola pagina del Gruppo, che puoi selezionare dall'elenco nella pagina **Users \> Groups**. Fai clic sul Nome del gruppo evidenziato per accedere alla pagina del Gruppo che desideri modificare.

Per visualizzare o modificare l'appartenenza a un Gruppo, un Utente deve avere le Autorizzazioni di configurazione appropriate abilitate, oltre all'appartenenza al Gruppo (o lo stato di Superuser).

### **Aggiungere un utente a un Gruppo**

I Gruppi di utenti possono avere tutti gli Utenti assegnati che desideri. Tutti gli Utenti in un Gruppo riceveranno il Ruolo associato su ogni Prodotto o Tipo di prodotto elencato, ma gli Utenti possono anche avere Ruoli individuali che hanno la precedenza sul ruolo del Gruppo.

1. Dalla pagina del Gruppo, seleziona **\+ Add Users** dal pulsante **☰** all'estremità dell'intestazione **Members**.
​

![image](images/Create_a_User_Group_for_shared_permissions_4.png)

2. Questo ti porterà alla schermata **Add Some Group Members**. Apri il menu a discesa Users, e poi seleziona ciascun utente che desideri aggiungere al Gruppo.
​

![image](images/Create_a_User_Group_for_shared_permissions_5.png)

3. Seleziona il Ruolo del gruppo che desideri assegnare a questi Utenti. Questo determina la loro capacità di configurare il Gruppo.

Nota che aggiungere un membro a un Gruppo non gli consentirà l'accesso alla propria pagina del Gruppo per impostazione predefinita. Questa è un'Autorizzazione di configurazione separata che deve essere prima abilitata.

### **Modificare o eliminare un Membro da un Gruppo di utenti**

1. Dalla pagina del Gruppo, seleziona ⋮ accanto al Nome dell'Utente che desideri modificare o eliminare dal Gruppo.

**📝 Edit** ti porterà alla schermata Edit Member, dove puoi modificare il Ruolo di questo utente (da Reader, Maintainer o Owner a una scelta diversa).

**🗑️ Delete** rimuove completamente l'appartenenza dell'Utente. Non rimuoverà alcun contributo o modifica che l'Utente ha apportato al Prodotto o Tipo di prodotto.

![image](images/Create_a_User_Group_for_shared_permissions_6.png)

## Gestire le Autorizzazioni di un Gruppo

Le Autorizzazioni del Gruppo vengono gestite dalla singola pagina del Gruppo, che puoi selezionare dall'elenco nella pagina **Users \> Groups**. Fai clic sul Nome del gruppo evidenziato per accedere alla pagina del Gruppo che desideri modificare.

Nota che solo i Superuser possono modificare le autorizzazioni di un Gruppo (Prodotto / Tipo di prodotto, o Configurazione).
​
### **Aggiungere Ruoli di Prodotto o Ruoli di Tipo di prodotto per un Gruppo**

Puoi registrare tutti i Ruoli di Prodotto o Ruoli di Tipo di prodotto che desideri in ciascun Gruppo.

1. Dalla pagina del Gruppo, seleziona **\+ Add Product Types**, oppure \+ **Add Product** dall'intestazione pertinente (Product Type Groups o Product Groups).
​

![image](images/Create_a_User_Group_for_shared_permissions_7.png)

2. Questo ti porterà a una pagina **Register New Products / Product Types**, dove puoi selezionare un Prodotto o Tipo di prodotto da aggiungere dal menu a discesa.

![image](images/Create_a_User_Group_for_shared_permissions_8.png)

3. Seleziona il Ruolo che vuoi che tutti i membri del Gruppo abbiano riguardo a questo particolare Prodotto o Tipo di prodotto.

I Gruppi non possono essere assegnati a Prodotti o Tipi di prodotto senza un Ruolo. Se non sei sicuro di quale Ruolo vuoi che un Gruppo abbia, Reader è una buona opzione 'predefinita'. Questo manterrà sicuro lo stato del tuo Prodotto finché non prendi la decisione finale sul Ruolo del Gruppo.

### **Assegnare Autorizzazioni di configurazione a un Gruppo**

Se vuoi che i Membri del tuo Gruppo accedano alle funzioni di Configurazione e controllino determinati aspetti di DefectDojo, puoi assegnare queste responsabilità dalla pagina del Gruppo.

Assegna i ruoli View, Add, Edit o Delete dal menu nell'angolo in basso a destra. Selezionare un'Autorizzazione di configurazione darà immediatamente al Gruppo l'accesso a questa particolare funzione.

![image](images/Create_a_User_Group_for_shared_permissions_9.png)
