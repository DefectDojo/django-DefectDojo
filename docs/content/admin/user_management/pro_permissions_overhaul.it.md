---
title: Impostare le autorizzazioni in Pro
description: Revisione, funzionalità Pro
weight: 3
audience: pro
aliases:
- /it/en/customize_dojo/user_management/pro_permissions_overhaul
---

## Introduzione ai tipi di autorizzazione

I singoli utenti dispongono di quattro diversi tipi di autorizzazione che possono essere loro assegnati:

* Gli utenti possono essere assegnati come **Membri di Prodotti o Tipi di prodotto**. Questo consente loro di visualizzare e interagire con i Tipi di dati (Tipi di prodotto, Prodotti, Engagement, Test e Riscontri) in DefectDojo, in base al ruolo che viene loro assegnato sullo specifico Prodotto. Gli utenti possono avere più appartenenze a Prodotti o Tipi di prodotto, con diversi livelli di accesso.
​
* Gli utenti possono anche avere assegnate **Autorizzazioni di configurazione**, che consentono loro di accedere alle pagine di configurazione di DefectDojo. Le Autorizzazioni di configurazione non sono correlate a Prodotti o Tipi di prodotto.
​
* Agli utenti possono essere assegnati **Ruoli globali**, che forniscono loro un livello di accesso standardizzato a tutti i Prodotti e Tipi di prodotto.
​
* Gli utenti possono essere configurati come **Superuser**: ruoli di livello amministratore che conferiscono loro il controllo e l'accesso a tutti i dati e la configurazione di DefectDojo.

Puoi anche creare Gruppi se desideri assegnare l'Appartenenza a Prodotti, Autorizzazioni di configurazione o Ruoli globali a un gruppo di utenti contemporaneamente. Se hai un numero elevato di utenti in DefectDojo, ad esempio un team di test dedicato a un determinato Prodotto, i Gruppi possono essere una funzionalità più utile.

## Superuser \& Ruoli globali

Parte della configurazione del controllo degli accessi basato sui ruoli (RBAC) potrebbe richiedere la creazione di Superuser aggiuntivi, o di utenti con Ruoli globali.

* I Superuser (Admin) non hanno limitazioni nel sistema. Possono modificare tutte le impostazioni, gestire gli utenti e avere accesso in lettura / scrittura a tutti i dati. Possono anche modificare le regole di accesso per tutti gli utenti in DefectDojo. I Superuser ricevono inoltre le notifiche per tutti i problemi e gli avvisi di sistema.
* Gli utenti con Ruoli globali possono visualizzare e interagire con qualsiasi Tipo di dati (Tipi di prodotto, Prodotti, Engagement, Test e Riscontri) in DefectDojo, in base al Ruolo loro assegnato. Per maggiori informazioni su ciascun Ruolo e sui privilegi associati, consulta il nostro articolo Introduzione ai Ruoli.
* Gli utenti possono anche avere Autorizzazioni di configurazione specifiche assegnate, che consentono loro di accedere a determinate pagine di configurazione di DefectDojo. Gli utenti non hanno alcuna Autorizzazione di configurazione per impostazione predefinita.

Per impostazione predefinita, il primo account creato su una nuova istanza di DefectDojo avrà le autorizzazioni Superuser. Quell'utente potrà modificare le autorizzazioni per tutti gli utenti DefectDojo successivi. Solo un Superuser esistente può aggiungere un altro superuser, o assegnare un Ruolo globale a un utente.

Le autorizzazioni in <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> sono state semplificate, per rendere più facile assegnare l'accesso agli oggetti.  Questa funzionalità è accessibile tramite l'[interfaccia Pro](/get_started/about/ui_pro_vs_os/).

### Aprire la finestra delle autorizzazioni

![image](images/pro_permissions.png)

Quando visualizzi un Tipo di prodotto o un Prodotto, puoi aprire la finestra delle Autorizzazioni per impostare rapidamente le autorizzazioni.  Questo menu si trova in una Tabella facendo clic sui puntini orizzontali **"⋮"**.  Se stai visualizzando la pagina di un singolo **Prodotto** o **Tipo di prodotto**, questo menu si trova sotto l'icona a forma di ingranaggio blu '⚙️'.

## Impostare le autorizzazioni tramite la finestra delle autorizzazioni

![image](images/pro_permissions_2.png)

1. Nella parte superiore di questa finestra, puoi scegliere di gestire le autorizzazioni per un singolo utente o per un [gruppo di utenti](../create_user_group).
2. Qui puoi selezionare un utente o un gruppo da aggiungere al Prodotto, e selezionare  il [Ruolo](../about_perms_and_roles) che vuoi che quell'utente abbia.
3. Nella tabella inferiore, puoi vedere un elenco di tutti gli utenti o gruppi che hanno accesso a questo oggetto.  Puoi anche assegnare rapidamente un nuovo ruolo a uno di questi utenti o gruppi dal menu a discesa.

## Impostare le autorizzazioni di configurazione tramite la vista Utente

Le autorizzazioni di configurazione di un utente possono ora essere impostate con un approccio più intuitivo. Dalla vista Users, tutte le autorizzazioni di configurazione vengono visualizzate in un menu a discesa, quindi raggruppate per tipo di autorizzazione. Se la selezione delle autorizzazioni di configurazione è diversa dal valore attuale, viene visualizzato un pulsante "Update Configuration Permissions". Quando viene cliccato, all'utente verrà chiesto di confermare di voler aggiornare le autorizzazioni per il gruppo selezionato prima che l'aggiornamento venga effettuato.

![image](images/pro_user_view.png)
