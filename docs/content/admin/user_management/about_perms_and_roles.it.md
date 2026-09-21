---
title: Autorizzazioni in DefectDojo
description: Riepilogo dettagliato di tutte le opzioni di autorizzazione di DefectDojo
  Pro
weight: 2
audience: pro
aliases:
- /it/en/customize_dojo/user_management/about_perms_and_roles
---

> **Funzionalità di DefectDojo Pro.** Il sistema RBAC basato su Membri / Gruppi / Ruoli globali descritto in questa pagina fa parte di DefectDojo Pro. DefectDojo open-source utilizza il modello [Utenti autorizzati](../os__authorized_users/) — consulta quella pagina per il controllo degli accessi in open-source, e le [note di aggiornamento alla 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) se stai passando da un'edizione all'altra.

Se hai un team di utenti che lavora in DefectDojo, è importante configurare correttamente il controllo degli accessi basato sui ruoli (Role\-Based Access Control, RBAC) in modo che gli utenti possano accedere solo a dati specifici. I dati di sicurezza sono altamente sensibili, e le opzioni di controllo degli accessi di DefectDojo permettono di definire in modo specifico l'accesso alle informazioni per ciascun membro del team.

Questo articolo è una panoramica di come funzionano le autorizzazioni in DefectDojo.  Se preferisci una descrizione dettagliata di **ogni azione** che può essere controllata dalle Autorizzazioni, consulta il nostro articolo **[Tabella delle autorizzazioni](../user_permission_chart/)**.

## Tipi di autorizzazioni

DefectDojo gestisce quattro diversi tipi di autorizzazioni:

* Gli utenti possono essere assegnati come **Membri** di **Prodotti o Tipi di prodotto**. L'appartenenza a un Prodotto è accompagnata da un **Ruolo** che consente agli utenti di visualizzare e interagire con i Tipi di dati (Tipi di prodotto, Prodotti, Engagement, Test e Riscontri) in DefectDojo. Gli utenti possono avere più appartenenze a Prodotti o Tipi di prodotto, con diversi livelli di accesso.
​
* Gli utenti possono anche avere assegnate **Autorizzazioni di configurazione**, che consentono loro di accedere alle pagine di configurazione di DefectDojo. Le Autorizzazioni di configurazione non sono correlate a Prodotti o Tipi di prodotto, e non sono associate ai Ruoli.
​
* Agli utenti possono essere assegnati **Ruoli globali**, che forniscono loro un livello di accesso standardizzato a tutti i Prodotti e Tipi di prodotto.
​
* Gli utenti possono essere configurati come **Superuser**: ruoli di livello amministratore che conferiscono loro il controllo e l'accesso a tutti i dati e la configurazione di DefectDojo.

Ciascuno di questi tipi di Autorizzazione può anche essere assegnato a un **Gruppo** **di utenti**. Se hai un numero elevato di utenti in DefectDojo, ad esempio un team di test dedicato a un determinato Prodotto, i Gruppi ti consentono di configurare e mantenere le autorizzazioni rapidamente.

## Appartenenza a Prodotto/Tipo di prodotto \& Ruoli

Quando gli utenti vengono assegnati come membri di un Prodotto o Tipo di prodotto, ricevono anche un ruolo che controlla come interagiscono con i dati dei Riscontri associati.

### Riepilogo dei ruoli

DefectDojo Pro include cinque **ruoli predefiniti**: Reader, Writer, Maintainer, Owner e API Importer. Ognuno di essi può essere assegnato a livello globale o all'interno di un Prodotto / Tipo di prodotto.

I ruoli predefiniti sono preset bloccati. Non possono essere modificati o eliminati, e le loro autorizzazioni sono le stesse su ogni istanza di DefectDojo Pro. Se nessuno di essi si adatta al modo in cui lavora il tuo team, puoi crearne uno su misura scegliendo le singole autorizzazioni oppure clonando un ruolo predefinito e adattandolo. Vedi [Ruoli RBAC personalizzati](../pro__custom_rbac_roles/).

Per "dati sottostanti" si intendono tutti i Prodotti, Engagement, Test, Riscontri o Endpoint annidati sotto un Prodotto, o Tipo di prodotto.

* Gli **utenti Reader** possono visualizzare i dati sottostanti di qualsiasi Prodotto o Tipo di prodotto a cui sono assegnati, e aggiungere commenti. Non possono modificare, aggiungere o alterare in altro modo i dati sottostanti, ma possono esportare Report e aggiungere Note ai dati.
​
* Gli **utenti Writer** hanno tutte le capacità dei Reader, oltre alla possibilità di aggiungere o modificare Engagement, Test e Riscontri. Non possono aggiungere nuovi Prodotti, né eliminare alcun dato sottostante.
​
* Gli **utenti Maintainer** hanno tutte le capacità dei Writer, oltre alla possibilità di modificare Prodotti o Tipi di prodotto. Possono aggiungere nuovi Membri con Ruoli al Prodotto o Tipo di prodotto, e possono anche eliminare Engagement, Test e Riscontri.
​
* Gli **utenti Owner** hanno il maggior livello di controllo su un Prodotto o Tipo di prodotto. Possono designare altri Owner, e possono anche eliminare i Prodotti o Tipi di prodotto a cui sono assegnati.
​
* Gli **utenti API Importer** hanno capacità limitate. Questo Ruolo consente un accesso API limitato senza esporre la maggior parte degli endpoint API, quindi è utile per l'automazione o per utenti destinati a essere "esterni" a DefectDojo. Possono visualizzare i dati sottostanti, aggiungere / modificare Engagement, e importare dati di scansione.

Per informazioni dettagliate sui Ruoli predefiniti, consulta la nostra **[Tabella delle autorizzazioni per ruolo](../user_permission_chart/)**. Per l'elenco completo delle autorizzazioni che è possibile assegnare a un ruolo, e per scoprire come crearne uno personalizzato, consulta **[Ruoli RBAC personalizzati](../pro__custom_rbac_roles/)**.

### Ruoli globali

Gli utenti con **Ruoli globali** possono visualizzare e interagire con qualsiasi Tipo di dati (Tipi di prodotto, Prodotti, Engagement, Test e Riscontri) in DefectDojo, in base al Ruolo assegnato.

### Appartenenze ai gruppi

I Gruppi di utenti possono essere aggiunti come Membri di un Prodotto o Tipo di prodotto. Gli utenti che fanno parte del Gruppo erediteranno l'accesso a tutti i Prodotti o Tipi di prodotto associati, e erediteranno il Ruolo assegnato al Gruppo.

#### Utenti con più ruoli

* Se un Utente viene assegnato come membro di un Prodotto, non gli vengono concesse automaticamente le autorizzazioni associate al Tipo di prodotto.

* Se un Utente si ritrova con più di un ruolo sullo stesso Prodotto o Tipo di prodotto (ad esempio uno assegnato direttamente e un altro ereditato da un Gruppo), riceve le autorizzazioni **combinate** di tutti i ruoli che detiene in quel contesto.

* Il Ruolo di Prodotto di un Utente ha sempre la precedenza sul suo Ruolo di Tipo di prodotto "predefinito".
​
* Il Ruolo di Prodotto / Tipo di prodotto di un Utente ha sempre la precedenza sul suo Ruolo globale all'interno del Prodotto o Tipo di prodotto sottostante. Ad esempio, se un Utente ha un Ruolo di Tipo di prodotto Reader, ma è anche assegnato come Owner su un Prodotto annidato sotto quel Tipo di prodotto, avrà autorizzazioni Owner aggiuntive solo per quel Prodotto.
​
* I Ruoli non possono togliere autorizzazioni, possono solo aggiungerne di nuove. Ad esempio, se un Utente ha un Ruolo di Tipo di prodotto o un Ruolo globale Owner, assegnargli un ruolo Reader su un determinato Prodotto non gli toglierà le autorizzazioni Owner su quel Prodotto.
​
* Lo stato di Superuser ha sempre la precedenza su qualsiasi Ruolo assegnato.

## Superuser

I Superuser (Admin) non hanno limitazioni nel sistema. Possono modificare tutte le impostazioni, gestire gli utenti e avere accesso in lettura / scrittura a tutti i dati. Possono anche modificare le regole di accesso per tutti gli utenti in DefectDojo. I Superuser ricevono inoltre le notifiche per tutti i problemi e gli avvisi di sistema.

Per impostazione predefinita, il primo account creato su una nuova istanza di DefectDojo avrà le autorizzazioni Superuser. Quell'utente potrà modificare le autorizzazioni per tutti gli utenti DefectDojo successivi. Solo un Superuser esistente può aggiungere un altro superuser, o assegnare un Ruolo globale a un utente.


## Autorizzazioni di configurazione

Le Autorizzazioni di configurazione, sebbene simili, non sono correlate a Prodotti o Ruoli. Devono essere assegnate separatamente dai Ruoli. **Gli utenti normali non dispongono di alcuna Autorizzazione di configurazione per impostazione predefinita, e l'assegnazione di queste autorizzazioni di configurazione deve essere effettuata con attenzione.**

Le Autorizzazioni di configurazione possono essere assegnate agli utenti in diversi modi:

1. Le Autorizzazioni di configurazione possono essere assegnate direttamente agli utenti. Le autorizzazioni specifiche possono essere configurate direttamente nella pagina di un Utente.

2. Le Autorizzazioni di configurazione possono essere assegnate ai Gruppi di utenti. Come per i Ruoli, è possibile aggiungere Autorizzazioni di configurazione specifiche ai Gruppi, il che conferirà queste autorizzazioni a tutti i membri del Gruppo.

I Superuser dispongono di tutte le Autorizzazioni di configurazione, quindi non hanno una sezione Autorizzazioni di configurazione nella loro pagina Utente.

### Autorizzazioni di configurazione del gruppo

Se gli utenti fanno parte di un Gruppo, dispongono anche di Autorizzazioni di configurazione del gruppo che controllano il loro livello di accesso alla configurazione di un Gruppo. Le Autorizzazioni del gruppo non corrispondono all'appartenenza del Gruppo a Prodotti o Tipi di prodotto.

Se gli utenti creano un nuovo Gruppo, ricevono per impostazione predefinita il ruolo Owner del nuovo Gruppo.

Per ulteriori informazioni sulle Autorizzazioni di configurazione, consulta la nostra **[Tabella delle autorizzazioni di configurazione](../user_permission_chart/#configuration-permission-chart)**.

## Gestire le autorizzazioni predefinite

Quando in DefectDojo viene creato un nuovo utente — manualmente, tramite SAML / SSO, o tramite un qualsiasi provider di social-auth — questo **non ha alcuna autorizzazione per impostazione predefinita**. Al primo accesso vedrà zero Tipi di prodotto, zero Prodotti e zero Engagement. Non può visualizzare né interagire con alcun dato finché un Superuser non gli concede l'accesso (direttamente, tramite un Ruolo globale, tramite un'appartenenza a Prodotto / Tipo di prodotto, o aggiungendolo a un Gruppo).

Se desideri che ogni nuovo utente creato riceva automaticamente un livello di accesso di base — ad esempio, "ogni nuovo utente SSO deve essere Reader in un determinato gruppo" — puoi configurare un **Default group** nella pagina System Settings.

1. Apri **⚙️ Configuration → System Settings** (solo Superuser).
2. Imposta **Default group** sul [Gruppo di utenti](../create_user_group/) a cui devono unirsi i nuovi utenti creati.
3. Imposta **Default group role** sul ruolo che devono avere in quel gruppo (ad es. **Reader**).
4. Facoltativamente, imposta **Default group email pattern** su un'espressione regolare (ad es. `.*@yourcompany\.com$`) in modo che il gruppo predefinito venga applicato solo agli utenti la cui email corrisponde.
5. Save.

Sia **Default group** che **Default group role** devono essere impostati — se uno dei due è vuoto, il gruppo predefinito non viene applicato.

Questa impostazione si applica a ogni percorso di creazione utente: creazione manuale, SAML, OAuth e altri provider di social-auth. Non viene applicata retroattivamente — gli utenti esistenti manterranno le loro appartenenze ai gruppi attuali anche se modifichi questa impostazione in seguito.

Per indicazioni specifiche su SSO, consulta [Configurazione SAML](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users) o la sezione del tuo provider in [Configurazione SSO](../configure_sso/).
