---
title: Impostare le notifiche a livello di sistema
description: Come configurare le notifiche personali e di sistema
aliases:
- /it/en/customize_dojo/notifications/configure_system_notifs
---

DefectDojo dispone di due diversi tipi di notifiche: **Personal** (inviate a un singolo account) e **System** (inviate a tutti gli utenti).

Sia le Notifiche personali di un account che le Notifiche di sistema globali possono essere configurate dalla stessa pagina: **⚙️Configuration \> Notifications** nella barra laterale.

![image](images/Configure_System_&_Personal_Notifications.png)

## Configurare le notifiche di sistema (interfaccia classica)

**Per modificare le notifiche a livello di sistema è necessario l'accesso da Superuser.**

1. Parti dalla pagina Notifications (⚙️ **Configuration \> Notifications** nella barra laterale).
2. Dal menu a discesa Scope, puoi selezionare quale insieme di notifiche desideri modificare.
3. Seleziona System Notifications.
4. Seleziona il metodo di consegna della notifica che desideri usare per ciascun tipo di notifica. Puoi selezionarne più di uno.

![image](images/Configure_System_&_Personal_Notifications_2.png)

Per impostare le destinazioni per le notifiche email a livello di sistema (Email, Slack o MS Teams), consulta la nostra [Guida](../email_slack_teams).

## Notifiche modello

I Superuser hanno anche accesso a un modulo "Template".  Il modulo Template consente di impostare le Notifiche personali predefinite abilitate per ogni nuovo utente.

## Dove vengono inviate le notifiche di sistema

Le notifiche di sistema verranno inviate a:
- l'unico indirizzo email specificato nelle System Settings (se abilitato)
- qualsiasi utente DefectDojo con un account e le autorizzazioni RBAC appropriate
- l'account Slack o Teams a livello di sistema.

Come per qualsiasi notifica in DefectDojo, le Notifiche di sistema verranno inviate solo agli utenti che hanno accesso ai dati pertinenti.  Quindi, anche se le Notifiche sui Prodotti sono impostate a livello di sistema, gli utenti riceveranno notifiche solo per i Prodotti che hanno accesso a visualizzare.

Questa restrizione non si applica alle Notifiche di sistema inviate a uno specifico indirizzo Email o canale Slack.

Consulta la nostra guida sul [controllo degli accessi basato sui ruoli](../../user_management/about_perms_and_roles/) per maggiori informazioni su RBAC e sull'impostazione delle autorizzazioni.

Tuttavia, gli account System Email, Slack e Teams collegati non possono applicare RBAC poiché non sono associati a uno specifico utente DefectDojo.  **Tutte le notifiche a livello di sistema selezionate verranno inviate a queste destinazioni, quindi dovresti assicurarti che questi canali siano accessibili solo a persone specifiche della tua organizzazione.**
