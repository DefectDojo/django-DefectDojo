---
title: Impostare le notifiche personali
description: Configurare le notifiche per un account personale
aliases:
- /it/en/customize_dojo/notifications/configure_personal_notifs
---

## Configurare le notifiche personali

Le Notifiche personali vengono inviate in aggiunta alle Notifiche a livello di sistema e si applicano a qualsiasi Prodotto, Tipo di prodotto o altro tipo di dati a cui hai accesso. Le preferenze delle Notifiche personali si applicano solo a un singolo utente e possono essere impostate solo sull'account che le sta configurando.

![image](images/Configure_System_&_Personal_Notifications.png)

Le notifiche di sistema vengono impostate da un Superuser di DefectDojo e non possono essere disattivate dal singolo utente.

1. Parti dalla pagina Notifications (⚙️**Configuration \> Notifications** nella barra laterale).
2. Dal menu a discesa **Scope**, puoi selezionare quale insieme di notifiche desideri modificare.
3. Seleziona Personal Notifications.
4. Seleziona il metodo di notifica che desideri usare per ciascun tipo di notifica. Puoi selezionarne più di uno.

Le Notifiche personali non possono essere inviate tramite Microsoft Teams, poiché Teams consente solo di pubblicare notifiche globali in un unico canale.

### Ricevere notifiche personali per uno specifico Prodotto

Oltre alle notifiche personali standard, gli Utenti di DefectDojo possono anche ricevere notifiche per l'attività su uno specifico Prodotto. Questo è utile quando ci sono determinati Prodotti che un utente deve monitorare più da vicino.

![image](images/Configure_System_&_Personal_Notifications_3.png)

Questa configurazione può essere modificata dalla sezione **Notifications** nella pagina **Product**: ad esempio `your-instance.defectdojo.com/product/{id}`.

Da qui puoi impostare se desideri ricevere notifiche **🔔 Alert**, **Mail** o **Slack** per le azioni intraprese su questo particolare Prodotto. Queste notifiche si applicano in aggiunta a qualsiasi notifica a livello di sistema che già ricevi. 

Microsoft Teams non può inviare notifiche personali di alcun tipo, quindi le notifiche Teams non possono essere selezionate da questo menu.

Le notifiche email personali verranno sempre inviate all'indirizzo email associato al tuo login DefectDojo. Per configurare un account Slack personale per ricevere le notifiche, consulta la nostra [Guida](../email_slack_teams/#send-personal-notifications-to-slack).
