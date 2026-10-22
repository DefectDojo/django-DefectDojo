---
title: Informazioni su Notifiche e 🔔 Alert
description: Informazioni su notifiche e alert in-app
aliases:
- /it/en/customize_dojo/notifications/about_notifications
---

DefectDojo ti tiene aggiornato in diversi modi. Le notifiche possono essere inviate per Engagement imminenti, [menzioni utente](/triage_findings/findings_workflows/intro_to_findings/#notes-and-mentions), scadenza SLA e altri eventi nel software.

Questo articolo fornisce una panoramica delle notifiche sia a livello di Sistema che Personale.

## Tipi di notifica

DefectDojo gestisce le notifiche in due modi diversi:

* Le **Notifiche a livello di sistema** vengono inviate a tutti gli utenti.
* **Le Notifiche personali vengono impostate dai singoli utenti e vengono ricevute in aggiunta a eventuali Notifiche a livello di sistema.**

In entrambi i casi, si applicano le regole del [controllo degli accessi basato sui ruoli](../../user_management/about_perms_and_roles/), quindi gli utenti non riceveranno notifiche di attività per Prodotti o Tipi di prodotto (o i relativi oggetti correlati) a cui non hanno accesso.

## Metodi di consegna delle notifiche

Esistono quattro metodi di consegna per le notifiche di DefectDojo:

* DefectDojo può condividere **🔔 Alert,** memorizzati come elenco nell'interfaccia di DefectDojo
* DefectDojo può inviare notifiche a un indirizzo **Email**
* DefectDojo può inviare notifiche a **Slack,** in un canale condiviso o individuale
* DefectDojo può inoltre inviare notifiche a **Microsoft Teams** in un canale condiviso

Le notifiche possono essere inviate contemporaneamente a più destinazioni.

Per ricevere notifiche su Slack e Teams è necessaria un'integrazione funzionante. Per maggiori informazioni su come configurare questa integrazione, consulta la nostra [Guida](../email_slack_teams).

## Avvisi in-app

Il sistema di Alert di DefectDojo ti tiene aggiornato su tutte le attività relative a Prodotti o al sistema.

### L'elenco degli Alert

L'elenco degli Alert è sempre visibile nell'angolo in alto a destra di DefectDojo e contiene un elenco compatto delle notifiche. Facendo clic su ciascun Alert verrai indirizzato direttamente alla pagina pertinente in DefectDojo.

Puoi aprire il tuo elenco degli Alert facendo clic sull'**icona 🔔▼** nell'angolo in alto a destra:

![image](images/About_In-App_Alerts.png) 

Per visualizzare tutte le tue notifiche, con ulteriori dettagli, puoi fare clic sul pulsante **See All Alerts \>**, che aprirà la **pagina degli Alert**.

Puoi anche selezionare **Clear All Alerts \>** dall'elenco degli Alert.

### La pagina degli Alert

La pagina degli Alert memorizza tutti i tuoi Alert in DefectDojo con ulteriori dettagli. In questa pagina puoi leggere le descrizioni di ciascun Alert in DefectDojo e rimuoverli dalla coda degli Alert quando non ti servono più.

![image](images/About_In-App_Alerts_2.png)

Per rimuovere uno o più Alert dalla pagina degli Alert, seleziona la casella vuota accanto ad esso, quindi fai clic sul pulsante **Remove selected** nell'angolo in basso a destra della pagina.

### Note sugli Alert

* Leggere un Alert o aprire la pagina degli Alert non rimuoverà alcun Alert dal conteggio accanto all'icona a forma di campana. Questo ti consente di accedere facilmente agli Alert passati per usarli come promemoria o come registro di attività personale.
* L'uso della funzione **Clear All Alerts \>** nel menu degli Alert cancellerà completamente anche la **pagina degli Alert**, quindi usa questa funzione con cautela.
* La rimozione di un Alert influisce solo sul tuo elenco degli Alert: non avrà effetto sugli Alert di altri utenti.
* La rimozione di un Alert non elimina alcuna cronologia di importazione o registro di attività da DefectDojo.

## Restringere le notifiche di richiesta di revisione (Pro)

Se una revisione viene richiesta a tutti i revisori idonei, tutti coloro che sono idonei su quell'asset vengono notificati. Si tratta di molte email per un revisore che si occupa solo di una parte del tuo parco asset.

Nell'interfaccia di DefectDojo Pro puoi restringere le tue notifiche di richiesta di revisione. Nella pagina delle impostazioni delle notifiche, in **Review Requests**:

* **Review Request Scope** — *All* (l'impostazione predefinita) ti notifica su tutto ciò che puoi vedere. *Selected* ti limita agli asset e ai tipi di asset che scegli.
* **Review Request Assets** / **Review Request Asset Types** — la porzione del parco asset su cui vuoi essere informato. Una richiesta corrisponde se riguarda uno degli asset selezionati *oppure* uno dei tipi di asset selezionati.

Due cose da chiarire:

* Scegliere *Selected* e non selezionare nulla significa **nessuno**, non tutti.
* Il restringimento sopprime la notifica, **non la richiesta**. Rimani un revisore richiesto e la richiesta continua a comparire nella tua coda [My Work](/metrics_reports/dashboards/pro__my_work/) in **Awaiting My Review** — semplicemente non ricevi un messaggio al riguardo. Questo è intenzionale: la coda è il registro permanente, le notifiche sono il promemoria.

Questo restringimento ha inoltre la precedenza sull'override a livello di sistema descritto di seguito, quindi un revisore che si è escluso non viene notificato anche quando `review_requested` è configurato per avere la precedenza sulle preferenze personali.

Il restringimento può anche essere impostato tramite API sull'endpoint delle notifiche, il che è l'approccio pratico se stai configurando molti revisori contemporaneamente.

## Notifiche di assegnazione del lavoro (Pro)

Quando i Riscontri ti vengono assegnati, la notifica **Work Assigned** ti indica quanti sono e include un link alla tua coda My Work.

È aggregata per persona anziché per Riscontro: assegnare cento Riscontri invia un solo messaggio, non cento. Come per le richieste di revisione, l'assegnazione è visibile nella tua coda indipendentemente dal fatto che la notifica ti raggiunga o meno.

## Considerazioni per la versione open source

### Override specifici

Le impostazioni delle notifiche di sistema (scope: system) descrivono l'invio di notifiche ai superadmin. Le impostazioni delle notifiche utente (scope: personal) descrivono l'invio di notifiche allo specifico utente.

Tuttavia, esiste un caso d'uso specifico in cui l'utente decide di disabilitare le notifiche (per ridurre il rumore) ma l'impostazione di sistema viene usata per sovrascrivere questo comportamento. Questi override si applicano per impostazione predefinita solo a `user_mentioned` e `review_requested`.

L'ambito di questa impostazione è personalizzabile (vedi la variabile d'ambiente `DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP`).

Per maggiori informazioni su questo comportamento, consulta la [pull request correlata #9699](https://github.com/DefectDojo/django-DefectDojo/pull/9699/)

### Webhook (sperimentale)

DefectDojo supporta anche webhook che seguono gli stessi eventi delle altre notifiche (puoi essere notificato nelle stesse situazioni). I dettagli sulla configurazione sono descritti nella [pagina correlata](/automation/api/notification_webhooks/).
