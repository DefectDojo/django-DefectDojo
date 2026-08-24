---
title: Utilizzo del Cloud Manager
description: Gestisci il tuo abbonamento e le impostazioni dell'account
weight: 1
collapsed: true
audience: pro
aliases:
- /it/en/cloud_management/using-cloud-manager
---

Accedendo al Cloud Manager di DefectDojo puoi configurare le impostazioni del tuo account e gestire il tuo abbonamento a DefectDojo Cloud.

## **Nuovo abbonamento**
<https://cloud.defectdojo.com/accounts/onboarding/step_1>

Questa pagina ti consente di richiedere una nuova istanza Cloud, [o un'istanza aggiuntiva](../additional-cloud-instance/), da DefectDojo.

## **Gestisci abbonamenti**
<https://cloud.defectdojo.com/accounts/manage_subscriptions>

La pagina di Gestione degli abbonamenti mostra tutte le tue istanze Cloud attualmente attive e ti consente di configurare le impostazioni del Firewall per ciascuna istanza.

### Modifica delle impostazioni del Firewall
![image](images/using_the_cloud_manager.png)

Una volta nella pagina **Edit Subscription**, inserisci l'Indirizzo IP, la Maschera e l'Etichetta per la regola che desideri aggiungere. Se è necessaria più di una regola firewall, fai clic su **Add New Range** per creare una nuova regola vuota.

![image](images/using_the_cloud_manager_2.png)

Qui puoi anche aprire il tuo firewall verso servizi esterni (GitHub e Jira Cloud).  Puoi anche disabilitare completamente il tuo firewall, se lo desideri, selezionando **Proceed Without Firewall** dal menu.

## Aggiungere utenti aggiuntivi al Cloud Portal

Se hai più utenti a cui vuoi dare il controllo sul tuo Cloud Portal / abbonamento DefectDojo, puoi aggiungerli utilizzando questo modulo.  Gli utenti che vuoi aggiungere dovranno aver creato il proprio account Cloud Portal su cloud.defectdojo.com; avere un account sulla tua istanza DefectDojo non è sufficiente.

![image](images/using_the_cloud_manager_5.png)

Inserisci l'email associata all'account Cloud Portal dell'utente e fai clic su Submit per aggiungerlo al tuo elenco di utenti collegati.  L'utente sarà ora in grado di gestire il Cloud Portal e il tuo abbonamento DefectDojo.

## Risorse
<https://cloud.defectdojo.com/resources/>

La pagina Resources contiene un modulo Contact Us, che puoi utilizzare per metterti in contatto con il nostro team di Supporto.

![image](images/using_the_cloud_manager_3.png)

## Strumenti
<https://cloud.defectdojo.com/external_tools/defectdojo-cli>

La pagina Tools è uno dei posti in cui puoi scaricare strumenti Pro esterni, come Universal Importer o DefectDojo CLI.  Questi strumenti sono componenti aggiuntivi esterni che possono essere utilizzati per creare rapidamente una pipeline di importazione da riga di comando nella tua rete. Per maggiori informazioni su questi strumenti, consulta la documentazione [Strumenti esterni](/import_data/pro/specialized_import/external_tools/).

![image](images/using_the_cloud_manager_6.png)


## Impostazioni dell'account
<https://cloud.defectdojo.com/accounts/settings>

La pagina delle impostazioni dell'account ha quattro sezioni:

* **User Contact** ti consente di impostare Username, Indirizzo email, Nome e Cognome.
* **Email Accounts** ti consente di aggiungere ulteriori indirizzi email al tuo account. L'aggiunta di un account email aggiuntivo invierà un'email di verifica al nuovo indirizzo.
* **Manage Social Accounts** ti consente di collegare DefectDojo Cloud alle tue credenziali GitHub o Google, che possono essere utilizzate per accedere al posto di username e password.
* **MFA Settings** ti consente di aggiungere un codice MFA a Google Authenticator, 1Password o app simili. Aggiungere un ulteriore passaggio al processo di login è un buon accorgimento proattivo per prevenire accessi non autorizzati.

### Aggiungere l'MFA al login del tuo Cloud Portal
<https://cloud.defectdojo.com/settings/mfa/configure/>

Nota che questo aggiungerà l'MFA solo al login di DefectDojo Cloud, non al login della tua app DefectDojo.

![image](images/using_the_cloud_manager_4.png)

1. Inizia installando un'app Authenticator che supporti l'autenticazione tramite codice QR sul tuo smartphone o computer.
2. Una volta fatto, fai clic su **Generate QR Code**.
3. Scansiona il codice QR fornito in DefectDojo utilizzando la tua app Authenticator, e poi inserisci il codice a sei\-cifre fornito dalla tua app.
4. Fai clic su **Enable Multi\-Factor Authentication**.
