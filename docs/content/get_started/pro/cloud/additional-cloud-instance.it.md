---
title: Configurare un'istanza Cloud aggiuntiva
description: Aggiungi un'istanza DefectDojo di test, di sviluppo o di altro tipo al
  tuo account
weight: 3
audience: pro
aliases:
- /it/en/cloud_management/additional-cloud-instance
---

Il processo per aggiungere una seconda istanza Cloud è più o meno lo stesso di quando hai aggiunto la tua prima istanza. Questa guida presuppone che tu abbia già configurato il tuo server DefectDojo iniziale e che tu abbia un accordo con il nostro team Sales per aggiungere un'altra istanza.

Se non hai ancora richiesto un'istanza Cloud aggiuntiva, contatta [info@defectdojo.com](mailto:info@defectdojo.com) prima di procedere.

## Passaggio 1: Avvia il processo New Subscription

Puoi avviare questo processo dal seguente link: <https://cloud.defectdojo.com/accounts/onboarding/step_1>, oppure facendo clic su 🛒 **New Subscription** dalla pagina del Cloud Manager (cloud.defectdojo.com).

![image](images/request_a_trial.png)

## Passaggio 2: Imposta la tua Server Label

Inserisci il **Name** della tua azienda e la **Server Label** che vuoi usare con DefectDojo. Verrà quindi creato un dominio personalizzato per la tua istanza DefectDojo sui nostri server.

Mantieni il nome della tua azienda invariato, ma crea una nuova Server Label e seleziona il pulsante "**Use Server Label in Domain**", in modo da poter distinguere facilmente i tuoi server.

![image](images/request_a_trial_2.png)

## Passaggio 3: Seleziona una Server Location

Seleziona una Server Location dal menu a tendina. Come in precedenza, ti consigliamo di selezionare un server geograficamente più vicino ai tuoi utenti per ridurre la latenza del server.

![image](images/request_a_trial_3.png)

## Passaggio 4: Configura le tue Firewall Rules

Inserisci gli intervalli di indirizzi IP, la subnet mask e le etichette a cui vuoi consentire l'accesso a DefectDojo. Indirizzi IP e regole aggiuntivi possono essere aggiunti o modificati dal tuo team dopo che l'istanza è attiva e funzionante.

Se lo desideri, queste regole firewall possono essere diverse da quelle della tua istanza DefectDojo principale.

![image](images/request_a_trial_4.png)

Se vuoi utilizzare servizi esterni con questa istanza (GitHub o JIRA), seleziona le caselle appropriate elencate sotto **Select External Services.**

Puoi anche procedere senza firewall selezionando **Proceed Without Firewall**.  Il tuo firewall può essere riattivato in seguito.

## Passaggio 5: Conferma il tipo di piano e la frequenza di fatturazione

Al termine del processo, verrai messo in contatto con il nostro team di vendita, che potrà fornirti un preventivo accurato per il tuo nuovo server. Ti consigliamo di selezionare il Plan Type che ha le specifiche del server di cui hai bisogno per la nuova istanza.

![image](images/request_a_trial_5.png)

Un secondo server potrebbe non richiedere gli stessi requisiti di storage, CPU e RAM della tua istanza 'principale', ma questo dipenderà dai requisiti tecnici del tuo team.

## Passaggio 6: Rivedi e invia la tua richiesta

Ti verrà chiesto di rivedere ancora una volta la tua richiesta. Una volta inviata, solo le regole del firewall potranno essere modificate dal tuo team senza l'assistenza del Support.

![image](images/request_a_trial_6.png)

Dopo aver esaminato e accettato il License and Support Agreement di DefectDojo, puoi procedere con **Checkout With Stripe**, oppure, se hai già un accordo di fatturazione in essere, puoi fare clic su **Contact Sales**.

Il nostro team di Support ti contatterà con le credenziali di accesso quando il tuo server sarà stato approvato e messo in produzione.
