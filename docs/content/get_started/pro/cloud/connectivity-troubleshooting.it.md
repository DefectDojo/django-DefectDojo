---
title: Risoluzione dei problemi di connettività
description: Ricollegati alla tua istanza DefectDojo
weight: 2
audience: pro
aliases:
- /it/en/cloud_management/connectivity-troubleshooting
---

Se hai difficoltà ad accedere alla tua istanza DefectDojo, ecco alcuni passaggi che puoi seguire per ricollegarti:

## Riesco ad accedere al sito, ma non riesco a effettuare il login

1. Puoi reimpostare la password del tuo account dalla pagina di login: **yourcompanyinstance.cloud.defectdojo.com/login**. Fai clic su 'I forgot my password' per iniziare il processo.
​

![image](images/Connectivity_Troubleshooting.png)

2. Inserisci il tuo indirizzo email e fai clic su "Reset my password".
​
3. Dovresti ricevere un'email con l'oggetto "`Password reset on yourcompanyinstance.cloud.defectdojo.com`". Questa email contiene un link su cui puoi fare clic per impostare una nuova password.


![image](images/Connectivity_Troubleshooting_2.png)

Se non ricevi un'email, controlla la cartella Spam. In caso contrario, chiedi all'amministratore DefectDojo del tuo team di confermare che tu abbia un account registrato sulla tua istanza.



## Non riesco ad accedere al sito cloud.defectdojo della mia azienda

Se il sito cloud.defectdojo della tua azienda non si carica nel browser, o va in timeout, potrebbe essere necessario che la tua azienda modifichi le regole del firewall per accettare la tua connessione.

Le regole del firewall possono essere modificate nel tuo Cloud Manager all'indirizzo <https://cloud.defectdojo.com/accounts/manage_subscriptions>.

Se la tua azienda utilizza una VPN condivisa, un proxy server o uno strumento simile, assicurati che sia autorizzato a connettersi a DefectDojo e che l'indirizzo IP sia incluso nelle regole del firewall di DefectDojo.

Se il problema persiste, contatta [support@defectdojo.com](mailto:support@defectdojo.com) .



## Non riesco ad accedere al Cloud Manager

Se non riesci ad accedere al Cloud Manager, vai alla pagina di Login all'indirizzo <https://cloud.defectdojo.com/accounts/login/> e fai clic su **"Forgot your password?"**


![image](images/Connectivity_Troubleshooting_3.png)
Ti verrà chiesto di inserire il tuo indirizzo email, e il nostro team ti invierà un'email con un link per reimpostare la password e inserirne una nuova.

Tieni presente che questo metodo di login funziona solo per il **Cloud Manager**, un sito di amministrazione a cui non tutti i membri del tuo team potrebbero avere accesso. Accedere direttamente alla tua istanza per utilizzare DefectDojo è possibile solo collegandosi direttamente a **yourcompanyinstance.cloud.defectdojo.com/login**.



## Ho perso l'accesso ai miei codici MFA

* **Per il Cloud Manager:** Se perdi l'accesso ai tuoi codici MFA o all'app Authenticator, contatta il Support di DefectDojo all'indirizzo [support@defectdojo.com](mailto:support@defectdojo.com).
* **Per un'istanza DefectDojo:** Prova prima uno dei **codici di recupero** rilasciati al momento della configurazione dell'MFA — da inserire al posto del codice a sei cifre durante il login. Se non sono disponibili, un amministratore con accesso al server può rimuovere l'MFA dall'account usando `python manage.py remove_mfa --username <username>`; l'utente potrà quindi accedere con la propria password e ri\-registrarsi, mantenendo tutti i permessi e la cronologia esistenti. Su DefectDojo Cloud, contatta il Support per far eseguire quel comando. Vedi [Autenticazione a più fattori](/admin/user_management/pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device) per tutte le opzioni.
