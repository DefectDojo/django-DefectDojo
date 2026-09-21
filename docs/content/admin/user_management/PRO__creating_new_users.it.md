---
title: Creare un nuovo utente
description: Come inserire un nuovo utente nella tua istanza DefectDojo
audience: pro
weight: 1
---

Questa pagina descrive il flusso di lavoro consigliato per l'onboarding di nuovi utenti in un'istanza DefectDojo. Gli utenti DefectDojo possono essere utilizzati sia come account standard, gestiti da persone, sia come account di servizio.

L'amministratore che crea l'account è responsabile della consegna delle credenziali iniziali (nome utente e password) al nuovo utente.

## Flusso di lavoro consigliato

1. **Crea l'account utente** in DefectDojo (solo Superuser):
   * Vai su **👤 Utenti → ➕ Nuovo utente**.
   * Inserisci il nome e l'indirizzo email del nuovo utente.
   * Imposta una password temporanea.
   * Invia il modulo.

2. **Assegna le autorizzazioni** in base alle esigenze: appartenenza a Prodotto/Tipo di prodotto, Autorizzazioni di configurazione, Ruolo globale o stato Superuser. Per i dettagli, consulta [Impostare le autorizzazioni di un Utente](../set_user_permissions/). Un nuovo utente senza alcuna assegnazione non potrà visualizzare alcun Prodotto o Riscontro.

3. **Invia le credenziali al nuovo utente tramite un canale separato** (email, lo strumento di chat del tuo team o qualunque modo tu usi normalmente per condividere segreti). Includi:
   * L'URL dell'istanza DefectDojo.
   * Il nome utente (in genere il suo indirizzo email).
   * La password temporanea appena impostata.
   * Una nota che indichi di cambiare la password e abilitare l'MFA (se la tua istanza utilizza l'MFA) al primo accesso.

4. **Il nuovo utente effettua l'accesso e sostituisce la credenziale.** Può:
   * Accedere con la password temporanea e poi cambiarla dal menu del proprio profilo, oppure
   * Utilizzare il link **I forgot my password** nella pagina di accesso per impostare direttamente una password senza usare quella temporanea. La password temporanea resta comunque necessaria per l'esistenza del record iniziale dell'account, ma l'utente non deve ricordarla se utilizza il flusso di reimpostazione della password.

5. **Il nuovo utente configura l'MFA** dal proprio menu del profilo. Consigliamo vivamente di richiedere l'MFA per tutti gli utenti sulle istanze non protette da SSO.

## Utenti SSO

Se la tua istanza è configurata con [SSO](../configure_sso/), il flusso di lavoro è diverso: gli utenti vengono in genere creati al primo accesso dall'Identity Provider ed è necessario solo assegnare loro l'appartenenza a un gruppo o i ruoli in un secondo momento.

## Recupero da un token MFA perso

Se un utente perde l'accesso al proprio dispositivo MFA, può accedere utilizzando uno dei codici di recupero emessi al momento della registrazione. Se anche questi sono andati persi, un amministratore con accesso al server può rimuovere l'MFA dall'account con `python manage.py remove_mfa --username <username>`, dopodiché l'utente accede con la propria password e si registra nuovamente: le sue autorizzazioni e la sua cronologia vengono preservate, quindi non è necessario creare un account sostitutivo.

Consulta [Autenticazione a più fattori (MFA)](../pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device) per tutte le opzioni di recupero, e tieni presente che l'accesso al **Cloud Manager** in sé è una questione separata: consulta la [guida alla risoluzione dei problemi di connettività](/get_started/pro/cloud/connectivity-troubleshooting/#ive-lost-access-to-my-mfa-codes).
