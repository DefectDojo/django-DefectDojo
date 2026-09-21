---
title: Creazione di un nuovo utente
description: Come inserire un nuovo utente nella tua istanza di DefectDojo
audience: opensource
weight: 1
---

Questa pagina descrive il flusso di lavoro consigliato per l'onboarding e l'aggiunta di nuovi utenti a un'istanza di DefectDojo.  Gli utenti di DefectDojo possono essere utilizzati sia come account standard gestiti da persone, sia come account di servizio.

L'amministratore che crea l'account è responsabile della consegna delle credenziali iniziali (nome utente e password) al nuovo utente.

## Flusso di lavoro consigliato

1. **Crea l'account utente** in DefectDojo (solo Superuser):
   * Vai su **👤 Users → Users** per aprire la tabella All Users.
   * Fai clic sull'icona 🛠️ (chiave inglese e cacciavite incrociati).
   * Inserisci il nome e l'indirizzo email del nuovo utente.
   * Imposta una password temporanea.
   * Invia il modulo.

2. **Assegna i permessi** come opportuno — appartenenza a Prodotto/Tipo di prodotto, Configuration Permissions, Global Role o stato di Superuser. Per i dettagli, vedi [Impostare i permessi di un utente](../set_user_permissions/). Un nuovo utente senza alcuna assegnazione non potrà vedere nessun Prodotto o Riscontro.

3. **Invia le credenziali al nuovo utente fuori banda** (via email, lo strumento di chat del tuo team, o comunque tu condivida normalmente i segreti). Includi:
   * L'URL dell'istanza DefectDojo.
   * Il nome utente (in genere il loro indirizzo email).
   * La password temporanea appena impostata.
   * Una nota che li invita a cambiare la password e ad attivare l'MFA (se la tua istanza utilizza l'MFA) al primo accesso.

4. **Il nuovo utente accede e sostituisce la credenziale.** Può:
   * Accedere con la password temporanea e poi cambiarla dal proprio menu profilo, oppure
   * Usare il link **I forgot my password** nella pagina di accesso per impostare direttamente una password senza usare quella temporanea. La password temporanea è comunque necessaria perché esista il record iniziale dell'account, ma l'utente non deve ricordarla se utilizza il flusso di reimpostazione della password.

5. **Il nuovo utente configura l'MFA** dal proprio menu profilo. Consigliamo vivamente di richiedere l'MFA per tutti gli utenti sulle istanze che non sono dietro SSO.

## Utenti SSO

Se la tua istanza è configurata con [SSO](../configure_sso/), il flusso di lavoro è diverso — gli utenti vengono in genere creati al primo accesso dall'Identity Provider, e devi solo concedere loro l'appartenenza a un gruppo o i ruoli in un secondo momento.

Se sei passato a DefectDojo open source (dove SSO è disponibile solo in Pro) e gli utenti SSO esistenti non riescono più ad accedere, consulta [Riattivare l'accesso per gli utenti SSO](../os__sso_user_local_login_fallback/).

## Ripristino da un token MFA perso

Se un utente perde l'accesso al proprio dispositivo MFA, consulta la [sezione sul ripristino dell'MFA](/get_started/pro/cloud/connectivity-troubleshooting/#ive-lost-access-to-my-mfa-codes) della guida alla risoluzione dei problemi di connettività. Al momento non esiste un modo per rimuovere l'MFA da un account senza un codice MFA — la soluzione alternativa è creare un nuovo account per l'utente e riconcedere gli stessi permessi.
