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

2. **Concedi l'accesso** come opportuno. Aggiungi l'utente all'elenco Authorized Users di ogni Asset o Organizzazione di cui ha bisogno, oppure contrassegnalo come staff o superuser. Per i dettagli, vedi [Permessi Open Source](../os__authorized_users/). Un nuovo utente senza alcuna assegnazione non potrà vedere nessun Asset o Riscontro.

3. **Invia le credenziali al nuovo utente fuori banda** (via email, lo strumento di chat del tuo team, o comunque tu condivida normalmente i segreti). Includi:
   * L'URL dell'istanza DefectDojo.
   * Il nome utente (in genere il loro indirizzo email).
   * La password temporanea appena impostata.
   * Una nota che li invita a cambiare la password al primo accesso.

4. **Il nuovo utente accede e sostituisce la credenziale.** Può:
   * Accedere con la password temporanea e poi cambiarla dal proprio menu profilo, oppure
   * Usare il link **I forgot my password** nella pagina di accesso per impostare direttamente una password senza usare quella temporanea. La password temporanea è comunque necessaria perché esista il record iniziale dell'account, ma l'utente non deve ricordarla se utilizza il flusso di reimpostazione della password.

## Utenti che hanno effettuato l'accesso con SSO

DefectDojo open source supporta solo account locali. SSO (SAML, OIDC, OAuth), LDAP e MFA sono disponibili in [DefectDojo Pro](/admin/sso/).

Se sei passato a DefectDojo open source 3.x e gli utenti SSO esistenti non riescono più ad accedere, consulta [Riattivare l'accesso per gli utenti SSO](../os__sso_user_local_login_fallback/).
