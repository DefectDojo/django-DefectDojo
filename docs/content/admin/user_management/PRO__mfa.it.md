---
title: Autenticazione a più fattori (MFA)
description: Configura l'MFA sul tuo account, rendila obbligatoria in tutta l'istanza
  e recupera un utente che ha perso il proprio dispositivo
audience: pro
weight: 3
---

L'autenticazione a più fattori aggiunge un secondo passaggio all'accesso: dopo la password, DefectDojo richiede un codice a sei cifre generato da un'app di autenticazione. Consigliamo vivamente di richiederla per tutti gli utenti sulle istanze non protette da SSO.

L'MFA di DefectDojo Pro utilizza un'**app di autenticazione TOTP**: Google Authenticator, 1Password, Authy o qualsiasi altra app in grado di scansionare un codice QR standard. Non è prevista alcuna opzione via email o SMS.

## Configurare l'MFA sul tuo account

1. Vai su **Connect \> Authorization \> MFA Settings**.
2. In **Personal Multi-Factor Authentication Settings**, fai clic su **Set Up MFA**.
3. Scansiona il codice QR con la tua app di autenticazione. Se non riesci a scansionarlo, la schermata di configurazione mostra anche la chiave in formato testo, che puoi digitare manualmente nella tua app.
4. Inserisci il codice a sei cifre mostrato dalla tua app e fai clic su **Verify & enable**.
5. DefectDojo mostra i tuoi **codici di recupero**. Salvali in un posto sicuro prima di continuare, vedi sotto. Fai clic su **Copy codes**, conservali, quindi fai clic su **I've saved them. Continue**.

Da quel momento l'MFA è attiva. Al prossimo accesso, DefectDojo richiederà un codice dopo la password.

### Codici di recupero

Quando abiliti l'MFA ti vengono forniti **dieci codici di recupero monouso**. Ognuno può essere usato una sola volta, al posto di un codice dell'app di autenticazione, e viene consumato all'uso.

Vengono mostrati **una sola volta**, nella schermata finale della configurazione. In seguito, la pagina MFA Settings mostra solo quanti te ne restano, non i codici stessi.

Se perdi i codici di recupero, o ne vuoi un nuovo set dopo averne usati diversi, fai clic su **Regenerate Recovery Codes** nella pagina MFA Settings. Questo **sostituisce tutti i codici esistenti**: quelli salvati in precedenza smettono di funzionare immediatamente, quindi salva subito il nuovo set.

I codici di recupero sono ciò che ti permette di rientrare quando perdi il telefono, quindi conservali in un posto separato dal dispositivo su cui gira la tua app di autenticazione.

### Disattivare l'MFA

**Disable MFA** nella pagina MFA Settings la disattiva per il tuo account. Devi solo essere connesso: non ti verrà chiesto un codice per confermare.

Se il tuo amministratore ha reso l'MFA obbligatoria, ti verrà chiesto di configurarla di nuovo al prossimo accesso.

## Accedere con l'MFA

Dopo aver inserito nome utente e password, DefectDojo richiede il tuo codice a sei cifre. Se non hai la tua app di autenticazione, inserisci invece uno dei tuoi **codici di recupero** nello stesso campo: quel codice verrà quindi consumato.

## Richiedere l'MFA per tutti

I superuser possono rendere l'MFA obbligatoria su tutta l'istanza:

1. Vai su **Connect \> Authorization \> MFA Settings**.
2. Nella scheda **MFA Settings** (visibile solo ai Superuser), seleziona **Require Multi-Factor Authentication Globally**.
3. Invia.

Questa opzione è **disattivata per impostazione predefinita**.

Una volta attivata, qualsiasi utente che non si è ancora registrato viene inviato alla schermata di configurazione dell'MFA al prossimo accesso e **non può saltarla**. Completa la registrazione, salva i codici di recupero e arriva alla destinazione originariamente prevista.

### Utenti SSO

L'MFA è applicata da DefectDojo, non delegata al tuo identity provider. Con l'MFA globale obbligatoria, anche gli utenti che accedono tramite SSO vengono inviati a configurare l'MFA dopo che il loro provider li restituisce a DefectDojo, e viene richiesto loro un codice negli accessi successivi.

Non esiste un'impostazione per esentare gli utenti SSO. Se il tuo identity provider applica già una propria MFA, valuta consapevolmente se vuoi entrambe: attivare l'MFA globale significherà due richieste per gli utenti SSO.

## Recuperare un utente che ha perso il proprio dispositivo MFA

Procedi in quest'ordine:

1. **Usa un codice di recupero.** Se l'utente ha ancora i codici di recupero, ne inserisce uno al posto di un codice dell'app in fase di accesso, poi configura di nuovo l'MFA da zero.
2. **Se è ancora connesso da qualche parte,** può andare su **MFA Settings** e fare clic su **Disable MFA** senza bisogno di un codice, quindi registrarsi di nuovo.
3. **Chiedi a un amministratore di rimuovere la sua MFA.** Con accesso al server, un amministratore può rimuovere l'MFA da un account:

   ```
   python manage.py remove_mfa --username <username>
   ```

   Il comando accetta anche `--user-id` o `--email` al posto di `--username` (ne è richiesto esattamente uno; `--email` non distingue tra maiuscole e minuscole). Chiede conferma prima di applicare la modifica. L'utente può quindi accedere con la sola password e registrarsi di nuovo.

   Si tratta di un comando shell, quindi richiede accesso al container o all'host di DefectDojo. Non esiste un pulsante equivalente nell'interfaccia né un endpoint nell'API. Su **DefectDojo Cloud**, contatta [DefectDojo Support](mailto:support@defectdojo.com) per farlo eseguire.

Creare un account sostitutivo **non** è necessario: rimuovere l'MFA preserva le autorizzazioni, la cronologia e le assegnazioni esistenti dell'utente.

## MFA e l'API

Quando un utente ha l'MFA abilitata, le richieste a `/api/v2/api-token-auth/` (l'endpoint che scambia un nome utente e una password con un token API) devono includere anche un codice MFA, in un campo `mfa_code` accanto alle credenziali. È accettato sia un codice TOTP corrente sia un codice di recupero non utilizzato; passare qui un codice di recupero lo **consuma**.

Un codice mancante o errato restituisce lo stesso errore generico *"Unable to log in with provided credentials"* di una password errata, quindi se le richieste di token iniziano a fallire dopo che un utente ha abilitato l'MFA, questa è la prima cosa da controllare.

**I token API esistenti continuano a funzionare.** Abilitare o disabilitare l'MFA non revoca né ruota i token già emessi: il controllo MFA si applica al momento dell'emissione di un token, non a ogni richiesta effettuata con esso. Le automazioni di lunga durata che già possiedono un token non sono influenzate dalla registrazione di un utente all'MFA.
