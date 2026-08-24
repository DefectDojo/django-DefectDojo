---
title: Google Auth
description: Configura l'OAuth di Google in DefectDojo Pro
weight: 11
audience: pro
---

DefectDojo Pro supporta l'accesso tramite account Google. I nuovi utenti vengono creati automaticamente al primo accesso se non esistono già. Gli utenti DefectDojo esistenti vengono associati agli account Google in base al nome utente (la parte prima della `@` nella loro email Google). La versione open source di DefectDojo non include l'SSO — vedi [Utenti autorizzati](/admin/user_management/os__authorized_users/) per il controllo degli accessi in open source.

## Prerequisiti

Completa i seguenti passaggi nella Google Cloud Console prima di configurare DefectDojo:

1. Accedi alla [Google Developers Console](https://console.developers.google.com).

2. Vai su **Credentials > Create Credentials > OAuth Client ID**.

   ![immagine](images/google_1.png)

3. Seleziona **Web Application** e assegna un nome descrittivo (ad es. `DefectDojo`).

4. In **Authorized Redirect URIs**, aggiungi:
   `https://your-instance.cloud.defectdojo.com/complete/google-oauth2/`

5. Annota il **Client ID** e la **Client Secret Key**.

## Configurazione

In DefectDojo, vai su **Enterprise Settings > OAuth Settings**, seleziona **Google** e compila il modulo:

- **Google OAuth Key** — inserisci il tuo **Client ID**
- **Google OAuth Secret** — inserisci la tua **Client Secret Key**
- **Whitelisted Domains** — inserisci il dominio della tua organizzazione (ad es. `yourcompany.com`) per consentire l'accesso a qualsiasi utente con quel dominio
- **Whitelisted E-mail Addresses** — in alternativa, inserisci indirizzi email specifici da consentire (ad es. `user1@yourcompany.com, user2@yourcompany.com`)

Devi impostare almeno un dominio o indirizzo email in whitelist, altrimenti nessun utente potrà accedere tramite Google.

Seleziona **Enable Google OAuth** e invia il modulo. Un pulsante **Login With Google** comparirà nella pagina di accesso.
