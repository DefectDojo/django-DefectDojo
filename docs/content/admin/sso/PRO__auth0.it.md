---
title: Auth0
description: Configura l'SSO Auth0 in DefectDojo Pro
weight: 3
audience: pro
---

DefectDojo Pro supporta l'accesso tramite Auth0. La versione open source di DefectDojo non include l'SSO — vedi [Utenti autorizzati](/admin/user_management/os__authorized_users/) per il controllo degli accessi in open source.

## Prerequisiti

Completa i seguenti passaggi nella dashboard di Auth0 prima di configurare DefectDojo:

1. Crea una nuova applicazione: **Applications > Create Application > Single Page Web Application**.

2. Configura l'applicazione:
   - **Name:** `DefectDojo`
   - **Allowed Callback URLs:** `https://your-instance.cloud.defectdojo.com/complete/auth0/`

3. Annota i seguenti valori — ti serviranno in DefectDojo:
   - **Domain**
   - **Client ID**
   - **Client Secret**

## Configurazione

In DefectDojo, vai su **Enterprise Settings > OAuth Settings**, seleziona **Auth0** e compila il modulo:

- **Auth0 OAuth Key** — inserisci il tuo **Client ID**
- **Auth0 OAuth Secret** — inserisci il tuo **Client Secret**
- **Auth0 Domain** — inserisci il tuo **Domain**

Seleziona **Enable Auth0 OAuth** per aggiungere un pulsante **Login With Auth0** alla pagina di accesso di DefectDojo.
