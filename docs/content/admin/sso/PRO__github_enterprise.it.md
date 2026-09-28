---
title: GitHub Enterprise
description: Configura l'SSO di GitHub Enterprise in DefectDojo Pro
weight: 7
audience: pro
---

DefectDojo Pro supporta l'accesso tramite GitHub Enterprise. La versione open source di DefectDojo non include l'SSO — vedi [Utenti autorizzati](/admin/user_management/os__authorized_users/) per il controllo degli accessi in open source.

## Prerequisiti

Completa i seguenti passaggi in GitHub Enterprise prima di configurare DefectDojo:

1. [Crea una nuova OAuth App](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app) nel tuo GitHub Enterprise Server.

2. Scegli un nome per l'applicazione, ad es. `DefectDojo`.

3. Imposta il **Redirect URI**:
   `https://your-instance.cloud.defectdojo.com/complete/github-enterprise/`

4. Annota il **Client ID** e il **Client Secret** dall'app.

## Configurazione

In DefectDojo, vai su **Enterprise Settings > OAuth Settings**, seleziona **GitHub Enterprise** e compila il modulo:

- **GitHub Enterprise OAuth Key** — inserisci il tuo **Client ID**
- **GitHub Enterprise OAuth Secret** — inserisci il tuo **Client Secret**
- **GitHub Enterprise URL** — inserisci l'URL GitHub della tua organizzazione, ad es. `https://github.yourcompany.com/`
- **GitHub Enterprise API URL** — inserisci l'URL API GitHub della tua organizzazione, ad es. `https://github.yourcompany.com/api/v3/`

Seleziona **Enable GitHub Enterprise OAuth** e invia il modulo. Un pulsante **Login With GitHub** comparirà nella pagina di accesso.
