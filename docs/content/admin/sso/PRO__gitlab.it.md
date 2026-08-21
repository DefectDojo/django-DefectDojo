---
title: GitLab
description: Configura l'SSO di GitLab in DefectDojo Pro
weight: 9
audience: pro
---

DefectDojo Pro supporta l'accesso tramite GitLab. La versione open source di DefectDojo non include l'SSO — vedi [Utenti autorizzati](/admin/user_management/os__authorized_users/) per il controllo degli accessi in open source.

## Prerequisiti

Completa i seguenti passaggi in GitLab prima di configurare DefectDojo:

1. Vai alla pagina Applications del tuo profilo GitLab:
   - GitLab.com: `https://gitlab.com/profile/applications`
   - Self-hosted: `https://your-gitlab-host/profile/applications`

2. Crea una nuova applicazione:
   - **Name:** `DefectDojo`
   - **Redirect URI:** `https://your-dojo-instance.cloud.defectdojo.com/complete/gitlab/`

3. Annota l'**Application ID** e il **Secret** dell'applicazione.

## Configurazione

In DefectDojo, vai su **Enterprise Settings > OAuth Settings**, seleziona **GitLab** e compila il modulo:

- **GitLab OAuth Key** — inserisci il tuo **Application ID**
- **GitLab OAuth Secret** — inserisci il tuo **Secret**
- **GitLab API URL** — inserisci l'URL di base della tua istanza GitLab, ad es. `https://gitlab.com`

Seleziona **Enable GitLab OAuth** e invia il modulo. Un pulsante **Login With GitLab** comparirà nella pagina di accesso.
