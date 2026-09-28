---
title: Okta
description: Configura il Single Sign-On Okta in DefectDojo Pro
weight: 15
audience: pro
---

DefectDojo Pro supporta l'accesso tramite Okta. DefectDojo open source non include il SSO — consulta [Utenti autorizzati](/admin/user_management/os__authorized_users/) per il controllo degli accessi in open source.

## Prerequisiti

Completa i seguenti passaggi in Okta prima di configurare DefectDojo:

1. Accedi o crea un account su [Okta](https://www.okta.com/developer/signup/).

2. Vai su **Applications** e fai clic su **Add Application**.

   ![image](images/okta_1.png)

3. Seleziona **Web Applications**.

   ![image](images/okta_2.png)

4. In **Login Redirect URLs**, aggiungi l'URL di callback di DefectDojo. Seleziona anche la casella **Implicit**.

   ![image](images/okta_3.png)

5. Fai clic su **Done**.

6. Dalla **Dashboard**, annota l'**Org-URL**.

   ![image](images/okta_4.png)

7. Apri l'applicazione appena creata e annota il **Client ID** e il **Client Secret**.

   ![image](images/okta_5.png)

## Configurazione

In DefectDojo, vai su **Enterprise Settings > OAuth Settings**, seleziona **Okta** e compila il modulo:

- **Okta OAuth Key** — inserisci il tuo **Client ID**
- **Okta OAuth Secret** — inserisci il tuo **Client Secret**
- **Okta Tenant ID** — inserisci il tuo Org-URL nel formato `https://your-org-url/oauth2`

Seleziona **Enable Okta OAuth** e invia il modulo. Nella pagina di accesso apparirà un pulsante **Login With Okta**.
