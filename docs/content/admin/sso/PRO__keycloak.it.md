---
title: KeyCloak
description: Configura l'SSO di KeyCloak in DefectDojo Pro
weight: 13
audience: pro
---

DefectDojo Pro supporta l'accesso tramite KeyCloak. La versione open source di DefectDojo non include l'SSO — vedi [Utenti autorizzati](/admin/user_management/os__authorized_users/) per il controllo degli accessi in open source.

Questa guida presuppone che tu abbia già configurato un Realm KeyCloak. In caso contrario, consulta la [documentazione di KeyCloak](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/realms/create.html).

## Prerequisiti

Completa i seguenti passaggi nel tuo realm KeyCloak prima di configurare DefectDojo:

1. Aggiungi un nuovo client di tipo `openid-connect`. Annota il client ID.

2. Nelle impostazioni del client:
   - Imposta **Access Type** su `confidential`
   - In **Valid Redirect URIs**, aggiungi il tuo URL DefectDojo, ad es. `https://yourorganization.cloud.defectdojo.com` oppure `https://your-dojo-host/*`
   - In **Web Origins**, aggiungi lo stesso URL (oppure `+`)
   - In **Fine Grained OpenID Connect Configuration**:
     - Imposta **User Info Signed Response Algorithm** su `RS256`
     - Imposta **Request Object Signature Algorithm** su `RS256`
   - Salva le impostazioni.

3. In **Scope**, imposta **Full Scope Allowed** su `off`.

4. In **Mappers**, aggiungi un mapper personalizzato:
   - **Name:** `aud`
   - **Mapper Type:** `audience`
   - **Included Audience:** seleziona il tuo client ID
   - **Add ID to Token:** `off`
   - **Add Access to Token:** `on`

5. In **Credentials**, copia il **Secret**.

6. In **Realm Settings > Keys**, copia la **Public Key** (chiave di firma).

7. In **Realm Settings > General > Endpoints**, apri la configurazione dell'endpoint OpenID e copia gli URL degli endpoint **Authorization** e **Token**.

## Configurazione

In DefectDojo, vai su **Enterprise Settings > OAuth Settings**, seleziona **KeyCloak** e compila il modulo:

- **KeyCloak OAuth Key** — inserisci il nome del tuo client (dal passaggio 1)
- **KeyCloak OAuth Secret** — inserisci il secret delle credenziali del client (dal passaggio 5)
- **KeyCloak Public Key** — inserisci la Public Key dalle impostazioni del tuo realm (dal passaggio 6)
- **KeyCloak Resource** — inserisci l'URL dell'Authorization Endpoint (dal passaggio 7)
- **KeyCloak Group Limiter** — inserisci l'URL del Token Endpoint (dal passaggio 7)
- **KeyCloak OAuth Login Button Text** — scegli il testo per il pulsante di accesso di DefectDojo

Seleziona **Enable KeyCloak OAuth** e invia il modulo. Nella pagina di accesso comparirà un pulsante di login con il testo che hai configurato.
