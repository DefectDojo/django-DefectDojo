---
title: Single Sign-On
description: DefectDojo Pro supporta SAML e una vasta gamma di provider OAuth per
  il Single Sign-On
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2026-04-30 00:00:00+00:00
draft: false
weight: 8
collapsed: true
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
pro-feature: true
aliases:
- /it/admin/user_management/configure_sso/
- /it/admin/sso/os__saml/
- /it/admin/sso/os__auth0/
- /it/admin/sso/os__azure_ad/
- /it/admin/sso/os__github_enterprise/
- /it/admin/sso/os__gitlab/
- /it/admin/sso/os__google/
- /it/admin/sso/os__keycloak/
- /it/admin/sso/os__oidc/
- /it/admin/sso/os__okta/
- /it/admin/sso/os__remote_user/
---

Il Single Sign-On è una funzionalità di **DefectDojo Pro**. A partire da DefectDojo 3.0, l'intera superficie SSO — SAML, OIDC e i provider OAuth inclusi — è disponibile solo in DefectDojo Pro. DefectDojo open source utilizza l'accesso locale con username/password e il flusso di reimpostazione della password.

Se utilizzi DefectDojo open source e desideri il SSO, dovrai passare a [DefectDojo Pro](https://defectdojo.com); la migrazione è descritta nelle [note di aggiornamento della 3.0](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only). Gli account utente e le appartenenze ai gruppi esistenti vengono preservati durante l'aggiornamento. Per il controllo degli accessi su DefectDojo open source, consulta la pagina [Utenti autorizzati](/admin/user_management/os__authorized_users/).

## Visualizzare cosa è configurato

**[Authorization Connectors](/admin/sso/pro__authorization_connectors/)** elenca in un'unica pagina tutti i provider supportati — quali sono configurati, quali sono abilitati e quale protocollo utilizza ciascuno — e ti porta direttamente al modulo di impostazioni di ognuno di essi. Parti da lì se vuoi conoscere lo stato di questa istanza piuttosto che configurare un provider specifico.

## Provider SSO supportati (DefectDojo Pro)

DefectDojo Pro supporta SAML e i seguenti provider OAuth. Ogni guida illustra la configurazione lato provider e la corrispondente configurazione nell'interfaccia **Enterprise Settings** di Pro.

* **[Auth0](/admin/sso/pro__auth0/)**
* **[Azure Active Directory](/admin/sso/pro__azure_ad/)**
* **[GitHub Enterprise](/admin/sso/pro__github_enterprise/)**
* **[GitLab](/admin/sso/pro__gitlab/)**
* **[Google](/admin/sso/pro__google/)**
* **[KeyCloak](/admin/sso/pro__keycloak/)**
* **[Okta](/admin/sso/pro__okta/)**
* **[OIDC (OpenID Connect)](/admin/sso/pro__oidc/)**
* **[SAML](/admin/sso/pro__saml/)**
* **[LDAP](/admin/sso/pro__ldap/)**

## Provisioning degli utenti dalla tua directory (DefectDojo Pro)

I provider sopra indicati decidono chi può accedere. **[SCIM Provisioning](/admin/sso/pro__scim/)** mantiene l'elenco degli account allineato alla tua directory, così gli utenti vengono creati quando entrano a far parte dell'organizzazione, aggiornati quando cambiano i loro dati e disattivati (insieme ai loro token API) quando la lasciano.

La configurazione del SSO in DefectDojo Pro può essere eseguita solo da un **Superuser**.

**Utenti DefectDojo Pro:** aggiungi gli indirizzi IP dei tuoi servizi SAML o SSO alla whitelist del Firewall prima di configurare il SSO. Consulta [Regole del firewall](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings) per maggiori informazioni.

## Disabilitare l'accesso con Username / Password

Una volta configurato il SSO in DefectDojo Pro, potresti voler disabilitare il tradizionale modulo di accesso con username/password. Deseleziona **Allow Login via Username and Password** in **Enterprise Settings > Login Settings**.

![image](images/pro_login_settings.png)

### Accesso di riserva

Se la tua integrazione SSO smette di funzionare, puoi sempre tornare al modulo di accesso standard aggiungendo quanto segue al tuo URL di DefectDojo:

`/login?force_login_form`

Ti consigliamo di mantenere almeno un account amministratore con username e password configurati come riserva.
