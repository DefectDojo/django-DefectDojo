---
title: Authorization Connectors
description: 'Visualizza tutti i provider di identità in un''unica pagina: quali sono
  configurati, quali sono abilitati e quale protocollo utilizza ciascuno'
weight: 1
audience: pro
---

Authorization Connectors è un'unica pagina che elenca tutti i provider di identità supportati da DefectDojo Pro, in quale stato si trova ciascuno e quale protocollo utilizza. Prima che esistesse, ogni provider risiedeva nel proprio modulo di impostazioni e non c'era modo di rispondere alla domanda "cosa è configurato su questa istanza?" senza aprirli tutti.

Authorization Connectors è una funzionalità di **DefectDojo Pro**. La trovi in **Connect > Authorization**. Solo un **Superuser** può visualizzare o modificare la configurazione dei provider di identità.

![Connettori di autorizzazione](images/authorization_connectors.png)

## Come è organizzata la pagina

I provider sono suddivisi in due sezioni, e ciascuna sezione è elencata in ordine alfabetico con un conteggio accanto al titolo:

* **Configured Providers** — i provider che sono stati configurati su questa istanza, che siano o meno attualmente attivi.
* **Available Providers** — i provider supportati ma non ancora configurati.

La suddivisione si basa deliberatamente su *configurato*, non su *abilitato*. Un provider che è stato configurato e poi disattivato resta in Configured Providers, perché è lì che la persona che lo ha configurato andrà a cercarlo. Il suo stato è invece indicato sulla scheda.

| | |
| --- | --- |
| **Logo and name** | Il provider, indicato senza il suo protocollo |
| **Protocol tag** | `SAML 2.0`, `OAuth 2.0`, `OpenID Connect`, o `LDAP` |
| **Status tag** | `Enabled`, `Disabled`, o `Not configured` |
| **`BETA` tag** | Presente sui provider ancora in beta |
| **Action** | **Manage Configuration** per un provider configurato, **Configure** per uno disponibile |

Entrambe le sezioni hanno una casella di ricerca che effettua la corrispondenza sul nome del provider e sul protocollo, quindi cercando `oauth` la pagina si restringe ai provider OAuth.

![Provider disponibili](images/authorization_available.png)

## Una configurazione per provider

Le impostazioni del provider di identità sono un unico insieme di valori per provider per istanza — un'applicazione Okta, un provider di identità SAML, una directory LDAP. Le schede lo indicano chiaramente, e non esiste un "aggiungine un altro": per cambiare come un provider è configurato, si modifica la configurazione già esistente.

Questo è ciò che rende Authorization Connectors diverso dalle [gallerie dei connettori](/connectors/upstream/about/), dove uno strumento può avere molte configurazioni fianco a fianco.

## I tre stati e il loro significato

| Status | Significato | Cosa fare |
| --- | --- | --- |
| **Enabled** | Configurato e accetta gli accessi | Nessuna azione |
| **Disabled** | Configurato, ma disattivato — il suo pulsante non comparirà nella pagina di accesso | Riabilitalo dalla sua configurazione quando vuoi ripristinarlo |
| **Not configured** | Supportato, ma non ancora compilato | **Configure** per impostarlo |

Selezionando un provider si apre direttamente il modulo delle sue impostazioni. Non esiste un selettore di provider intermedio.

## Provider supportati

| Provider | Protocollo | Guida alla configurazione |
| --- | --- | --- |
| Auth0 | OAuth 2.0 | [Auth0](/admin/sso/pro__auth0/) |
| GitHub Enterprise | OAuth 2.0 | [GitHub Enterprise](/admin/sso/pro__github_enterprise/) |
| GitLab | OAuth 2.0 | [GitLab](/admin/sso/pro__gitlab/) |
| Google | OAuth 2.0 | [Google](/admin/sso/pro__google/) |
| Keycloak | OAuth 2.0 | [KeyCloak](/admin/sso/pro__keycloak/) |
| LDAP | LDAP | [LDAP](/admin/sso/pro__ldap/) |
| Microsoft Entra ID | OAuth 2.0 | [Azure Active Directory](/admin/sso/pro__azure_ad/) |
| Okta | OAuth 2.0 | [Okta](/admin/sso/pro__okta/) |
| OpenID Connect | OpenID Connect | [OIDC](/admin/sso/pro__oidc/) |
| SAML | SAML 2.0 | [SAML](/admin/sso/pro__saml/) |

La pagina riporta quale sia lo *stato* della configurazione di un provider. Non restituisce mai i segreti della configurazione — client secret, password di bind e certificati non fanno parte dei dati alla base di questa pagina e non possono esserne estratti.

## Quando un provider non si connette

Authorization Connectors indica cosa è configurato; non mostra i tentativi di accesso falliti. Questi vengono registrati in [Diagnostics](/admin/diagnostics/pro__diagnostics/), dove SSO, SAML e LDAP riportano ciascuno i propri tentativi con il motivo del rifiuto — una firma dell'asserzione non valida, un bind rifiutato, un attributo non corrispondente. Queste righe sono a livello di istanza e quindi riservate ai superuser.

Mantieni almeno un account superuser con nome utente e password come soluzione di riserva, e ricorda che `/login?force_login_form` restituisce il modulo di accesso standard se un provider di identità smette di funzionare. Vedi [Single Sign-On](/admin/sso/) per entrambi.

## Correlati

* [Single Sign-On](/admin/sso/) — le guide alla configurazione per singolo provider e le impostazioni di accesso
* [Diagnostics](/admin/diagnostics/pro__diagnostics/) — perché un tentativo di accesso è fallito
* [Connectors](/connectors/upstream/about/) — la galleria upstream a cui questa pagina si ispira
