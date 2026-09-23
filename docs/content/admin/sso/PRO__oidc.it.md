---
title: OIDC
description: Configura il Single Sign-On OpenID Connect (OIDC) in DefectDojo Pro
weight: 17
audience: pro
---

DefectDojo Pro supporta l'accesso tramite un provider OpenID Connect (OIDC) generico. DefectDojo open source non include il SSO — consulta [Utenti autorizzati](/admin/user_management/os__authorized_users/) per il controllo degli accessi in open source.

## Configurazione

In DefectDojo, vai su **Enterprise Settings > OIDC Settings**.

![image](images/oidc_pro.png)

Compila il modulo:

1. **Endpoint** — l'URL di base del tuo provider OIDC. Non includere `/.well-known/openid-configuration`.
2. **Client ID** — il tuo client ID OIDC.
3. **Client Secret** — il tuo client secret OIDC.
4. Facoltativamente configura **Claim Mapping** e **Group Mapping** — vedi sotto.
5. Seleziona **Enable OIDC**.

Invia il modulo. Nella pagina di accesso di DefectDojo apparirà un pulsante **Log In With OIDC**.

Usa **Validate Config** in qualsiasi momento per verificare le impostazioni senza salvarle. Questa funzione recupera il documento di discovery, verifica le chiavi di firma e l'issuer, restituisce l'esatto redirect URI da registrare presso il tuo provider e confronta le tue mappature di claim e gruppi con i claim pubblicizzati dal provider.

## Claim Mapping

Ogni riga associa una **OIDC Claim** al **DefectDojo Field** che deve popolare. Usa **Add Claim Mapping** per aggiungere altre righe e l'icona del cestino per rimuoverne una.

![image](images/sso_oidc_claim_mapping.png)

Un campo senza una riga corrispondente mantiene il proprio claim standard, quindi questa sezione è necessaria solo se il tuo provider utilizza nomi diversi. I claim standard sono:

| DefectDojo Field | Claim standard |
| --- | --- |
| Username | `preferred_username` |
| Email | `email` |
| First Name | `given_name` |
| Last Name | `family_name` |

Note:

- Un'istanza non configurata si apre con queste quattro righe già compilate, così puoi vedere cosa fa OIDC prima di modificare qualsiasi cosa.
- Lo stesso claim può alimentare più di un campo. Ogni campo di DefectDojo può invece essere mappato da un solo claim.
- I claim vengono letti sia dall'ID token sia dalla risposta userinfo, quindi un claim che il tuo provider rilascia solo in uno dei due funziona comunque.
- Se per un determinato utente un claim mappato è mancante o vuoto, il campo mantiene il proprio valore standard invece di essere svuotato.

## Group Mapping

DefectDojo può replicare nei propri gruppi quelli segnalati dal tuo provider a ogni accesso. Seleziona **Enable Group Mapping** per visualizzare le impostazioni.

![image](images/sso_oidc_group_mapping.png)

- **Group Claim Name** — il claim che contiene i gruppi dell'utente. **La maggior parte dei provider non lo emette per impostazione predefinita** e richiede la configurazione esplicita di un mapper; in Keycloak, ad esempio, aggiungi un mapper *Group Membership* al client. Nota che un mapper *User Realm Role* invia i **ruoli** del realm, non i gruppi.
- **Group Limiter Regex Expression** — vengono replicati solo i gruppi che corrispondono a questa espressione. Usa `.*` per consentirli tutti.
- **Remove Stale Group Memberships** — se abilitata, le appartenenze a gruppi creati tramite OIDC che il provider non segnala più vengono rimosse al successivo accesso. Sono interessati solo i gruppi creati da OIDC; i gruppi assegnati manualmente e quelli forniti da un altro provider, come SAML, non vengono mai toccati.

I gruppi vengono creati al primo utilizzo e denominati esattamente come li segnala il provider. Se il tuo provider invia i percorsi completi dei gruppi (il mapper *Group Membership* di Keycloak lo fa quando è abilitata l'opzione **Full group path**), il gruppo in DefectDojo viene denominato `/Group A` anziché `Group A`. Disattiva questa opzione se vuoi che i nomi corrispondano ai gruppi provenienti da un altro provider, altrimenti finirai per avere due gruppi DefectDojo per lo stesso gruppo logico.

Se il mapping dei gruppi sembra non avere alcun effetto, esegui **Validate Config**: questa funzione indica se il claim che hai indicato è tra quelli pubblicizzati dal provider.
