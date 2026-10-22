---
title: Autenticazione LDAP
description: Configura l'autenticazione LDAP in DefectDojo Pro
weight: 20
audience: pro
aliases:
- /it/en/open_source/ldap-authentication
---

DefectDojo Pro supporta l'autenticazione LDAP dall'interfaccia **Enterprise Settings** — non sono necessarie immagini Docker
personalizzate né file di configurazione.

A differenza degli altri provider di questa pagina, LDAP non è un flusso basato su redirect. Gli utenti accedono
con il modulo standard di nome utente e password di DefectDojo, e le loro credenziali vengono verificate rispetto
alla tua directory. Non c'è alcun pulsante di accesso aggiuntivo.

## Configurazione

Apri **Enterprise Settings > LDAP Settings**.

![immagine](images/sso_ldap_settings.png)

1. **Server URI** — la directory a cui connettersi, ad es. `ldaps://ldap.example.com:636`.
   Preferisci `ldaps://`. Se devi usare `ldap://` semplice, abilita **Use StartTLS** più sotto in modo che la
   connessione venga aggiornata prima dell'invio delle credenziali.
2. **Bind DN** — il distinguished name dell'account di servizio usato per cercare gli utenti.
   Lascia vuoto per un bind anonimo.
3. **Bind Password** — la password per quell'account di servizio. Il valore memorizzato non viene mai
   restituito al browser; lascia il campo vuoto per mantenere la password già salvata.
4. **User Search Base** — il DN sotto cui cercare le voci utente, ad es.
   `ou=people,dc=example,dc=com`.
5. **User Search Filter** — il filtro usato per individuare l'utente. **Deve** contenere il
   segnaposto letterale `%(user)s`, che viene sostituito con il nome utente inviato. Valori comuni
   sono `(uid=%(user)s)` per OpenLDAP e `(sAMAccountName=%(user)s)` per Active
   Directory.
6. **User Attribute Mapping** — vedi sotto.
7. Seleziona **Enable LDAP** per attivarlo.

Usa **Validate Config** per verificare le impostazioni senza salvarle. Riporta la completezza delle impostazioni,
se il server è raggiungibile, se il bind ha successo, se le basi di ricerca si risolvono e se il mapping degli
attributi sembra utilizzabile.

## User Attribute Mapping

Ogni riga associa un **LDAP Attribute** al **DefectDojo Field** che deve popolare. Usa
**Add Attribute Mapping** per righe aggiuntive e l'icona del cestino per rimuoverne una.

![immagine](images/sso_ldap_attribute_mapping.png)

- **LDAP Attribute** è testo libero e deve corrispondere all'attributo effettivamente
  restituito dalla tua directory — ad esempio `uid`, `givenName`, `sn`, `mail` su OpenLDAP, oppure
  `sAMAccountName`, `givenName`, `sn`, `mail` su Active Directory.
- **DefectDojo Field** viene scelto da un elenco: **Username**, **First Name**, **Last Name** e
  **Email**.
- È fortemente consigliato mappare un attributo su **Email**: DefectDojo usa l'indirizzo
  email per le notifiche.
- Lo stesso attributo può alimentare più di un campo. Ogni campo DefectDojo può essere
  mappato da un solo attributo.
- Senza alcun mapping, gli account vengono creati senza nome o indirizzo email.

**Always Update User** controlla quando viene applicato il mapping. Se abilitato (impostazione predefinita), gli
attributi mappati vengono aggiornati dalla directory a ogni accesso, così una modifica di nome o email
in LDAP raggiunge DefectDojo. Se disabilitato, vengono applicati solo alla prima
creazione dell'account.

## Mapping dei gruppi

DefectDojo può replicare i gruppi LDAP di un utente nei gruppi DefectDojo all'accesso. Seleziona **Enable
Group Mapping** per visualizzare le impostazioni.

![immagine](images/sso_ldap_group_mapping.png)

- **Group Search Base** — il DN sotto cui cercare le voci di gruppo, ad es.
  `ou=groups,dc=example,dc=com`. Obbligatorio quando il mapping dei gruppi è abilitato.
- **Group Type** — come la tua directory modella l'appartenenza. Scegli **groupOfNames** per
  OpenLDAP e Active Directory, **groupOfUniqueNames**, oppure **posixGroup**.
- **Group Limiter Regex Expression** — vengono replicati solo i gruppi il cui nome corrisponde a questa
  espressione. Usa `.*` per consentirli tutti, oppure un prefisso come `^dd-` per replicare solo i gruppi che
  intendi far gestire a DefectDojo.

I gruppi vengono creati al primo utilizzo se non esistono già. Un gruppo appena creato non ha
permessi finché un Superuser non li configura — vedi
[Gruppi utente](../../user_management/create_user_group/).

## Opzioni aggiuntive

* **Use StartTLS** — aggiorna a TLS una connessione `ldap://` semplice prima del bind. Non è necessario
  quando l'URI è già `ldaps://`.
* **Always Update User** — aggiorna gli attributi mappati dalla directory a ogni accesso.

## Risoluzione dei problemi

Esegui prima **Validate Config** — di solito indica direttamente il problema. Oltre a questo:

**Ogni accesso fallisce, ma la directory è raggiungibile.** Controlla che **User Search Filter**
contenga `%(user)s` e che l'attributo al suo interno corrisponda a quanto digitano effettivamente gli utenti. Un
filtro del tipo `(uid=%(user)s)` non corrisponderà mai se i tuoi utenti accedono con uno
`sAMAccountName` di Active Directory.

**Gli accessi hanno successo ma gli account non hanno nome o email.** **User Attribute Mapping** è
vuoto, oppure i nomi degli attributi LDAP a sinistra non corrispondono a quanto restituisce la tua directory.

**Un nome è cambiato in LDAP ma non in DefectDojo.** **Always Update User** è disabilitato, quindi il
mapping è stato applicato solo alla creazione dell'account.

**I tentativi di accesso si bloccano o sono lenti.** Connessioni e ricerche sono limitate da un timeout, quindi
una directory irraggiungibile fallisce anziché bloccarsi indefinitamente. Controlla **Server Reachability**
in **Validate Config** e verifica che la porta sia aperta dall'host DefectDojo.
