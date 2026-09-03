---
title: Azure Active Directory
description: Configura l'SSO di Azure AD e il mapping dei gruppi in DefectDojo Pro
weight: 5
audience: pro
---

DefectDojo Pro supporta l'accesso tramite Azure Active Directory (Azure AD), inclusa la sincronizzazione automatica dei gruppi utente. La versione open source di DefectDojo non include l'SSO — vedi [Utenti autorizzati](/admin/user_management/os__authorized_users/) per il controllo degli accessi in open source.

## Prerequisiti

Completa i seguenti passaggi nel portale Azure prima di configurare DefectDojo:

1. [Registra una nuova app](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) in Azure Active Directory.

2. Annota i seguenti valori dall'app registrata:
   - **Application (client) ID**
   - **Directory (tenant) ID**
   - In **Certificates & Secrets**, crea un nuovo **Client Secret** e annotane il valore
   - **Application ID URI**

3. In **Authentication > Redirect URIs**, aggiungi un URI di tipo **Web**:
   `https://your-instance.cloud.defectdojo.com/complete/azuread-tenant-oauth2/`

## Configurazione

In DefectDojo, vai su **Enterprise Settings > OAuth Settings**, seleziona **Azure AD** e compila il modulo:

- **Azure AD OAuth Key** — inserisci il tuo **Application (client) ID**
- **Azure AD OAuth Secret** — inserisci il tuo **Client Secret**
- **Azure AD Resource** — per impostazione predefinita è `https://graph.microsoft.com/`. È l'URI che DefectDojo utilizza per leggere informazioni aggiuntive (come i nomi dei gruppi) dalla [Microsoft Graph Web API](https://docs.azure.cn/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-id-uri). Modificalo solo se i nomi dei tuoi gruppi sono memorizzati su una risorsa API diversa.
- **Azure AD Tenant ID** — inserisci il tuo **Directory (tenant) ID**
- **Azure AD Groups Filter** — inserisci facoltativamente una stringa regex per limitare quali Gruppi utente vengono importati (vedi [Mapping dei gruppi](#group-mapping) più sotto)

Seleziona **Enable Azure AD OAuth** e invia il modulo. Un pulsante **Login With Azure AD** comparirà nella pagina di accesso.

## Mapping dei gruppi

Il mapping dei gruppi consente a DefectDojo di importare l'appartenenza ai [Gruppi utente](../../user_management/create_user_group/) da Azure AD. I Gruppi utente in DefectDojo regolano l'accesso a prodotti e tipi di prodotto tramite [RBAC](../../user_management/set_user_permissions/).

Seleziona **Enable Azure AD OAuth Grouping** per attivare questa funzionalità. All'accesso, DefectDojo farà corrispondere i gruppi Azure AD dell'utente ai gruppi DefectDojo esistenti. Eventuali gruppi non trovati in DefectDojo verranno creati automaticamente.

Per importare solo un sottoinsieme di gruppi, inserisci una regex nel campo **Azure AD Groups Filter**. Ad esempio:
- `^team-.*` — corrisponde a qualsiasi gruppo che inizia con `team-`
- `teamA|teamB|groupC` — corrisponde a gruppi specifici con nome

### Configurare Azure AD per inviare i gruppi

Il token di Azure AD deve essere configurato per includere gli ID dei gruppi. Senza questo, nel token non sarà presente alcuna informazione sui gruppi.

Per configurarlo:
1. Aggiungi un [Group Claim](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims) nella configurazione del token di Azure AD. Se non sei sicuro di quale tipo di gruppo selezionare, scegli **All Groups**.
2. **Non** abilitare **Emit groups as role claims**.
3. Aggiorna le autorizzazioni API dell'applicazione includendo `GroupMember.Read.All` o `Group.Read.All`. `GroupMember.Read.All` è consigliato perché concede meno permessi.

### Pulizia dei gruppi

Se **Enable Azure AD OAuth Group Cleaning** è abilitato, i gruppi DefectDojo creati tramite la sincronizzazione con Azure AD verranno rimossi automaticamente quando non hanno più membri. Quando un utente viene rimosso da un gruppo in Azure AD, viene rimosso anche dal gruppo corrispondente in DefectDojo.
