---
title: Azure Active Directory
description: Configure o SSO do Azure AD e o mapeamento de grupos no DefectDojo Pro
weight: 5
audience: pro
---

O DefectDojo Pro oferece suporte a login via Azure Active Directory (Azure AD), incluindo sincronização
automática de User Group. O DefectDojo open-source não inclui SSO — consulte
[Usuários Autorizados](/admin/user_management/os__authorized_users/) para controle de acesso no open-source.

## Pré-requisitos

Conclua as etapas a seguir no portal do Azure antes de configurar o DefectDojo:

1. [Registre uma nova aplicação](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
   no Azure Active Directory.

2. Anote os seguintes valores da aplicação registrada:
   - **Application (client) ID**
   - **Directory (tenant) ID**
   - Em **Certificates & Secrets**, crie um novo **Client Secret** e anote o valor
   - **Application ID URI**

3. Em **Authentication > Redirect URIs**, adicione uma URI do tipo **Web**:
   `https://your-instance.cloud.defectdojo.com/complete/azuread-tenant-oauth2/`

## Configuração

No DefectDojo, acesse **Enterprise Settings > OAuth Settings**, selecione **Azure AD** e preencha o
formulário:

- **Azure AD OAuth Key** — insira seu **Application (client) ID**
- **Azure AD OAuth Secret** — insira seu **Client Secret**
- **Azure AD Resource** — o padrão é `https://graph.microsoft.com/`. Esta é a URI que o DefectDojo usa para
  ler informações adicionais (como nomes de grupos) da
  [Microsoft Graph Web API](https://docs.azure.cn/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-id-uri).
  Altere isso apenas se os nomes dos seus grupos estiverem armazenados em outro recurso de API.
- **Azure AD Tenant ID** — insira seu **Directory (tenant) ID**
- **Azure AD Groups Filter** — opcionalmente, insira uma expressão regular para restringir quais User
  Groups são importados (veja [Group Mapping](#group-mapping) abaixo)

Marque **Enable Azure AD OAuth** e envie o formulário. Um botão **Login With Azure AD** aparecerá na página
de login.

## Group Mapping

O group mapping permite que o DefectDojo importe a associação a
[User Group](../../user_management/create_user_group/) do Azure AD. Os User Groups no DefectDojo controlam
o acesso a produtos e tipos de produto por meio do [RBAC](../../user_management/set_user_permissions/).

Marque **Enable Azure AD OAuth Grouping** para ativar este recurso. No login, o DefectDojo vai corresponder
os grupos do Azure AD do usuário aos grupos já existentes no DefectDojo. Quaisquer grupos não encontrados no
DefectDojo serão criados automaticamente.

Para importar apenas um subconjunto de grupos, insira uma expressão regular no campo **Azure AD Groups
Filter**. Por exemplo:
- `^team-.*` — corresponde a qualquer grupo que comece com `team-`
- `teamA|teamB|groupC` — corresponde a grupos específicos nomeados

### Configurando o Azure AD para enviar grupos

O token do Azure AD deve ser configurado para incluir IDs de grupo. Sem isso, nenhuma informação de grupo
estará presente no token.

Para configurar isso:
1. Adicione um [Group Claim](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims)
   na configuração do token do Azure AD. Se não tiver certeza de qual tipo de grupo selecionar, escolha
   **All Groups**.
2. **Não** habilite **Emit groups as role claims**.
3. Atualize as permissões de API da aplicação para incluir `GroupMember.Read.All` ou `Group.Read.All`.
   `GroupMember.Read.All` é recomendado, pois concede menos permissões.

### Group Cleaning

Se **Enable Azure AD OAuth Group Cleaning** estiver ativado, os grupos do DefectDojo criados pela
sincronização com o Azure AD serão removidos automaticamente quando não tiverem mais membros. Quando um
usuário é removido de um grupo no Azure AD, ele também é removido do grupo correspondente no DefectDojo.
