---
title: OIDC
description: Configure o SSO OpenID Connect (OIDC) no DefectDojo Pro
weight: 17
audience: pro
---

O DefectDojo Pro oferece suporte a login por meio de um provedor genérico OpenID Connect (OIDC). O DefectDojo open-source não inclui SSO — consulte [Usuários Autorizados](/admin/user_management/os__authorized_users/) para o controle de acesso no open-source.

## Configuração

No DefectDojo, acesse **Enterprise Settings > OIDC Settings**.

![image](images/oidc_pro.png)

Preencha o formulário:

1. **Endpoint** — a URL base do seu provedor OIDC. Não inclua `/.well-known/openid-configuration`.
2. **Client ID** — o ID de cliente do seu OIDC.
3. **Client Secret** — o segredo de cliente do seu OIDC.
4. Opcionalmente, configure **Claim Mapping** e **Group Mapping** — veja abaixo.
5. Marque **Enable OIDC**.

Envie o formulário. Um botão **Log In With OIDC** aparecerá na página de login do DefectDojo.

Use **Validate Config** a qualquer momento para verificar as configurações sem salvá-las. Isso busca o documento de descoberta, verifica as chaves de assinatura e o emissor, exibe o URI de redirecionamento exato a ser registrado no seu provedor e faz a validação cruzada dos seus mapeamentos de claims e grupos com as claims anunciadas pelo provedor.

## Mapeamento de Claims

Cada linha mapeia uma **OIDC Claim** para o **DefectDojo Field** que ela deve preencher. Use **Add Claim Mapping** para adicionar linhas e o ícone de lixeira para remover uma.

![image](images/sso_oidc_claim_mapping.png)

Um campo sem linha correspondente mantém sua claim padrão, então esta seção só é necessária quando seu provedor nomeia as coisas de forma diferente. As claims padrão são:

| DefectDojo Field | Claim padrão |
| --- | --- |
| Username | `preferred_username` |
| Email | `email` |
| First Name | `given_name` |
| Last Name | `family_name` |

Observações:

- Uma instância não configurada é aberta com essas quatro linhas já preenchidas, para que você possa ver o que o OIDC está fazendo antes de alterar qualquer coisa.
- A mesma claim pode alimentar mais de um campo. Cada campo do DefectDojo só pode ser mapeado a partir de uma única claim.
- As claims são lidas tanto do ID token quanto da resposta userinfo, então uma claim que seu provedor libera em apenas um dos dois ainda funciona.
- Se uma claim mapeada estiver ausente ou vazia para um determinado usuário, esse campo mantém seu valor padrão em vez de ficar em branco.

## Mapeamento de Grupos

O DefectDojo pode espelhar os grupos que seu provedor reporta nos grupos do DefectDojo a cada login. Marque **Enable Group Mapping** para exibir as configurações.

![image](images/sso_oidc_group_mapping.png)

- **Group Claim Name** — a claim que contém os grupos do usuário. **A maioria dos provedores não emite uma por padrão** e precisa que um mapper seja configurado explicitamente; no Keycloak, por exemplo, adicione um mapper *Group Membership* ao cliente. Observe que um mapper *User Realm Role* envia **roles** de realm, não grupos.
- **Group Limiter Regex Expression** — apenas os grupos que correspondem a esta expressão são espelhados. Use `.*` para permitir todos.
- **Remove Stale Group Memberships** — quando habilitado, as associações em grupos provisionados pelo OIDC que o provedor não reporta mais são removidas no próximo login. Apenas os grupos criados pelo OIDC são afetados; grupos que você atribuiu manualmente e grupos provisionados por outro provedor, como o SAML, nunca são alterados.

Os grupos são criados no primeiro uso e nomeados exatamente como o provedor os reporta. Se o seu provedor enviar caminhos completos de grupo (o mapper *Group Membership* do Keycloak faz isso quando **Full group path** está habilitado), o grupo do DefectDojo será nomeado `/Group A` em vez de `Group A`. Desative essa opção se quiser que os nomes correspondam aos grupos vindos de outro provedor; caso contrário, você acabará com dois grupos do DefectDojo para o mesmo grupo lógico.

Se o mapeamento de grupos parecer não fazer nada, execute **Validate Config**: ele informa se a claim que você indicou é uma das que o provedor anuncia.
