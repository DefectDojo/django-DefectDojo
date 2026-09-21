---
title: Configuração de SAML
description: Configure o SAML no DefectDojo Pro
weight: 1
audience: pro
---

O DefectDojo Pro oferece suporte à autenticação SAML por meio da interface **Enterprise Settings**. O DefectDojo open-source não inclui SSO — consulte [Usuários Autorizados](/admin/user_management/os__authorized_users/) para o controle de acesso no open-source.

## URL do ACS (Assertion Consumer Service)

Seu Identity Provider precisa saber para onde enviar (POST) a resposta SAML depois que um usuário se autentica. A URL do ACS do DefectDojo é:

```
https://<your-instance>.cloud.defectdojo.com/saml2/acs/
```

Algumas coisas a saber sobre esse endpoint:

- **O endpoint aceita apenas requisições `POST`.** Abrir a URL do ACS diretamente em um navegador emite um GET e retornará um **HTTP 405 Method Not Allowed**. Esse é o comportamento esperado — não significa que o SAML esteja quebrado ou mal configurado. O endpoint foi projetado para ser invocado pelo seu IdP como parte do fluxo de redirecionamento SAML, não por um navegador acessando a URL diretamente.
- **A URL do ACS está disponível na sua instância do DefectDojo Cloud o tempo todo** — você não precisa habilitar o SAML no DefectDojo antes de apontar seu IdP para ela. Você pode configurar o lado do IdP e o lado do DefectDojo em qualquer ordem.

## Configuração inicial

1. Acesse **Enterprise Settings > SAML Settings**.

   ![image](images/sso_betaui_1.png)

2. Defina um **Entity ID** — um rótulo ou URL que seu SAML Identity Provider usa para identificar o DefectDojo. Este campo é obrigatório.

3. Opcionalmente, defina o **Login Button Text** — o texto exibido no botão em que os usuários clicam para iniciar o login SAML.

4. Opcionalmente, defina uma **Logout URL** para redirecionar os usuários depois que eles saírem do DefectDojo.

5. Escolha um **Name ID Format**:
   - **Persistent** — os usuários são identificados de forma consistente pelo SAML entre sessões.
   - **Transient** — os usuários recebem um ID SAML diferente a cada login.
   - **Entity** — todos os usuários compartilham um único NameID SAML.
   - **Encrypted** — o NameID de cada usuário é criptografado.

6. **Required Attributes** — especifique os atributos que o DefectDojo exige na resposta SAML.

7. **Attribute Mapping** — mapeie os atributos enviados pelo seu IdP para os campos de usuário do DefectDojo que eles devem preencher. Cada linha associa um **SAML Attribute** a um **DefectDojo Field**; use **Add Attribute Mapping** para adicionar linhas e o ícone de lixeira para remover uma.

   ![image](images/sso_saml_attribute_mapping.png)

   - **SAML Attribute** é um campo de texto livre e deve corresponder exatamente ao nome do atributo que seu IdP realmente emite. Alguns IdPs (por exemplo, Entra ID / Azure AD) enviam URIs de claim totalmente qualificados, como `http://schemas.microsoft.com/identity/claims/emailaddress`, em vez de nomes amigáveis. Se você não tiver certeza do que seu IdP envia, habilite **Enable SAML Debugging** (veja [Solução de problemas](#troubleshooting)) e inspecione a assertion nos logs.
   - **DefectDojo Field** é escolhido a partir de uma lista: **Username**, **First Name**, **Last Name** e **Email**.
   - No mínimo, mapeie o atributo que corresponde a **Username**. O DefectDojo procura usuários pelo nome de usuário ao associar logins SAML a contas existentes.
   - É altamente recomendável mapear um atributo para **Email**: o DefectDojo usa o endereço de e-mail para notificações e para associar um login recebido a uma conta existente pelo e-mail.
   - O mesmo atributo pode alimentar mais de um campo — por exemplo, uma claim de e-mail usada tanto para **Email** quanto para **Username**. O inverso não é permitido: cada campo do DefectDojo só pode ser mapeado a partir de um único atributo.
   - Uma linha com apenas metade preenchida é rejeitada ao salvar, e a célula problemática é destacada. Linhas que você adiciona mas nunca preenche são descartadas em vez de tratadas como erros.

8. **Remote SAML Metadata** — a URL onde os metadados do seu SAML Identity Provider estão hospedados.

9. Marque **Enable SAML** na parte inferior do formulário para ativar o login SAML. Um botão **Login With SAML** aparecerá na página de login do DefectDojo.

   ![image](images/sso_saml_login.png).

## Opções adicionais

* **Create Unknown User** — cria automaticamente um novo usuário do DefectDojo caso ele não seja encontrado na resposta SAML.
* **Allow Unknown Attributes** — permite o login de usuários que possuem atributos não listados no Attribute Mapping.
* **Sign Assertions/Responses** — exige que todas as respostas SAML recebidas sejam assinadas.
* **Sign Logout Requests** — assina todas as requisições de logout enviadas pelo DefectDojo.
* **Force Authentication** — exige que os usuários se autentiquem no Identity Provider a cada login, independentemente de sessões existentes.
* **Enable SAML Debugging** — registra a saída detalhada do SAML para solução de problemas. Veja [Solução de problemas → Saída do SAML Debugging](#saml-debugging-output) para saber onde essa saída aparece.

## Mapeamento de Grupos SAML

O DefectDojo pode usar a assertion SAML para atribuir usuários automaticamente a [Grupos de Usuários](../../user_management/create_user_group/). Os grupos no DefectDojo atribuem permissões a todos os seus membros, então o Group Mapping permite gerenciar permissões em massa. Essa é a única forma de definir permissões via SAML.

**O mapeamento de grupos é opcional.** Embora os campos **Group Name Attribute** e **Group Limiter Regex Expression** apareçam com um asterisco de campo obrigatório (`*`) na interface, o formulário SAML será enviado sem eles, e o login SAML funcionará sem o mapeamento de grupos. Não é necessário pré-criar grupos ou roles no seu IdP (por exemplo, application roles do Azure AD) antes de habilitar o SAML — você só precisa configurar esses campos quando realmente quiser que o DefectDojo leia a associação a grupos a partir da assertion. Se você não configurar o mapeamento de grupos, os usuários de SSO recém-criados não terão permissões por padrão; veja [Acesso padrão para usuários provisionados por SSO](#default-access-for-sso-provisioned-users) abaixo.

O campo **Group Name Attribute** especifica qual atributo na assertion SAML contém as associações de grupo do usuário. Quando um usuário faz login, o DefectDojo lê esse atributo e atribui o usuário a quaisquer grupos correspondentes. Para limitar quais grupos da assertion são considerados, use o campo **Group Limiter Regex Expression** — uma expressão regular aplicada aos nomes de grupo da assertion, usada para filtrar em quais o DefectDojo deve atuar.

O valor deve corresponder exatamente ao nome do atributo que seu Identity Provider emite na assertion, incluindo qualquer prefixo de namespace. Um nome curto e amigável como `groups` só funcionará se o seu IdP estiver configurado para emitir esse nome de atributo literal — muitos IdPs usam, em vez disso, um URI de claim totalmente qualificado.

### Group Name Attribute por Identity Provider

| Identity Provider | Nome de atributo padrão a ser usado |
|---|---|
| **Entra ID / Azure AD** | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |
| **Okta** | `groups` (o nome de atributo configurado no Group Attribute Statement do aplicativo SAML) |
| **Keycloak** | `groups` (ou o que você definir como "SAML Attribute Name" no mapper Group List) |
| **PingFederate / generic** | O valor que você configurou no lado do IdP — verifique a assertion do seu IdP antes de presumir `groups` |

Se o mapeamento de grupos parecer não fazer nada — os usuários fazem login com sucesso, mas nenhum grupo é criado ou atribuído — veja [Solução de problemas → O mapeamento de grupos SAML não faz nada](#saml-group-mapping-does-nothing--users-log-in-but-no-groups-are-assigned) abaixo.

Se não existir um grupo com o nome correspondente, o DefectDojo criará um automaticamente e atribuirá a seus membros a role **Reader**. Observe que essa role Reader rege o acesso do membro *ao próprio grupo* — ela não concede nenhum acesso aos Produtos, Tipos de Produto ou outros ativos organizacionais subjacentes. Essas permissões são configuradas separadamente, e um grupo recém-criado automaticamente ainda não tem nenhuma delas até que um Superuser atribua ao grupo uma role nos Produtos ou Tipos de Produto relevantes.

Para ativar o mapeamento de grupos, marque a caixa de seleção **Enable Group Mapping** na parte inferior do formulário.

## Acesso padrão para usuários provisionados por SSO

Quando um novo usuário é criado via SAML (ou qualquer provedor social-auth) e não é adicionado a nenhum grupo via SAML Group Mapping, ele chegará a uma instância do DefectDojo **sem permissões**. Ao fazer login, ele verá zero Tipos de Produto, zero Produtos e zero Engajamentos — o painel aparecerá vazio.

Para dar a todo novo usuário de SSO provisionado uma base razoável, configure um **Default group** + **Default group role** na página System Settings:

1. Acesse **⚙️ Configuration → System Settings** (somente Superuser).
2. Defina **Default group** como o [Grupo de Usuários](../../user_management/create_user_group/) que os usuários recém-criados devem integrar.
3. Defina **Default group role** como a role que eles devem ter nesse grupo (por exemplo, **Reader**).
4. Opcionalmente, defina **Default group email pattern** com uma regex (por exemplo, `.*@yourcompany\\.com$`) para que o grupo padrão seja aplicado somente a usuários cujo e-mail corresponda.
5. Salve.

Tanto **Default group** quanto **Default group role** precisam estar definidos — se algum deles estiver vazio, o grupo padrão não é aplicado.

Essa configuração se aplica a **todo usuário recém-criado**, incluindo usuários criados via SAML, OAuth e outros provedores social-auth, porque ela é executada no sinal de criação de usuário do Django, em vez de dentro de um backend de autenticação específico.

> **Usuários existentes não são afetados.** O grupo padrão só é aplicado quando um usuário é criado pela primeira vez. Os usuários existentes do DefectDojo manterão suas associações de grupo atuais mesmo que você altere essa configuração posteriormente.

## Diferenças entre Cloud e On-Premise

O DefectDojo Cloud não tem o mesmo nível de personalização de SAML que o DefectDojo On-Prem.  As únicas variáveis que podem ser definidas são pela interface.  Aqui estão algumas das principais diferenças:

| Capacidade | Cloud | On-Premise |
|---|---|---|
| **Correspondência de nome de usuário** | Somente NameID | Somente NameID (a variável de ambiente `SAML_USE_NAME_ID_AS_USERNAME` se aplica somente ao Open Source, não ao Pro) |
| **Criptografia de assertion SAML** | Atualmente não suportado | Atualmente não suportado |
| **Logs de login SAML** | Não disponível na interface. Entre em contato com o Suporte para solicitar os logs. | Disponível via logs do container da aplicação (`docker logs dojo`) |
| **Método de configuração** | Somente pela interface Enterprise Settings | Interface Enterprise Settings, Django Admin ou Django Shell |
| **Variáveis de ambiente** | Não podem ser definidas diretamente pelos clientes. Entre em contato com o Suporte para alterações. | Podem ser definidas via `dojo-compose-cli environment add` |

Se você precisar corresponder usuários por um atributo diferente de NameID (como `uid` ou `email`), configure seu Identity Provider para enviar o valor desejado como o NameID, em vez de ajustar as configurações do DefectDojo.

## Solução de problemas

### Saída do SAML Debugging

Quando **Enable SAML Debugging** (em [Opções adicionais](#additional-options)) está marcado, o DefectDojo grava a saída detalhada do processamento SAML — incluindo os atributos brutos recebidos do IdP — nos logs da aplicação no nível `DEBUG`, sob o logger `saml2`.

| Onde você está executando | Onde ler a saída de debug |
|---|---|
| **DefectDojo Cloud** | O log de debug do SAML não é exposto na interface. Entre em contato com o Suporte do DefectDojo para solicitar os logs de uma janela de tempo específica. |
| **On-Premise (container único)** | `docker logs dojo` (ou sua agregação de logs Helm/K8s) |
| **On-Premise (Helm/K8s)** | `kubectl logs deployment/defectdojo-django -c uwsgi` (ou o agregador de logs do seu cluster) |

Desative essa opção depois de concluir a solução de problemas — os logs de debug do SAML são verbosos e podem conter valores de atributos sensíveis do seu IdP.

### Os usuários recebem um erro "User not found" ou "Permission denied" depois de um login bem-sucedido no IdP

Se a assertion SAML for processada com sucesso (sem erros de XML ou de assinatura), mas o DefectDojo recusar o login, a causa mais comum é uma **incompatibilidade de nome de usuário** entre o IdP e o DefectDojo.

O DefectDojo procura o usuário **pelo nome de usuário** ao associar um login SAML a uma conta existente. Se o valor que seu IdP envia como o atributo `username` não corresponder ao nome de usuário de um usuário existente do DefectDojo, a busca falha — mesmo que o restante da assertion seja válido.

Duas soluções possíveis, escolha a que melhor se encaixa no seu ambiente:

- **Remova `username` do Attribute Mapping** e deixe o DefectDojo usar o `NameID` do SAML como nome de usuário. Isso é apropriado se os nomes de usuário do DefectDojo já corresponderem ao formato de NameID emitido pelo seu IdP.
- **Alinhe os nomes de usuário.** Certifique-se de que os nomes de usuário no DefectDojo sejam exatamente o que seu IdP envia na claim `username`. Para a maioria das organizações, a convenção mais simples é fazer os nomes de usuário do DefectDojo serem iguais ao endereço de e-mail do usuário, e configurar o IdP para enviar o e-mail como a claim `username`.

Se você não tiver certeza do que o IdP está realmente enviando, habilite **Enable SAML Debugging** (acima) e inspecione os atributos processados nos logs.

### O mapeamento de grupos SAML não faz nada — os usuários fazem login, mas nenhum grupo é atribuído

A causa mais comum é uma incompatibilidade entre o campo **Group Name Attribute** e o nome do atributo que seu IdP está realmente enviando. Veja a tabela [Group Name Attribute por Identity Provider](#group-name-attribute-by-identity-provider) acima, e habilite **Enable SAML Debugging** para ver os atributos brutos retornados pelo IdP.
