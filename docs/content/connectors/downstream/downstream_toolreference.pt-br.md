---
title: Referência de Ferramentas dos Conectores Downstream
description: Guias detalhados de configuração para Conectores Downstream
weight: 1
audience: pro
aliases:
- /pt-br/en/share_your_findings/integrations_toolreference
- /pt-br/issue_tracking/pro_integration/integrations_toolreference/
---

Aqui estão instruções específicas detalhando como configurar um Conector Downstream do DefectDojo com um rastreador de issues de terceiros.

## Azure DevOps Boards

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como a URL do seu Azure - por exemplo, `https://dev.azure.com/{your organization}`
- **Token** deve ser definido como um token de acesso pessoal do Azure.

A autenticação com o Azure DevOps requer um [token de acesso pessoal](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)
com permissões definidas como "Read, Write and Manage" para "Work Items" no projeto do Azure com o qual você deseja trabalhar.

### Mapeamento do Rastreador de Issues

Esses detalhes determinam como o DefectDojo mapeia os atributos de Achado ou Grupo de Achados para um determinado projeto no Azure DevOps:

#### Detalhes do mapeamento do rastreador de issues

O campo `Project ID` corresponde ao nome ou ao ID do projeto no Azure.

#### Detalhes do mapeamento de severidade

Os atributos no formulário são fornecidos como padrão e são os seguintes:

- **Nome do campo de severidade**: `/fields/Microsoft.VSTS.Common.Priority`
- **Mapeamento de Informativa**: `4`
- **Mapeamento de Baixo**: `4`
- **Mapeamento de Médio**: `3`
- **Mapeamento de Alto**: `2`
- **Mapeamento de Crítica**: `1`

#### Detalhes do mapeamento de status

Os atributos no formulário são fornecidos como padrão e são os seguintes:

- **Nome do campo de status**: `/fields/System.State`
- **Mapeamento de Ativo**: `To Do`
- **Mapeamento de Fechado**: `Done`
- **Mapeamento de Falso positivo**: `Done`
- **Mapeamento de Risco aceito**: `Done`

## Bitbucket

A integração com o Bitbucket permite enviar issues para o [rastreador de issues](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/) de um repositório do Bitbucket Cloud.

O rastreador de issues é opcional no Bitbucket e precisa ser ativado no repositório antes que o DefectDojo possa criar Issues nele. Para ativá-lo, abra o repositório no Bitbucket e selecione **Repository settings**, depois ative o rastreador de issues em **Features**.

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como `https://bitbucket.org`.
- **Email** deve ser o endereço de e-mail da conta Atlassian à qual o token de API pertence.
- **API Token** deve ser definido como um token de API do Atlassian com escopo definido.

As senhas de aplicativo do Bitbucket foram descontinuadas pela Atlassian e não funcionam com esta integração. Para criar um token de API:

1. Abra as [configurações da conta Atlassian](https://id.atlassian.com/manage-profile/security/api-tokens) e escolha **Security**, depois **Create and manage API tokens**.
2. Escolha **Create API token with scopes**, dê um nome ao token e defina uma data de expiração.
3. Selecione **Bitbucket** como o aplicativo.
4. Conceda ao token permissão para ler repositórios e para ler e gravar issues.

### Mapeamento do Rastreador de Issues

- **Workspace** deve ser o slug do workspace que contém o repositório, como aparece nas URLs do bitbucket.org.
- **Repository Slug** deve ser o slug do repositório no qual você deseja criar Issues.

### Detalhes do mapeamento de severidade

Isso corresponde ao campo Priority da issue no Bitbucket. Os atributos no formulário são fornecidos como padrão, e cada valor precisa ser uma das prioridades do Bitbucket: `trivial`, `minor`, `major`, `critical` ou `blocker`.

- **Nome do campo de severidade**: `priority`
- **Mapeamento de Informativa**: `trivial`
- **Mapeamento de Baixo**: `minor`
- **Mapeamento de Médio**: `major`
- **Mapeamento de Alto**: `critical`
- **Mapeamento de Crítica**: `blocker`

### Detalhes do mapeamento de status

Isso corresponde ao campo State da issue no Bitbucket. Cada valor precisa ser um dos estados de issue do Bitbucket: `new`, `open`, `resolved`, `on hold`, `invalid`, `duplicate`, `wontfix` ou `closed`.

- **Nome do campo de status**: `state`
- **Mapeamento de Ativo**: `new`
- **Mapeamento de Fechado**: `resolved`
- **Mapeamento de Falso positivo**: `invalid`
- **Mapeamento de Risco aceito**: `wontfix`

## GitHub

A integração com o GitHub permite adicionar issues a um [GitHub Project](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects), o que também abre Issues em um Repo associado. Esses Repos/Projects podem estar associados a uma organização do GitHub ou a uma conta pessoal do GitHub.

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como a URL do seu usuário ou organização do GitHub, dependendo de onde você deseja criar issues. Por exemplo, `https://github.com/{your-organization}`
- **Token** deve ser definido como um token de acesso pessoal do GitHub.

Tokens de acesso pessoal do GitHub podem ser criados em https://github.com/settings/tokens. O token precisa ter os escopos Repo e Project.

### Mapeamento do Rastreador de Issues

- **Issue Tracker Mapping Label** deve ser definido para identificar o Project ou Repo no qual você deseja criar Issues.
- **Project Number** deve ser o ID de um projeto do GitHub para o qual você deseja enviar itens. Você pode obtê-lo na URL ao visualizar um Project, por exemplo `https://github.com/orgs/{your-org}/projects/{project number}`.
- **Repository Name** deve ser o nome de um repo associado à sua organização (ou usuário) para o qual você deseja enviar Issues.


### Detalhes do mapeamento de severidade

**Para configurar a integração, o Project PRECISA ter um campo personalizado criado para representar a Issue Priority, caso contrário a Severidade não será mapeada corretamente e as Issues não serão enviadas ao GitHub.**

Siga este guia para criar um [campo personalizado](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority).
Cada Severidade precisará ter uma opção correspondente de seleção única disponível. Por exemplo, por padrão o DefectDojo sugere P0, P1, P2, P3, P4 como possíveis valores de Priority, e cada um deles precisará ser adicionado ao campo personalizado Priority.

- **Nome do campo de severidade**: `Priority`
- **Mapeamento de Informativa**: `P0`
- **Mapeamento de Baixo**: `P1`
- **Mapeamento de Médio**: `P2`
- **Mapeamento de Alto**: `P3`
- **Mapeamento de Crítica**: `P4`

### Detalhes do mapeamento de status

Por padrão, novos GitHub Projects têm os Statuses de Issues "In Progress" e "Done".  Statuses adicionais podem ser adicionados ao Project para acompanhar o status de Falso positivo ou Risco aceito, se desejado.  Uma das formas de fazer isso é adicionando uma nova Status Column ao Project Board.

- **Nome do campo de status**: `Status`
- **Mapeamento de Ativo**: `In Progress`
- **Mapeamento de Fechado**: `Done`
- **Mapeamento de Falso positivo**: `Done`
- **Mapeamento de Risco aceito**: `Done`

## GitLab

A integração com o GitLab permite adicionar issues a um [GitLab Project](https://docs.gitlab.com/ee/user/project/).

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como o link para o seu servidor GitLab, por exemplo `https://gitlab.com/`.
- **Token** deve ser definido como um token de acesso pessoal do GitLab. O token precisa ter escopos de API. Consulte o [guia do GitLab para criar um token de acesso pessoal](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token).

### Mapeamento do Rastreador de Issues

- **Project Name**: o nome do projeto no GitLab para o qual você deseja enviar issues.

### Detalhes do mapeamento de severidade

Isso corresponde ao campo Priority do GitLab.
- **Nome do campo de severidade**: `Priority`
- **Mapeamento de Informativa**: `1`
- **Mapeamento de Baixo**: `2`
- **Mapeamento de Médio**: `3`
- **Mapeamento de Alto**: `4`
- **Mapeamento de Crítica**: `5`

### Detalhes do mapeamento de status

Por padrão, o GitLab tem os statuses 'opened' e 'closed'.  Labels de status adicionais podem ser adicionadas se você quiser acompanhar o status de Falso positivo ou Risco aceito.  Consulte a [documentação do GitLab](https://docs.gitlab.com/user/work_items/status/) para mais detalhes.

- **Nome do campo de status**: `Status`
- **Mapeamento de Ativo**: `opened`
- **Mapeamento de Fechado**: `closed`
- **Mapeamento de Falso positivo**: `closed`
- **Mapeamento de Risco aceito**: `closed`

## Jira

A integração com o Jira envia Achados e Grupos de Achados do DefectDojo para um projeto do Jira como issues, mantém o status de cada issue sincronizado com o Achado e vincula o Achado à issue criada. Tanto o Jira **Cloud** quanto o **Data Center / Server** são suportados. O Jira Service Management não é suportado.

### Escolhendo um método de autenticação

Defina primeiro o **Jira Deployment** e, em seguida, escolha um **Authentication Method**:

**Jira Cloud**
- **API Token (email + token)** — autenticação HTTP Basic usando um e-mail de conta Atlassian e um [API token](https://id.atlassian.com/manage-profile/security/api-tokens). As chamadas vão diretamente para a URL do seu site.
- **OAuth 2.0 (recommended)** — um consentimento único pelo navegador; o DefectDojo obtém e renova os tokens para você.
- **Service Account Token** — um token de API com escopo definido, criado para uma [service account](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/) da Atlassian.

**Jira Data Center / Server**
- **Personal Access Token (recommended)**
- **Username + Password**

> **Como a autenticação do Cloud chega ao Jira:** tanto o OAuth 2.0 quanto o Service Account autenticam como um Bearer token no gateway da Atlassian — `https://api.atlassian.com/ex/jira/{cloudId}` — que é um *host diferente* da URL do seu site `https://your-site.atlassian.net`. O DefectDojo usa o gateway em todas as chamadas de API, mas sempre monta o link do ticket exibido em um Achado a partir da **URL do seu site**, de modo que o link em que o usuário clica é um link normal e navegável no formato `.../browse/{ISSUE-KEY}`. (A autenticação por API Token e Data Center chama a URL do site diretamente, então não há essa divisão.)

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como a **URL do seu site** Jira, por exemplo `https://your-organization.atlassian.net`. Isso é usado para os links navegáveis de tickets e — para autenticação por API Token e Data Center — como a URL base da API.
- Os demais campos dependem do método escolhido acima (e-mail + API token, credenciais de cliente OAuth, token de service account, PAT, ou username + password).

### Configuração do OAuth 2.0 (Cloud)

Crie um app dedicado no [Atlassian developer console](https://developer.atlassian.com/console/myapps/) e, em seguida, conecte a partir do DefectDojo.

1. Escolha **Create → OAuth 2.0 integration**. Precisa ser uma *OAuth 2.0 integration* — um app Connect ou Forge não pode usar o grant de authorization-code 3LO (você receberia `grant_type is not enabled for client`).
2. Quando solicitado o **Access type**, escolha **Resource-level**. Isso restringe o token a um único site Jira autorizado pelo usuário, que é exatamente o alvo de uma conexão do DefectDojo. (**Account-level** concede acesso a todos os sites da conta Atlassian — mais amplo do que o necessário.)
3. Em **Permissions**, adicione a **Jira platform REST API** e conceda os escopos listados abaixo. Observação: `offline_access` *não* aparece aqui — é um escopo OAuth padrão que o DefectDojo solicita na URL de autorização, não algo que você adiciona nesta tela.
4. Em **Authorization**, ao lado de **OAuth 2.0 (3LO)**, clique em **Configure** e defina a **Callback URL** como `https://<your-defectdojo-host>/integrators/jira/oauth/callback` — precisa corresponder exatamente à URL do site do seu DefectDojo. Habilitar isso é o que ativa o grant de authorization-code e os refresh tokens; pular esta etapa causa os erros `grant_type is not enabled` / `Client is not allowed to use offline_access`.
5. Copie o **Client ID** e o **Client Secret** para o formulário do DefectDojo e clique em **Submit** para salvar a conexão.
6. Clique em **Connect with Jira** e aprove a tela de consentimento. A Atlassian redireciona de volta para o DefectDojo, que armazena os tokens e resolve automaticamente o seu `cloudId`. Um indicador "Connected" aparece quando a operação é bem-sucedida.

> O host do callback é o `SITE_URL` do seu DefectDojo. A Atlassian precisa conseguir redirecionar o navegador para lá, e o valor precisa corresponder exatamente ao que o DefectDojo envia — portanto, use o hostname real pelo qual seus usuários acessam o DefectDojo, e não um valor acessível apenas de dentro da rede.

#### Escopos mínimos de OAuth

O DefectDojo solicita esses quatro escopos clássicos por padrão, que também são o **mínimo absoluto** necessário — cada um sustenta um comportamento específico:

| Scope | Necessário para |
|-------|--------------|
| `read:jira-work` | Ler o projeto, as issues e as transições disponíveis (validação da conexão e sincronização de status). |
| `write:jira-work` | Criar e editar issues, e executar transições de status. |
| `read:jira-user` | A verificação de identidade da conexão — o DefectDojo chama `/myself` ao validar o acesso. |
| `offline_access` | Emitir um **refresh token**. Sem ele, o access token expira (~1 hora após a conexão) e a conexão para de funcionar, pois o DefectDojo não consegue mais renová-lo. |

A Atlassian recomenda escopos clássicos em vez de granulares; os quatro acima mantêm a pegada do app mínima e são suficientes para tudo o que a integração faz.

##### Alternativa de escopo granular

Se sua organização exigir escopos **granulares** em vez de clássicos, o conjunto mínimo equivalente é:

| Granular scope | Necessário para |
|----------------|--------------|
| `read:user:jira` | A verificação de identidade `/myself`. |
| `read:project:jira` | Validar que o projeto de destino existe. |
| `read:issue:jira` | Ler o status atual de uma issue durante a sincronização. |
| `write:issue:jira` | Criar e editar issues **e executar transições de status** — não existe um escopo separado de escrita para transições; uma transição é uma escrita na issue. |
| `read:issue.transition:jira` | Listar as transições disponíveis em uma issue. |
| `offline_access` | O refresh token (o mesmo do clássico). |

Dependendo da configuração de campos do seu site, um endpoint também pode exigir escopos de leitura complementares para expandir campos — mais comumente `read:status:jira` e `read:field:jira` (e `read:issue-meta:jira` para criação). Se um envio falhar com um erro `403` "scope does not match", adicione exatamente o escopo indicado no erro. Essa proliferação de escopos complementares é justamente o motivo pelo qual os escopos clássicos são recomendados.

Para o método **Service Account Token**, conceda ao token `read:jira-work` e `write:jira-work` (mais `read:jira-user`) — ou os equivalentes granulares acima sem `offline_access`. O `offline_access` não se aplica — um token de service account tem vida longa e não é renovado pelo DefectDojo.

### Mapeamento do Rastreador de Issues

- **Project Key**: a chave do projeto Jira no qual as issues serão criadas, por exemplo `SEC`.
- **Issue Type**: o tipo de issue a ser criado, por exemplo `Bug` ou `Task`. O padrão é `Bug`.

### Detalhes do mapeamento de severidade

Os padrões correspondem ao esquema de prioridades padrão do Jira. Edite-os para corresponder aos nomes de prioridade do seu projeto:

- **Nome do campo de severidade**: `priority`
- **Mapeamento de Informativa**: `Lowest`
- **Mapeamento de Baixo**: `Low`
- **Mapeamento de Médio**: `Medium`
- **Mapeamento de Alto**: `High`
- **Mapeamento de Crítica**: `Highest`

### Detalhes do mapeamento de status

Os statuses variam de acordo com o workflow de cada projeto, portanto esses padrões devem ser editados para corresponder aos nomes de status do **seu** workflow:

- **Nome do campo de status**: `status`
- **Mapeamento de Ativo**: `To Do`
- **Mapeamento de Fechado**: `Done`
- **Mapeamento de Falso positivo**: `Done`
- **Mapeamento de Risco aceito**: `Done`

### Campos personalizados (opcional)

Você pode mapear campos adicionais do Jira — por exemplo, um `resolution` obrigatório ao fechar, ou `labels` — na etapa **Custom Fields** do mapeamento. Cada mapeamento de campo personalizado tem quatro partes:

- **Source** — de onde o valor vem: um atributo do **Achado**, **Teste**, **Engajamento** ou **Asset** sendo enviado, ou um **Static value**.
- **Value** — para uma origem do tipo objeto, o atributo específico a ser lido, escolhido em uma lista dos campos desse objeto com rótulos legíveis (por exemplo, *Severity*, *CVE*, *Mitigation*). Para uma origem **Static value**, este é um campo de texto livre onde você digita o valor literal.
- **Vendor Field** — o campo do Jira no qual gravar. Como o DefectDojo consegue ler o catálogo de campos do Jira, este é um seletor pesquisável que lista cada campo pelo seu **display name** e resolve o id interno para você — assim, você seleciona *DD Close Justification* e o DefectDojo armazena `customfield_10255`. O seletor é preenchido a partir da conexão, portanto funciona assim que a conexão é salva e validada.
- **Application point** — *quando* enviar o campo: na **criação do ticket**, em **cada atualização**, ou como parte de uma **transition** de status específica (Ativo / Fechado / Falso positivo / Risco aceito). Um campo com escopo de transição é enviado como parte da edição dessa transição — é assim que você fornece um valor que o Jira só aceita em uma tela de transição, mais comumente um `resolution` exigido pelo seu workflow quando uma issue é resolvida.

### Modelos de ticket (opcional)

Por padrão, as issues do Jira usam o título e o corpo integrados do DefectDojo. Para personalizá-los, anexe um **Ticket Template** ao mapeamento na etapa **Ticket Template**. Um modelo define quatro partes independentemente opcionais — o resumo e a descrição do **Achado**, e o resumo e a descrição do **Grupo de Achados**. Qualquer parte deixada em branco volta ao padrão integrado, então você pode sobrescrever apenas o título, apenas o corpo, ou os quatro. Use **Test render** no editor de modelos para pré-visualizar a saída renderizada com dados de exemplo — detectando erros como placeholders desconhecidos ou valores que excedem o limite de tamanho de um campo — antes de salvar. Se um modelo for excluído posteriormente, os mapeamentos que o usavam voltam automaticamente aos padrões integrados.

### Como funciona

- **Create / Update / Delete:** criar envia uma nova issue e registra o link no Achado; atualizar edita a issue existente; excluir um Achado força o fechamento de sua issue (nada é excluído no Jira). Os envios podem ser manuais ("Push to Integrator") ou automáticos, de acordo com o Issue Tracker Assignment.
- **Status reconciliation:** após a criação (e a cada atualização), o DefectDojo lê o status atual da issue e, se ele for diferente do alvo mapeado, encontra uma única transição de workflow que o alcance e a aplica. Se não existir tal transição, o mapeamento registra um erro em vez de falhar silenciosamente. Quaisquer campos personalizados com escopo de transição são enviados junto com essa transição.
- **Ticket link:** o link exibido no Achado é `https://your-site.atlassian.net/browse/{ISSUE-KEY}` — sempre a URL pública do seu site, nunca o gateway interno.
- **Token lifecycle (OAuth):** o DefectDojo controla todo o fluxo — ele realiza a troca de authorization-code, armazena os access e refresh tokens, e os renova sob demanda antes de um envio, persistindo o novo refresh token a cada vez (a Atlassian o rotaciona a cada renovação).
- **Credential storage:** todas as credenciais da conexão (senhas, tokens, client secrets, tokens OAuth) são criptografadas em repouso e nunca são retornadas pela API — editar uma conexão mostra um placeholder "leave blank to keep" para os segredos armazenados.

## Linear

A integração com o Linear permite enviar Achados do DefectDojo como Issues do [Linear](https://linear.app/). As Issues são criadas em um Team no seu workspace do Linear.

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como `https://api.linear.app/graphql`.
- **API Key** deve ser definido como uma personal API key do Linear. As chaves podem ser geradas no Linear em Settings, depois Security & access, depois [API](https://linear.app/settings/account/security). A chave é enviada para a API GraphQL do Linear no header `Authorization`.

### Mapeamento do Rastreador de Issues

- **Team (Group) ID** deve ser definido como o ID do Team do Linear para o qual as Issues serão criadas. Você pode listar seus Teams e seus IDs chamando a API GraphQL do Linear:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Detalhes do mapeamento de severidade

Uma Issue do Linear carrega uma **priority** numérica em vez de um campo de severidade. Cada severidade do DefectDojo é mapeada para uma priority do Linear, em que `1` é Urgent e `4` é Low:

- **Nome do campo de severidade**: `Priority`
- **Mapeamento de Informativa**: `4`
- **Mapeamento de Baixo**: `4`
- **Mapeamento de Médio**: `3`
- **Mapeamento de Alto**: `2`
- **Mapeamento de Crítica**: `1`

### Detalhes do mapeamento de status

Cada valor de status precisa ser definido como o ID de um Workflow State no seu Team do Linear. Os IDs de Workflow State são exclusivos de cada workspace, portanto não há valores padrão. Você pode listar os Workflow States e seus IDs chamando a API GraphQL do Linear:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Nome do campo de status**: `Workflow State ID`
- **Mapeamento de Ativo**: o ID de um estado iniciado ou não iniciado, por exemplo `Todo` ou `In Progress`.
- **Mapeamento de Fechado**: o ID de um estado concluído, por exemplo `Done`. Quando um Achado é excluído no DefectDojo, sua Issue é movida para esse estado.

## Opsgenie

A integração com o Opsgenie permite enviar Achados e Grupos de Achados do DefectDojo como Alerts do Opsgenie, opcionalmente roteados para um Team do Opsgenie como responder.

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como `https://api.opsgenie.com`.  Se sua conta Opsgenie estiver hospedada na região de serviço da UE, use `https://api.eu.opsgenie.com`.  Se seus alerts estiverem no Jira Service Management Operations (a Atlassian está incorporando o Opsgenie ao JSM), use `https://api.atlassian.com/jsm/ops/integration`.
- **API Key** deve ser definido como uma chave de **API integration** do Opsgenie.  Um administrador da conta pode criar uma no aplicativo web do Opsgenie em **Settings > Integrations**: adicione uma integração do tipo **API** e conceda *Create and Update Access* (e *Read Access* para que o DefectDojo possa verificar a conexão).  Observe que se trata de uma chave de integração, não de uma chave de API pessoal - o DefectDojo autentica com a autorização `GenieKey`, que só é suportada por chaves de integração.

### Mapeamento do Rastreador de Issues

- **Team Name** *(opcional)* deve ser o nome do Team do Opsgenie a ser adicionado como responder nos alerts criados.  Você pode deixá-lo vazio: se a chave de API integration tiver escopo de team, os alerts são roteados automaticamente para esse team; caso contrário, as próprias regras de roteamento da sua conta decidem os responders.

### Detalhes do mapeamento de severidade

As severidades correspondem ao campo **Priority** do alert no Opsgenie, que usa a escala fixa do Opsgenie de `P1` (crítica) a `P5` (informativa):

- **Nome do campo de severidade**: `Priority`
- **Mapeamento de Informativa**: `P5`
- **Mapeamento de Baixo**: `P4`
- **Mapeamento de Médio**: `P3`
- **Mapeamento de Alto**: `P2`
- **Mapeamento de Crítica**: `P1`

Se uma severidade for mapeada para um valor não reconhecido, a priority é omitida e o Opsgenie aplica seu próprio padrão (`P3`).

### Detalhes do mapeamento de status

Os alerts do Opsgenie são `open` ou `closed`, e um alert aberto também pode ser `acknowledged`:

- **Nome do campo de status**: `Status`
- **Mapeamento de Ativo**: `open`
- **Mapeamento de Fechado**: `closed`
- **Mapeamento de Falso positivo**: `closed`
- **Mapeamento de Risco aceito**: `acknowledged`

Observe que `closed` é um status final no Opsgenie - um alert fechado não pode ser reaberto, e seu alias é liberado.  Diferentemente de outras ferramentas, o Opsgenie permite edições de conteúdo após a criação, então enviar um Achado atualizado sincroniza sua mensagem, descrição e priority junto com o status.

O DefectDojo define o **alias** de cada alert como uma chave estável derivada do Achado ou Grupo de Achados, e o Opsgenie desduplica alerts abertos por alias - assim, reenviar o mesmo Achado atualiza o alert aberto existente em vez de criar um duplicado.

## PagerDuty

A integração com o PagerDuty permite enviar Achados e Grupos de Achados do DefectDojo como Incidents do PagerDuty, abertos em um Service do PagerDuty à sua escolha.

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como `https://api.pagerduty.com`.  Se sua conta PagerDuty estiver hospedada na região de serviço da UE, use `https://api.eu.pagerduty.com`.
- **API Token** deve ser definido como uma chave de REST API do PagerDuty.  Um administrador da conta pode criar uma no aplicativo web do PagerDuty em **Integrations > API Access Keys > Create New API Key**.  Deixe "Read-only" desmarcado - o DefectDojo precisa criar e atualizar incidents.
- **From Email** deve ser o endereço de e-mail de um usuário válido na sua conta PagerDuty.  O PagerDuty exige esse endereço ao criar ou atualizar incidents, e ele será exibido como o requester do incident.

### Mapeamento do Rastreador de Issues

- **Service ID** deve ser o ID do Service do PagerDuty no qual os incidents serão abertos.  Você pode encontrá-lo no final da URL ao visualizar o Service no PagerDuty, por exemplo `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`.

### Detalhes do mapeamento de severidade

Por padrão, isso corresponde ao campo **Urgency** do incident no PagerDuty, que só aceita `high` ou `low`:

- **Nome do campo de severidade**: `Urgency`
- **Mapeamento de Informativa**: `low`
- **Mapeamento de Baixo**: `low`
- **Mapeamento de Médio**: `low`
- **Mapeamento de Alto**: `high`
- **Mapeamento de Crítica**: `high`

Alternativamente, se sua conta PagerDuty tiver [Priorities](https://support.pagerduty.com/main/docs/incident-priority) habilitadas, você pode mapear as severidades para nomes de Priority.  Defina o **Nome do campo de severidade** como `Priority` e use os nomes de Priority da sua conta (por exemplo, de `P1` a `P5`) como valores de mapeamento.  Ao mapear para Priority, a Urgency do incident fica a cargo das próprias regras de urgência do Service.

### Detalhes do mapeamento de status

Os incidents do PagerDuty têm três statuses: `triggered`, `acknowledged` e `resolved`.

- **Nome do campo de status**: `Status`
- **Mapeamento de Ativo**: `triggered`
- **Mapeamento de Fechado**: `resolved`
- **Mapeamento de Falso positivo**: `resolved`
- **Mapeamento de Risco aceito**: `acknowledged`

Observe que `resolved` é um status final no PagerDuty - um incident resolvido não pode ser reaberto.  Observe também que o PagerDuty não permite editar o título ou a descrição de um incident após a criação, portanto enviar um Achado atualizado sincroniza seu status, urgency e priority, mas não alterações de conteúdo.

## ServiceNow

A integração com o ServiceNow permite enviar Achados do DefectDojo como Incidentes do ServiceNow.

### Configuração da instância

O DefectDojo se autentica no ServiceNow via OAuth 2.0. A forma de criar as credenciais OAuth depende da sua versão do ServiceNow — versões mais recentes (Zurich e posteriores) usam a concessão Client Credentials, enquanto versões anteriores usam um refresh token.

#### ServiceNow Zurich e posteriores (client credentials)

Versões recentes do ServiceNow descontinuaram a opção clássica "Create an OAuth API endpoint for external clients" em favor da **New Inbound Integration Experience**, que emite uma concessão OAuth **Client Credentials** vinculada a uma conta de serviço:

1. Na barra de navegação à esquerda, pesquise por "Application Registry" e selecione-a.
2. Clique em **New** e, em seguida, escolha **New Inbound Integration Experience**.
3. Selecione **New Integration → OAuth - Client credentials grant**.
4. Defina o **OAuth Application User** como a conta de serviço que criará os Incidentes. As permissões (roles) dessa conta determinam o que o DefectDojo tem permissão para gravar.
5. Salve o registro. O ServiceNow gera automaticamente o **Client ID** e o **Client Secret** (deixe esses campos em branco ao criar o registro).

Em seguida, no DefectDojo:

- **Instance Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como a URL do seu servidor ServiceNow, por exemplo `https://your-organization.service-now.com/`.
- **Client ID** deve ser o Client ID do registro OAuth.
- **Client Secret** deve ser o Client Secret do registro OAuth.

Deixe os campos Refresh Token, Username e Password vazios — o DefectDojo solicita um novo token de client credentials a cada sincronização.

#### Versões anteriores do ServiceNow (refresh token)

Em versões que ainda oferecem o registro clássico, obtenha um Refresh Token associado ao usuário ou conta de serviço que enviará Incidentes para o ServiceNow:

1. Na barra de navegação à esquerda, pesquise por "Application Registry" e selecione-a.
2. Clique em "New".
3. Escolha "Create an OAuth API endpoint for external clients".
4. Preencha os campos obrigatórios:
    * Name: forneça um nome significativo para sua aplicação (por exemplo, Vulnerability Integration Client).
    * (Opcional) Ajuste o Token Lifespan:
    * Access Token Lifespan: o padrão é 1800 segundos (30 minutos).
    * Refresh Token Lifespan: o padrão é 8640000 segundos (aproximadamente 100 dias).
5. Clique em Submit para criar o registro da aplicação.
6. Após o envio, selecione a aplicação na lista e anote os campos **Client ID e Client Secret**.

Em seguida, você precisará usar esse registro para obter um Refresh Token, que só pode ser obtido através da API do ServiceNow. Abra uma janela de terminal e cole o comando a seguir (substituindo as variáveis entre `{{}}` pelas informações reais do seu usuário)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

Se suas credenciais do ServiceNow estiverem corretas e permitirem acesso de nível administrativo ao ServiceNow, você deverá receber uma resposta com um RefreshToken. Você precisará desse token para concluir a integração com o DefectDojo.

- **Instance Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como a URL do seu servidor ServiceNow, por exemplo `https://your-organization.service-now.com/`.
- **Refresh Token** é onde o Refresh Token deve ser inserido.
- **Client ID** deve ser o Client ID definido no registro do aplicativo OAuth.
- **Client Secret** deve ser o Client Secret definido no registro do aplicativo OAuth.

### Detalhes do mapeamento de severidade

Isso é mapeado para o campo Impact do ServiceNow.
- **Info Mapping**: `1`
- **Low Mapping**: `1`
- **Medium Mapping**: `2`
- **High Mapping**: `3`
- **Critical Mapping**: `3`

### Detalhes do mapeamento de status

- **Status Field Name**: `State`
- **Active Mapping**: `New`
- **Closed Mapping**: `Closed`
- **False Positive Mapping**: `Resolved`
- **Risk Accepted Mapping**: `Resolved`

Cada mapeamento aceita um rótulo de estado padrão (`New`, `In Progress`, `On Hold`, `Resolved`, `Closed`, `Cancelled`) ou um valor de estado numérico. Em instâncias com estados de Incidente personalizados — ou ao direcionar para uma tabela diferente de `incident` — use o **valor de estado** numérico da lista de opções da sua instância; um valor numérico fora do conjunto padrão é enviado ao ServiceNow exatamente como configurado. O código de resolução padrão embutido só acompanha os estados resolvido/fechado padrão, portanto combine valores de estado personalizados com os mapeamentos de campos de fechamento e resolução abaixo.

### Campos de fechamento e resolução

Algumas instâncias do ServiceNow aplicam uma Data Policy que torna campos como o **Resolution code** (`close_code`) obrigatórios sempre que um Incidente é movido para um estado resolvido ou fechado. Se o DefectDojo fechar um Incidente sem esses campos, o ServiceNow rejeita a gravação com um HTTP 403 *"Data Policy Exception"* e o motivo fica registrado na visão de Erros da integração.

Anexe os campos obrigatórios à mudança de estado usando **Custom Field Mappings**, definindo **Apply On** para a disposição que deve carregá-los:

- **Transition to Closed** — enviado quando um Achado é mitigado / fechado.
- **Transition to False Positive** — enviado quando um Achado é marcado como falso positivo.
- **Transition to Risk Accepted** — enviado quando um Achado tem o risco aceito.

Por exemplo, para satisfazer um Resolution code obrigatório:

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

Observações:

- Field Name é o nome da coluna no ServiceNow — `close_code`, `close_notes`, ou um campo personalizado `u_...`.
- Os mapeamentos de transição disparam quando o estado do registro realmente muda: um Achado que já está fechado no primeiro envio, uma atualização que fecha ou reabre o registro, e o fechamento forçado quando um link de ticket é excluído. Eles não são reenviados em atualizações rotineiras de um registro inalterado, portanto campos de journal como `work_notes` recebem uma entrada por transição.
- Campos de referência como `assignment_group` e `assigned_to` esperam um **sys_id**, não um nome de exibição.
- Valores que são interpretados como JSON são enviados tipados: `true`, `42`, `[...]`, `{...}` — e `null`, que limpa o campo. Para enviar esse texto como uma string literal, envolva-o em aspas duplas (por exemplo, `"null"`).
- `short_description`, `description`, `state`, `impact`, `urgency` e `priority` pertencem ao template de descrição e aos mapeamentos de severidade/status, portanto não podem ser definidos por meio de um mapeamento de campo personalizado.
- Em tabelas diferentes de `incident`, valores de estado que correspondem ao conjunto padrão de Incidente (`1`, `2`, `3`, `6`, `7`, `8`) ainda são interpretados com a semântica de Incidente — incluindo o Resolution code padrão automático em `6`/`7`/`8`. Prefira valores de estado fora desse intervalo em tabelas personalizadas, ou forneça os campos de fechamento explicitamente como acima.

## ServiceNow SecOps

A integração ServiceNow SecOps (também conhecida como **ServiceNow SecOps / Vulnerability Response**) envia Achados e Grupos de Achados do DefectDojo para uma tabela de segurança do ServiceNow — um **Security Incident** (`sn_si_incident`) ou um **Vulnerable Item** (`sn_vul_vulnerable_item`) — e a mantém sincronizada conforme o Achado muda (criação, atualização e resolução/fechamento). É a contraparte de operações de segurança da integração de rastreamento de issues do ServiceNow acima; use o ServiceNow SecOps quando você executa as aplicações Security Incident Response (SIR) ou Vulnerability Response (VR).

### Configuração da instância

- **Instance Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como a URL do seu servidor ServiceNow, por exemplo `https://your-organization.service-now.com/`.

O ServiceNow SecOps suporta três métodos de autenticação; forneça **um**:

- **OAuth 2.0** — insira um **Client ID**, **Client Secret** e **Refresh Token**. Obtenha-os exatamente como descrito na seção [ServiceNow](#servicenow) acima (crie um endpoint de API OAuth no Application Registry e, em seguida, troque suas credenciais em `/oauth_token.do` por um refresh token). Alternativamente, forneça o **Client ID** e o **Client Secret** junto com um **Username** e **Password** para usar a concessão de senha OAuth em vez de um refresh token.
- **API Key** — insira uma **API Key**, enviada no cabeçalho `x-sn-apikey`. A chave não autentica nada até que um Inbound Authentication Profile e uma REST API Access Policy sejam anexados a ela na instância.
- **HTTP Basic** — insira o **Username** e **Password** da conta de serviço.

A conta de serviço (ou cliente OAuth) precisa de acesso de gravação à tabela de destino.

### Mapeamento do rastreador de issues

- **Target Table** seleciona a tabela do ServiceNow na qual os registros são gravados: **Security Incident** (`sn_si_incident`, o padrão) ou **Vulnerable Item** (`sn_vul_vulnerable_item`).

### Detalhes do mapeamento de severidade

Para um Security Incident, isso é mapeado para o campo **Impact**; o ServiceNow deriva a Priority do incidente a partir de Impact e Urgency, portanto Urgency espelha o Impact mapeado, a menos que você o mapeie você mesmo. Para um Vulnerable Item, mapeie a severidade para o campo de risco usado pela sua instância. Os padrões abaixo correspondem à escala Impact padrão do SIR (`1` High, `2` Medium, `3` Low) e são editáveis.

- **Severity Field Name**: `impact`
- **Info Mapping**: `3`
- **Low Mapping**: `3`
- **Medium Mapping**: `2`
- **High Mapping**: `1`
- **Critical Mapping**: `1`

### Detalhes do mapeamento de status

Isso é mapeado para o campo **State** do registro. Os valores de State são códigos numéricos que diferem entre as tabelas Security Incident e Vulnerable Item e podem ser personalizados por instância, portanto revise-os de acordo com sua própria configuração. Os padrões abaixo usam os códigos de estado padrão do SIR (`16` Analysis, `3` Closed).

- **Status Field Name**: `state`
- **Active Mapping**: `16`
- **Closed Mapping**: `3`
- **False Positive Mapping**: `3`
- **Risk Accepted Mapping**: `3`

Quando um registro é fechado, o DefectDojo também define o **Close Code** e as **Close Notes** do ServiceNow (`Resolved` para Achados fechados, `False positive` e `Risk accepted` para os estados correspondentes).

### Comportamentos específicos do ServiceNow SecOps

- **Deduplicação** — cada registro é marcado com o identificador do Achado ou Grupo de Achados do DefectDojo em seu `correlation_id`. Antes de criar um registro, o DefectDojo procura um existente por `correlation_id`; uma correspondência é adotada e atualizada em vez de duplicada, de modo que ressincronizações são idempotentes.
- **Atualizações** são publicadas no journal **Work notes** do registro (interno), nunca nos Comentários visíveis ao cliente.
- **Resolver ao excluir** — excluir um Achado no DefectDojo resolve/fecha o registro no ServiceNow (State + Close Code) em vez de excluí-lo; registros nunca são excluídos permanentemente.
- **Campos de referência** — os valores opcionais `cmdb_ci`, `assignment_group` e `assigned_to` podem ser fornecidos como nomes de exibição; o DefectDojo resolve cada um para seu `sys_id`. Um nome que não é resolvido é descartado com um aviso em vez de falhar o envio.

## Shortcut

A integração com o Shortcut permite enviar Achados do DefectDojo como Stories do [Shortcut](https://www.shortcut.com/). As Stories são criadas com o tipo de story Bug e atribuídas a um Team no seu workspace do Shortcut.

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como `https://api.app.shortcut.com`.
- **API Token** deve ser definido como um token de API do Shortcut. Os tokens podem ser gerados no Shortcut em Settings, depois Your Account, depois [API Tokens](https://app.shortcut.com/settings/account/api-tokens).

### Mapeamento do rastreador de issues

- **Team (Group) ID** deve ser definido como o UUID do Team do Shortcut para o qual as Stories serão criadas. Você pode encontrar esse UUID abrindo a página do Team no Shortcut e copiando o identificador da URL, ou chamando a API do Shortcut:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### Detalhes do mapeamento de severidade

Cada valor de severidade é aplicado à Story como um label. Os labels são criados automaticamente no Shortcut caso ainda não existam, portanto os valores padrão abaixo podem ser usados como estão, ou substituídos por nomes de label de sua escolha. Quando a severidade de um Achado muda, o label de severidade antigo é removido da Story e o novo é adicionado.

- **Severity Field Name**: `Label`
- **Info Mapping**: `sev-info`
- **Low Mapping**: `sev-low`
- **Medium Mapping**: `sev-medium`
- **High Mapping**: `sev-high`
- **Critical Mapping**: `sev-critical`

### Detalhes do mapeamento de status

Cada valor de status deve ser definido como o ID numérico de um Workflow State no seu workspace do Shortcut. Os IDs de Workflow State são exclusivos de cada workspace, portanto não há valores padrão. Você pode listar os Workflow States e seus IDs chamando a API do Shortcut:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **Status Field Name**: `Workflow State ID`
- **Active Mapping**: o ID do estado para trabalho em aberto, por exemplo um estado Backlog ou To Do.
- **Closed Mapping**: o ID de um estado do tipo Done. Quando um Achado é excluído no DefectDojo, sua Story é movida para esse estado.
- **False Positive Mapping**: o ID do estado a ser usado para Achados marcados como Falso positivo.
- **Risk Accepted Mapping**: o ID do estado a ser usado para Achados com Risco aceito.

## Freshservice

A integração com o Freshservice permite enviar Achados e Grupos de Achados do DefectDojo como tickets do Freshservice, atribuídos a um Group de agentes de sua escolha.

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como a URL do seu Freshservice: `https://yourcompany.freshservice.com`.
- **API Key** deve ser uma chave de API do Freshservice. Encontre-a clicando na sua foto de perfil (canto superior direito) > **Profile settings** - a chave aparece à direita, abaixo da seção **Delegate Approvals**, depois de você concluir o captcha. Se nenhuma chave for exibida ali, o acesso à API pode estar desabilitado no nível da conta e um administrador precisa habilitá-lo primeiro.
- **Requester Email** deve ser o endereço de e-mail em nome do qual os tickets são solicitados. O Freshservice exige um requester em todo ticket, portanto o DefectDojo cria tickets com esse endereço como requester.

### Mapeamento do rastreador de issues

- **Group ID** deve ser o ID numérico do grupo de agentes do Freshservice ao qual os tickets serão atribuídos. Encontre-o na URL ao visualizar o grupo em **Admin > Agent Groups**.
- **Workspace ID** (opcional) direciona os tickets para um workspace específico em contas com múltiplos workspaces. Deixe em branco para usar o workspace principal.

### Detalhes do mapeamento de severidade

Isso é mapeado para o campo **Priority** do ticket do Freshservice, que usa códigos numéricos (`1` Low, `2` Medium, `3` High, `4` Urgent). Os nomes das prioridades também são aceitos:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `1`
- **Low Mapping**: `1`
- **Medium Mapping**: `2`
- **High Mapping**: `3`
- **Critical Mapping**: `4`

### Detalhes do mapeamento de status

Isso é mapeado para o campo **Status** do ticket, que usa códigos numéricos (`2` Open, `3` Pending, `4` Resolved, `5` Closed). Os nomes dos status também são aceitos:

- **Status Field Name**: `Status`
- **Active Mapping**: `2`
- **Closed Mapping**: `5`
- **False Positive Mapping**: `5`
- **Risk Accepted Mapping**: `3`

Alguns comportamentos específicos do Freshservice a serem observados:

- As atualizações sincronizam o conteúdo completo do ticket - o Freshservice permite editar o assunto e a descrição após a criação.
- Os tickets são fechados em vez de excluídos quando um Achado é removido; tickets já Resolved ou Closed são deixados intactos. Uma nota de resolução é anexada automaticamente no fechamento, portanto contas que exigem uma (uma regra de negócio comum) aceitam o fechamento.
- Algumas contas calculam a priority de um ticket a partir de uma matriz Impact/Urgency ou de uma regra de negócio e ignoram a priority enviada na criação. O DefectDojo detecta isso e reaplica a priority mapeada com uma atualização subsequente, de modo que o mapeamento ainda entra em vigor.

## ServiceDesk Plus

A integração com o ManageEngine ServiceDesk Plus permite enviar Achados e Grupos de Achados do DefectDojo como requests do ServiceDesk Plus, atribuídos a um Group de suporte de sua escolha. Tanto a edição **cloud** (ServiceDesk Plus OnDemand) quanto a **on-premises** são suportadas pela mesma integração - as credenciais fornecidas determinam qual modo é usado.

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como a URL do seu ServiceDesk Plus: `https://sdpondemand.manageengine.com` para a edição cloud (ou seu equivalente regional), ou o endereço do seu servidor para instalações on-premises.

Em seguida, forneça **um** dos dois conjuntos de credenciais:

#### On-premises: Technician Key

- **Technician Key** deve ser uma chave de API gerada para um técnico no seu servidor, em **Admin > General Settings > API**. Deixe os campos de OAuth do Zoho vazios.

#### Cloud: Zoho OAuth

A edição cloud se autentica através do OAuth das Zoho Accounts:

1. Abra o [Zoho API Console](https://api-console.zoho.com/) e crie um **Self Client**.
2. Anote o **Client ID** e o **Client Secret**.
3. Na aba "Generate Code" do Self Client, insira o escopo `SDPOnDemand.requests.ALL`, escolha uma duração e gere o código.
4. Troque o código por um refresh token:

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. Insira o **Client ID**, o **Client Secret** e o **Refresh Token** retornado no formulário da instância. Se sua conta estiver hospedada fora do data center dos EUA, defina o **Token URL** para o endpoint regional das Zoho Accounts (por exemplo, `https://accounts.zoho.eu/oauth/v2/token`).

### Mapeamento do rastreador de issues

- **Group Name** deve ser o nome do grupo de suporte do ServiceDesk Plus ao qual os requests serão atribuídos, exatamente como aparece em **Admin > Users > Support Groups**.

### Detalhes do mapeamento de severidade

Isso é mapeado para o campo **Priority** do request do ServiceDesk Plus por nome, usando os nomes de priority da sua conta:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `Low`
- **Low Mapping**: `Normal`
- **Medium Mapping**: `Medium`
- **High Mapping**: `High`
- **Critical Mapping**: `High`

### Detalhes do mapeamento de status

Isso é mapeado para o campo **Status** do request por nome. Os padrões usam os status embutidos:

- **Status Field Name**: `Status`
- **Active Mapping**: `Open`
- **Closed Mapping**: `Closed`
- **False Positive Mapping**: `Closed`
- **Risk Accepted Mapping**: `On Hold`

Alguns comportamentos específicos do ServiceDesk Plus a serem observados:

- As atualizações sincronizam o conteúdo completo do request - diferente da maioria dos rastreadores, o ServiceDesk Plus permite editar o assunto e a descrição após a criação.
- Os requests são fechados em vez de excluídos quando um Achado é removido; requests já Closed ou Resolved são deixados intactos.
- Se sua conta torna campos obrigatórios no fechamento (por exemplo, uma resolução), um fechamento enviado pelo DefectDojo pode ser rejeitado por essas regras e aparecerá na tabela de erros de integração.

## Zendesk

A integração com o Zendesk permite enviar Achados e Grupos de Achados do DefectDojo como tickets do Zendesk, atribuídos a um Group do Zendesk de sua escolha.

### Configuração da instância

- **Label** deve ser o rótulo que você deseja usar para identificar esta integração.
- **Location** deve ser definido como a URL da sua conta Zendesk, por exemplo `https://your-subdomain.zendesk.com`.
- **Email** deve ser o endereço de e-mail do agente do Zendesk ao qual o token de API pertence.
- **API Token** deve ser definido como um token de API do Zendesk. Um administrador pode criar um no Zendesk Admin Center em **Apps and integrations > APIs > Zendesk API** (o acesso por token deve estar habilitado).

### Mapeamento do rastreador de issues

- **Group ID** deve ser o ID numérico do Group do Zendesk ao qual os tickets serão atribuídos. Você pode encontrá-lo no Admin Center em **People > Team > Groups**, ou na URL ao visualizar o grupo.

### Detalhes do mapeamento de severidade

Isso é mapeado para o campo **Priority** do ticket do Zendesk, que aceita `low`, `normal`, `high` e `urgent`:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `low`
- **Low Mapping**: `low`
- **Medium Mapping**: `normal`
- **High Mapping**: `high`
- **Critical Mapping**: `urgent`

### Detalhes do mapeamento de status

Os tickets do Zendesk suportam os status `new`, `open`, `pending`, `hold`, `solved` e `closed`. Note que `hold` deve ser habilitado na sua conta antes de poder ser usado.

- **Status Field Name**: `Status`
- **Active Mapping**: `new`
- **Closed Mapping**: `solved`
- **False Positive Mapping**: `solved`
- **Risk Accepted Mapping**: `pending`

Alguns comportamentos específicos do Zendesk a serem observados:

- A descrição do ticket é o primeiro comentário no Zendesk e não pode ser editada após a criação, portanto enviar um Achado atualizado sincronizará o assunto, a priority e o status do ticket, mas não as alterações de descrição.
- Os tickets são marcados como `solved` em vez de excluídos quando um Achado é removido; o Zendesk fecha tickets solved automaticamente após um período de tempo.
- `closed` é um status final - tickets fechados não podem ser atualizados de forma alguma, e enviar um Achado cujo ticket foi fechado resultará em um erro.
