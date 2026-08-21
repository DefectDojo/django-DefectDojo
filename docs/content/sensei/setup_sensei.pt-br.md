---
title: Configurar o Sensei
description: Conecte o GitHub, GitLab, Bitbucket ou Azure DevOps e integre um repositório
  para escaneamento hospedado
draft: false
audience: pro
weight: 2
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: o Sensei é um recurso exclusivo do DefectDojo Pro e atualmente está em BETA.</span>

Configurar o Sensei tem duas partes: **conectar um provedor de controle de código-fonte** e, em seguida, **integrar os repositórios** que você deseja escanear. Você precisa de uma função global de **Maintainer** ou **Owner** para fazer isso. O Sensei oferece suporte a:

- **GitHub**: um GitHub App (github.com ou **GitHub Enterprise Server**).
- **GitLab**: um token de acesso (gitlab.com ou self-managed).
- **Bitbucket**: Cloud ou Server/Data Center, via OAuth (recomendado), um token de API da Atlassian ou um token de acesso.
- **Azure DevOps**: um Personal Access Token.

A integração, a configuração, o escaneamento e a correção funcionam da mesma forma para todos os provedores; apenas a conexão inicial é diferente. Esta página aborda [conectar um GitHub App](#connect-a-github-app), [GitHub Enterprise Server](#connect-github-enterprise-server), [GitLab](#connect-gitlab), [Bitbucket](#connect-bitbucket) e [Azure DevOps](#connect-azure-devops); a partir da etapa [Selecionar repositórios](#select-repositories) o processo é compartilhado.

**Add Repositories** no hub do Sensei é o ponto de entrada para ambos os casos. Ele abre um menu listando cada conexão pelo nome: escolha uma para selecionar repositórios a partir dela, ou escolha **Connect a new source** para configurar um provedor que você ainda não conectou. Se nada estiver conectado, o fluxo vai direto para a conexão.

![O menu Add Repositories](images/add_repositories_menu.png)

## Conexões

Uma **conexão** é uma identidade de controle de código-fonte configurada: um registro de GitHub App, um token do GitLab, um workspace do Bitbucket ou uma organização do Azure DevOps. Você integra repositórios a partir de uma conexão, e gerencia ou desconecta essa conexão, na página **Connections** (o botão **Connections** no hub do Sensei).

![Conexões do Sensei](images/connections.png)

A tabela lista o rótulo, a identidade, o número de repositórios integrados, a data de criação e o provedor de cada conexão. Use as ações da linha (o menu à esquerda de cada linha) para gerenciar a conexão em seu provedor, adicionar repositórios a partir dessa conexão, abri-la para edição (**Update credentials**, ou **Manage App & installations** no caso do GitHub), ou desconectá-la.

![Ações da linha de conexão](images/connection_row_menu.png) **Add a connection** nunca mostra os detalhes de uma conexão já existente. Tudo sobre uma conexão que você já tem está em sua própria tela, acessada a partir de sua linha.

### Várias organizações por provedor

Uma instância pode conter **quantas conexões você precisar, para cada provedor**, uma por organização, grupo ou workspace:

- **GitHub:** instale o App em cada organização ou conta de usuário (**Install on another account**). Um único registro de App cobre todas elas. Para manter registros separados, como um host do GitHub Enterprise Server ao lado do github.com, use **Register another GitHub App**. O próprio estado de um App (suas instalações, aprovações de permissão, **Install on another account** e **Disconnect this App**) fica na tela dessa conexão, aberta com **Manage App & installations** em sua linha. Com mais de um registro, um seletor ali alterna entre eles.
- **GitLab:** uma conexão por token de grupo ou de projeto, incluindo várias no mesmo host (`gitlab.com` além de instâncias self-managed).
- **Bitbucket:** uma conexão por workspace.
- **Azure DevOps:** uma conexão por organização, já que um PAT tem escopo de organização.

Cada vez que você passa por **Connect** na página Connections, uma conexão é **adicionada**, então conectar um segundo grupo ou workspace nunca substitui o primeiro. Dê a cada uma um **Connection Label** para diferenciá-las na tabela. Cada repositório registra a conexão pela qual foi integrado, e seus scans, pull requests e correções usam a credencial dessa conexão. Quando existe mais de uma conexão para um provedor, a integração pergunta qual usar, em vez de escolher por você.

Para rotacionar um token, PAT ou app password, use **Update credentials** na linha dessa conexão. A tela que se abre trata de uma única conexão: ela tem o título **Edit connection: \<label\>** e salvar atualiza essa conexão em vez de adicionar outra. Chegar a ela a partir de **Connect** resulta no título **Add a connection**. (As credenciais do GitHub App são gerenciadas no GitHub.)

A **webhook URL de um provedor é compartilhada por todas as suas conexões**, e cada conexão verifica seu próprio secret, então não é necessária uma URL diferente por grupo, workspace ou organização.

> **⚠️ Desconectar é destrutivo:** desconectar uma conexão remove ela **e todos os repositórios integrados por meio dela**. Isso não pode ser desfeito.

## Escolha um provedor de controle de código-fonte

No hub do Sensei, escolha **Add Repositories → Connect a new source** (ou **Connect** na página Connections) para abrir **Add a connection** e, então, escolha seu provedor de controle de código-fonte: **GitHub** (incluindo GitHub Enterprise Server), **GitLab**, **Bitbucket** ou **Azure DevOps**. O fluxo de conexão de cada provedor é descrito abaixo.

![Add a connection, com o provedor de controle de código-fonte escolhido aqui](images/setup_providers.png)

## Conectar um GitHub App

O Sensei funciona inteiramente por meio de um GitHub App. Instale-o na sua organização/conta e o DefectDojo usa tokens de curta duração para abrir PRs, escanear e aplicar correções. Nada para colar, nada para rotacionar.

No hub do Sensei, escolha **Add Repositories → Connect a new source** (ou **Connect** na página Connections) para abrir **Add a connection**.

### Etapa 1: crie o App

Informe a **organização** dona dos repositórios que você deseja escanear (deixe em branco para criar o App na sua conta pessoal) e clique em **Create GitHub App**. O GitHub preenche previamente o nome do app, as URLs e as permissões, então revise-os e confirme.

![Crie o GitHub App](images/setup_create_app.png)

O GitHub abre uma página de confirmação. Clique em **Create GitHub App for `<org>`** para registrar o app sob essa organização.

![Confirme a criação do app no GitHub](images/github_create_app.png)

> **🔑 Dica:** crie o App na mesma organização dona dos repositórios que você pretende escanear. O dono do App é definido no momento da criação.

### Etapa 2: instale o App

De volta ao DefectDojo, o app aparece como *configured*. Clique em **Install on GitHub** para instalá-lo na sua organização.

![A tela própria da conexão, onde o App é instalado e gerenciado](images/setup_install_app.png)

No GitHub, confirme o local da instalação (sua organização), escolha **All repositories** ou **Only select repositories**, e revise as permissões solicitadas. O Sensei precisa de acesso de leitura a actions, issues e metadata, e de acesso de leitura/gravação a checks, code, pull requests, secrets e workflows para poder escanear e abrir PRs de correção. Clique em **Install**.

![Instale o App na sua organização](images/github_install_app.png)

## Conectar o GitLab

O Sensei também oferece suporte ao **GitLab**, tanto para o **gitlab.com** quanto para instâncias **self-managed**. Em vez de um GitHub App, o GitLab se conecta com um **token de acesso de projeto ou grupo** mais um webhook; o Sensei usa esse token para escanear, abrir merge requests e aplicar correções.

No hub do Sensei, escolha **Add Repositories → Connect a new source** (ou **Connect** na página Connections) para abrir **Add a connection** e, então, selecione **GitLab** como provedor de controle de código-fonte.

### Etapa 1: crie um token de acesso

No GitLab, abra o projeto (ou grupo) que você deseja escanear e vá em **Settings → Access tokens → Add new token**:

- **Role:** **Developer**, suficiente para enviar branches de correção e abrir merge requests. Escolha **Maintainer** se as regras de push do projeto exigirem.
- **Scopes:** **`api`** e **`write_repository`**.

Crie o token e copie o valor gerado `glpat-…` (o GitLab mostra ele apenas uma vez).

> **🔑 Dica:** um token de acesso de **grupo** integra qualquer projeto desse grupo; um token de acesso de **projeto** tem escopo restrito a um único projeto.

### Etapa 2: conecte-se

De volta a **Add a connection** com **GitLab** selecionado, preencha:

- **GitLab Base URL:** `https://gitlab.com`, ou a URL da sua instância self-managed (por exemplo, `https://gitlab.example.com`).
- **Access Token:** o token `glpat-…` da Etapa 1.
- **Webhook Secret:** deixe em branco para gerar automaticamente (recomendado). Você adicionará esse secret ao webhook na próxima etapa.

Clique em **Add GitLab connection**. O DefectDojo valida o token, armazena-o criptografado e, então, pode listar projetos, abrir merge requests e executar scans.

### Etapa 3: adicione o webhook

Para que o DefectDojo receba eventos de push, merge request e comentário, adicione um webhook a **cada** projeto do GitLab que você pretende integrar (**Settings → Webhooks → Add new webhook**):

- **URL:** a webhook URL mostrada na tela da conexão (`https://<your-defectdojo-host>/sensei/gitlab/webhooks`).
- **Secret token:** o webhook secret da Etapa 2.
- **Trigger events:** habilite **Push events**, **Merge request events** e **Comments**.

Deixe a verificação SSL habilitada, clique em **Add webhook** e, então, use **Test → Push events** para confirmar que o DefectDojo responde com **HTTP 200**.

Após conectar, clique em **Choose projects** e continue com [Selecionar repositórios](#select-repositories); a integração, a configuração e o escaneamento funcionam da mesma forma que no GitHub.

> **Equivalências no GitLab:** onde este guia diz *pull request*, o GitLab usa um **merge request**; o **status check** do pull request é postado como um **commit status** do GitLab no commit de topo (head commit) do merge request.

## Conectar o GitHub Enterprise Server

O Sensei funciona com o **GitHub Enterprise Server (GHES)** usando o mesmo modelo de GitHub App do github.com. Apenas o host é diferente. Como o fluxo de criação automática via manifesto de App é exclusivo do github.com, no GHES você **cria o App manualmente** no seu host corporativo e depois informa suas credenciais e o host no DefectDojo.

### Etapa 1: crie o App no seu host GHES

Na sua instância do GitHub Enterprise Server, vá em **Settings → Developer settings → GitHub Apps → New GitHub App** e crie um App com as mesmas permissões que o Sensei usa no github.com: leitura para actions, issues e metadata, e leitura/gravação para checks, code, pull requests, secrets e workflows. Aponte o webhook dele para `https://<your-defectdojo-host>/sensei/webhooks`. Gere e baixe uma **chave privada** e anote o **App ID** (e o **Client ID/Secret** do OAuth, se você os configurou).

### Etapa 2: conecte manualmente

Na tela de conexão com **GitHub** selecionado, clique em **Set up manually instead** e preencha:

- **App ID** e **Private Key (PEM)** da Etapa 1 (além de Client ID/Secret e Webhook Secret, se configurados).
- **GitHub Enterprise host:** o host da sua instância, por exemplo `https://github.example.com`. O DefectDojo deriva a API (`/api/v3`) e as origens web a partir dele. Deixe em branco para github.com.

Clique em **Save App credentials**. O DefectDojo valida essas informações contra o seu host corporativo, então instale o App e continue com [Selecionar repositórios](#select-repositories).

> **🔑 Dica:** o host precisa ser acessível a partir do DefectDojo (e o DefectDojo precisa ser acessível a partir do GHES para os webhooks). Hosts apenas internos funcionam bem, desde que ambos consigam se comunicar na sua rede.

## Conectar o Bitbucket

O Sensei oferece suporte ao **Bitbucket Cloud** (`bitbucket.org`) e ao **Bitbucket Server / Data Center** (self-hosted). Três métodos de autenticação não descontinuados são oferecidos; **o OAuth é recomendado**.

No hub do Sensei, escolha **Add Repositories → Connect a new source** (ou **Connect** na página Connections), então selecione **Bitbucket** e seu **deployment** (Cloud ou Server/Data Center) e o tipo de **authentication**.

### Etapa 1: crie a credencial

**OAuth (recomendado):** no Bitbucket, abra **Workspace settings → OAuth consumers → Add consumer**:

- **Callback URL:** a mostrada na tela da conexão (`https://<your-defectdojo-host>/sensei/bitbucket/oauth/callback`).
- **Permissions:** **Account: Read**, **Repositories: Read + Write**, **Pull requests: Read + Write** (adicione **Webhooks: Read + Write** se você for gerenciar webhooks via API).

Salve e, então, copie o **Key** (Client ID) e o **Secret** do consumer.

**API token**: crie um **API token** da Atlassian em `id.atlassian.com` (Account settings → Security → API tokens). Use-o com seu **e-mail da conta Atlassian**.

**Access token**: crie um **Access Token** de repositório ou workspace no Bitbucket e use-o como credencial bearer.

### Etapa 2: conecte-se

De volta à tela de conexão com **Bitbucket** selecionado:

- **OAuth:** cole o **Client ID** e o **Client Secret**, então clique em **Connect with Bitbucket**. Aprove a tela de consentimento; o DefectDojo armazena os tokens resultantes criptografados e os renova automaticamente.
- **API token / Access token:** informe seu **Workspace** (Cloud), seu **e-mail** (apenas para autenticação por API token) e o **token**. Para Server/Data Center, informe a **Base URL** do seu host.

O DefectDojo valida a credencial e, então, pode listar repositórios, abrir pull requests e executar scans.

### Etapa 3: adicione o webhook

Adicione um webhook a **cada** repositório do Bitbucket (**Repository settings → Webhooks → Add webhook**):

- **URL:** a webhook URL mostrada na tela da conexão (`https://<your-defectdojo-host>/sensei/bitbucket/webhooks`).
- **Secret:** o webhook secret mostrado na página (usado para verificação HMAC-SHA256 via `X-Hub-Signature`).
- **Triggers:** **Repository push**, **Pull request** (created, updated, merged, declined) e **Pull request comment created** (para comentários `/fix`).

Após conectar, clique em **Choose repositories** e continue com [Selecionar repositórios](#select-repositories).

> **Especificidades do Bitbucket:** os repositórios são endereçados como `workspace/repo` (Cloud) ou `PROJECTKEY/repo` (Server). O **status check** do pull request é postado como um **build status** do Bitbucket no commit de topo (head commit). O OAuth é o método recomendado porque opera no contexto do usuário (sem as peculiaridades de workspace/username) e se renova automaticamente; app passwords estão descontinuados e não são suportados.

## Conectar o Azure DevOps

O Sensei oferece suporte a **repositórios do Azure DevOps** usando um **Personal Access Token (PAT)**. Os repositórios vivem em uma hierarquia de **organização → projeto → repositório**.

No hub do Sensei, escolha **Add Repositories → Connect a new source** (ou **Connect** na página Connections), então selecione **Azure DevOps**.

### Etapa 1: crie um PAT

No Azure DevOps, abra **User settings → Personal access tokens → New Token**:

- **Organization:** a organização cujos repositórios você deseja escanear.
- **Scopes:** **Code (Read, Write, & Manage)**, que cobre clonagem, envio de branches de correção e abertura de pull requests.

Crie o token e copie-o (o Azure DevOps mostra ele apenas uma vez).

### Etapa 2: conecte-se

De volta à tela de conexão com **Azure DevOps** selecionado, preencha:

- **Base URL:** `https://dev.azure.com`, ou a URL da coleção do seu **Azure DevOps Server**.
- **Organization:** o nome da sua organização.
- **Personal Access Token:** o token da Etapa 1.

Clique em **Connect**. O DefectDojo valida o PAT contra `…/_apis/projects`, armazena-o criptografado e, então, pode listar repositórios, abrir pull requests e executar scans.

### Etapa 3: adicione o service hook

O Azure DevOps autentica seus **Service Hooks** com HTTP Basic, e usa **uma subscription por tipo de evento**. Em **Project settings → Service hooks → Create subscription → Web Hooks**, crie uma subscription para cada um dos eventos **Code pushed**, **Pull request created**, **Pull request updated** e **Pull request merged**, todos com:

- **URL:** a webhook URL mostrada na tela da conexão (`https://<your-defectdojo-host>/sensei/azure/webhooks`).
- **Basic authentication username / password:** os valores mostrados na página.

Após conectar, clique em **Choose repositories** e continue com [Selecionar repositórios](#select-repositories).

> **Especificidades do Azure DevOps:** os repositórios são endereçados como `project/repo` (a organização fica armazenada na conexão). O **status check** do pull request é postado como um **commit status** do Git no commit de topo (head commit).

## Selecionar repositórios

Depois que o App é instalado, o DefectDojo mostra os repositórios aos quais ele tem acesso. Somente os repositórios aos quais o Sensei tem **acesso de push** são listados; a remediação funciona enviando um branch e abrindo um pull request, então repositórios sem acesso de push ficam ocultos. Um pull request é aberto contra o **branch padrão** de cada repositório.

![Selecione os repositórios para integrar](images/setup_repo_picker.png)

Use **Add** para selecionar um ou mais repositórios e, então, clique em **Configure N repo(s)**. Repositórios já integrados são marcados como **Configured** e não podem ser adicionados novamente.

### Um repositório não aparece na lista

O seletor só mostra os repositórios que foram concedidos à conexão. Um repositório ao qual você nunca deu acesso ao Sensei não vai aparecer. Se a conexão cobre um único repositório que já foi integrado, a lista parece não ter nada para adicionar. Amplie o que a conexão pode ver e depois volte a esta etapa:

- **GitHub:** use **Manage repository access for \<account\>** para abrir a página dessa instalação no GitHub, onde você pode adicionar repositórios à instalação. Use **Install on another account** para instalar o App em uma segunda organização ou conta de usuário.
- **GitLab, Bitbucket, Azure DevOps:** a lista tem o escopo definido pela credencial que você conectou. Conceda ao token, app password ou PAT acesso ao projeto (um token de **grupo** do GitLab cobre todos os projetos do grupo), ou adicione uma segunda conexão para outro grupo, workspace ou organização.

## Configurar um repositório

O formulário **Configure Repository** controla como o Sensei escaneia e reporta sobre o repositório.

![Configure um repositório](images/repo_config.png)

- **Scanning Mode (DefectDojo-hosted):** os scans rodam no DefectDojo. Nada é adicionado ao seu repositório; dispare scans sob demanda ou automaticamente via o GitHub App.
- **PR Reporting:** escolha o que o Sensei publica de volta nos pull requests:
  - Postar um status check no pull request.
  - Falhar o check quando achados novos (net-new) forem introduzidos.
  - Postar um comentário-resumo dos resultados em cada commit.
  - Criar automaticamente a baseline do branch base no primeiro PR.
- **Automated Fixes:** habilite *Stage matching findings for one-click auto-fix after each scan* para que o Sensei prepare candidatos automaticamente (veja abaixo).

### Critérios de correção automatizada

Quando as correções automatizadas estão habilitadas, os achados que atendem aos seus critérios são preparados como **candidatos** na página do Sensei após cada scan. Nada é executado (e nenhum custo de LLM é gerado) até que você aprove, a menos que você habilite a remediação automática.

![Critérios de correção automatizada e opções avançadas](images/repo_config_advanced.png)

- **Severity threshold:** achados nesse nível de severidade ou acima se qualificam (escolha *Any* para filtrar apenas por risco).
- **Risk threshold:** achados nesse nível de risco ou acima também se qualificam (combinado com a severidade usando OR).
- **Open fix PRs against branch:** o branch alvo dos pull requests de correção automática; pode ser sobreposto por correção individual quando você aprova cada uma.
- **Exclude findings tagged:** ignora achados que carregam as tags listadas (por exemplo, `no-fix`).
- **Automatically remediate candidates:** quando habilitado, uma verificação em segundo plano (a cada cerca de 5 minutos) abre pull requests de correção para os candidatos preparados desse repositório sem esperar aprovação, até que sua cota de correções seja atingida. Deixe desativado para revisar e aprovar cada candidato você mesmo.

Em **Advanced options** você pode vincular o repositório a um produto/asset existente ou criar um novo, definir a organização e definir uma severidade mínima abaixo da qual os achados não são reportados nem usados no merge gate.

## Integração

Clique em **Onboard for hosted scanning**. O repositório aparece no hub do Sensei com status **Active**, pronto para escanear. A partir daqui, continue em [Corrigindo achados com o Sensei](/sensei/fixing_findings/).
