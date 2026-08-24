---
title: Referência do Sensei
description: Status, ações de linha, cotas e solução de problemas
draft: false
audience: pro
weight: 5
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: o Sensei é um recurso exclusivo do DefectDojo Pro e atualmente está em BETA.</span>

Uma referência rápida para os status, ações e limites que você encontrará ao usar o Sensei.

## Status do repositório

O status exibido para um repositório integrado no hub do Sensei:

| Status | Significado |
|--------|---------|
| **Active** | Integrado e pronto para verificação. |
| **Pull Request Open** | O Sensei tem um pull request aberto no repositório. |
| **Pull Request Closed** | Um pull request do Sensei foi fechado. |
| **Error** | A última operação falhou: verifique o Scan Activity para identificar a causa raiz. |
| **Not Configured** | O repositório está conectado, mas ainda não configurado. |

## Status de candidatos e correções

Os candidatos a correção automática e os registros de correção passam pelos seguintes estados:

| Status | Significado |
|--------|---------|
| **Candidate** | Preparado pelos critérios de correção automática de uma verificação. Nada é executado até que você aprove. |
| **In Progress** | Aprovado: o Sensei está gerando a correção e abrirá um pull request. |
| **PR Open** | Um pull request de correção está aberto; o selo aponta para ele. |
| **Failed** | A correção não pôde ser concluída; permanece listada para não desaparecer silenciosamente. |

## Ações de linha do repositório

Cada repositório integrado tem um menu de ações de linha no hub do Sensei:

![Ações de linha do repositório](images/repo_row_menu.png)

- **Scan now:** inicia uma verificação sob demanda (abre o seletor de branch).
- **Scan history:** exibe as verificações anteriores deste repositório.
- **Configure:** reabre o formulário de configuração (relato em PRs, correções automatizadas, vínculo com o produto).
- **Re-stage candidates:** reavalia os achados do repositório em relação aos critérios de correção automática e prepara novos candidatos.
- **Delete:** remove o repositório do Sensei. Isso interrompe a verificação dele; não exclui o ativo ou os achados subjacentes.

## Cotas e medição

O uso do Sensei é medido em relação à sua licença DefectDojo Pro, exibido como medidores no topo do hub:

- **Fixes:** correções aplicadas em relação ao seu limite pré-pago. Aprovar um candidato ou disparar uma correção consome dessa cota; quando ela se esgota, novas correções são bloqueadas (um banner de aviso aparece) até que o limite seja aumentado.
- **Onboarded Repositories:** repositórios integrados em relação ao seu limite de repositórios. Quando ele é atingido, a integração de novos repositórios é bloqueada.

Para aumentar um limite, entre em contato com sua equipe de conta do DefectDojo.

## Especificidades do GitLab

O GitLab é suportado junto com o GitHub (gitlab.com e self-managed). O comportamento de verificação e correção é idêntico; estes são os detalhes específicos do GitLab:

- **Conexão:** um **token de acesso de projeto ou grupo** (função **Developer**, ou **Maintainer** se as regras de push exigirem) com os escopos **`api`** e **`write_repository`**, e não um GitHub App. Veja [Configurar o Sensei](/sensei/setup_sensei/#connect-gitlab).
- **Webhook:** cada projeto integrado precisa de um webhook para `…/sensei/gitlab/webhooks` (com o segredo da conexão) inscrito nos eventos **Push**, **Merge request** e **Comment**. Adicionar um webhook exige **Maintainer**/**Owner** no projeto.
- **Merge requests, não pull requests:** as correções abrem um **merge request** contra a branch padrão; o comentário `/fix` funciona nas notas do merge request.
- **Gate de commit-status:** a verificação de status do PR é um **commit status** do GitLab no commit de topo (head commit) do merge request: `running` durante a verificação, depois `success` ou `failed` (fail-on-new). O GitLab não tem estado *neutral*, portanto uma verificação **não bloqueante** que ainda tem achados mostra um status **verde**; a nota de resumo traz os detalhes dos achados.
- **Self-managed:** aponte a **GitLab Base URL** para a sua instância; o DefectDojo clona e chama a API nesse host.

## Especificidades do Bitbucket

O Bitbucket **Cloud** e **Server/Data Center** são suportados. O comportamento de verificação e correção é idêntico; estes são os detalhes específicos do Bitbucket:

- **Conexão:** **OAuth** (recomendado), um **token de API** da Atlassian (usado com o e-mail da sua conta), ou um **token de acesso** de repositório/workspace. Veja [Configurar o Sensei](/sensei/setup_sensei/#connect-bitbucket). Senhas de aplicativo (app passwords) estão descontinuadas e não são suportadas.
- **Escopo de workspace (Cloud):** tokens de API/acesso são vinculados a um workspace, portanto um **workspace** é obrigatório para o Cloud; o OAuth é em contexto de usuário e descobre automaticamente os workspaces acessíveis.
- **Webhook:** cada repositório integrado precisa de um webhook para `…/sensei/bitbucket/webhooks` (com o segredo da conexão, verificado via HMAC-SHA256 `X-Hub-Signature`) inscrito nos eventos **Push**, **Pull request** (created/updated/merged/declined) e **Pull request comment**.
- **Gate de build-status:** a verificação de status do PR é publicada como um **build status** do Bitbucket no commit de topo (`INPROGRESS` → `SUCCESSFUL`/`FAILED`). O Bitbucket não tem estado *neutral*, então uma verificação não bloqueante é mapeada para `SUCCESSFUL` e o comentário de resumo traz o detalhe. O link do build-status precisa ser uma URL pública, portanto usa o host do seu DefectDojo.
- **Nomes de repositório:** `workspace/repo` (Cloud) ou `PROJECTKEY/repo` (Server/Data Center).
- **Server/Data Center:** defina a **Base URL** para o seu host; o DefectDojo usa a API REST v1.0 e os caminhos git `/scm/…`.

## Especificidades do Azure DevOps

O Azure DevOps Repos é suportado por meio de um **Personal Access Token**. O comportamento de verificação e correção é idêntico; estes são os detalhes específicos do Azure:

- **Conexão:** um **PAT** com o escopo **Code (Read, Write, & Manage)**, além da **organization**. Os aplicativos OAuth do Azure DevOps estão sendo descontinuados, portanto um PAT é a credencial recomendada. Veja [Configurar o Sensei](/sensei/setup_sensei/#connect-azure-devops).
- **Webhook:** os **Service Hooks** do Azure autenticam com HTTP **Basic** (não HMAC) e usam **uma assinatura por evento**. Crie assinaturas para `…/sensei/azure/webhooks` para **Code pushed** e **Pull request created/updated/merged**, com o usuário/senha Basic da conexão.
- **Gate de commit-status:** a verificação de status do PR é publicada como um **commit status** do Git no commit de topo.
- **Nomes de repositório:** `project/repo` (a organization fica armazenada na conexão).
- **Azure DevOps Server:** defina a **Base URL** para a URL da sua collection on-premises.

## Especificidades do GitHub Enterprise Server

O GitHub Enterprise Server usa o **mesmo modelo de GitHub App** do github.com; apenas o host é diferente:

- **Conexão:** como o fluxo de criação automática via App-manifest é exclusivo do github.com, crie o App **manualmente** no seu host GHES e informe suas credenciais mais o **Enterprise host** por meio de **Set up manually**. Veja [Conectar o GitHub Enterprise Server](/sensei/setup_sensei/#connect-github-enterprise-server). O DefectDojo deriva a API (`/api/v3`) e as origens web a partir do host.
- **Coexistência:** uma conexão de App do github.com e uma conexão de App do GHES podem ser configuradas na mesma instância; cada repositório é resolvido para a conexão pela qual foi integrado.
- **Alcançabilidade:** o DefectDojo precisa alcançar o host da API do GHES, e o GHES precisa alcançar o endpoint `…/sensei/webhooks` do DefectDojo (hosts internos funcionam bem se ambos os lados conseguirem se conectar).

## Solução de problemas

- **O botão Sensei em um achado mostra "Configure Product."** O produto do achado não está integrado. Clique nele para integrar um repositório a esse produto e depois volte ao achado.
- **Uma correção mostra "Failed" em Auto-fix Candidates ou Scan Activity.** Abra o **Scan Activity** e verifique o **Root Cause** / **Details** dessa execução. Correções com falha permanecem listadas para não desaparecerem antes de produzir um PR; você pode preparar novamente (re-stage) e tentar de novo.
- **Um repositório não aparece na integração (onboarding).** Somente os repositórios que a conexão consegue acessar são exibidos. No **GitHub**, confirme se o App está instalado na organização correta e se o acesso a repositórios dele inclui o repositório. No **GitLab**, confirme se o escopo do token de acesso cobre o projeto. No **Bitbucket Cloud**, confirme se o **workspace** está definido (os tokens são vinculados a um workspace). No **Azure DevOps**, confirme se a organization do PAT corresponde e se o escopo **Code** foi concedido.
- **As verificações ou correções nunca começam após um webhook.** Confirme se o webhook do repositório aponta para o receptor do provedor (`…/sensei/{gitlab,bitbucket,azure}/webhooks`, ou `…/sensei/webhooks` para o GitHub) com o segredo/credenciais corretos, e se está inscrito nos eventos de push + pull-request (+ comment). As **entregas recentes** do provedor devem mostrar `HTTP 200`. As execuções disparadas por webhook ocorrem apenas para repositórios integrados no modo **hosted**; um push para uma branch que não é a padrão é verificado por meio do seu pull request, não isoladamente.
- **Nada acontece depois de uma verificação.** Verifique se as correções automatizadas estão habilitadas (e se seus limiares de severidade/risco correspondem aos achados) na configuração do repositório, e se sua cota de **Fixes** não está esgotada.

> **🔎 Ainda em BETA:** o Sensei está evoluindo rapidamente. Se o comportamento não corresponder a este guia, consulte o [changelog do Pro](/releases/pro/changelog/) para ver mudanças recentes.
