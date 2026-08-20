---
title: Solução de problemas de erros do Jira (Legado)
description: Corrigindo problemas com uma integração do Jira
weight: 2
aliases:
- /pt-br/issue_tracking/jira/troubleshooting_jira/
- /pt-br/en/share_your_findings/troubleshooting_jira/
---

Aqui estão alguns problemas comuns com a integração do Jira e formas de resolvê-los.

## Não encontro nenhuma configuração do Jira no DefectDojo

Se não houver um menu do Jira na barra lateral, nenhuma seção do Jira nos formulários de Produto / Engajamento e nenhuma opção **Push to Jira** nos Achados, é provável que a integração do Jira ainda esteja desabilitada nas Configurações do Sistema.  O DefectDojo oculta todos os controles do Jira até que ela seja ativada.

Marque **Enable Jira Integration** na página de Configurações do Sistema:

* Open Source: ⚙️ **Configuration \> System Settings**, depois marque **Enable JIRA integration**.  Um **Jira webhook secret** também é necessário antes que o formulário possa ser salvo, então clique no ícone 🔄 para gerar um.  Veja o [Guia de Integração com o Jira](/connectors/os_jira/os__jira_guide/#step-1-enable-the-jira-integration-in-system-settings).
* Pro: **\<Your Edition\> Settings \> System Settings**, depois marque **Enable Jira Integration** em **Jira Integration Settings**.  Veja o [Guia de Integração com o Jira](/connectors/downstream/pro__jira_guide/#step-1-enable-the-jira-integration-in-system-settings).

Se a configuração já estiver habilitada e você ainda não conseguir ver o menu do Jira, pode ser que falte ao seu usuário a Permissão de Configuração **View Jira Instance**, que também é necessária para que o menu apareça.  Ela pode ser atribuída diretamente na página do Usuário ou por meio de um Grupo de Usuários.  Veja [Sobre Permissões e Papéis](/admin/user_management/about_perms_and_roles/#configuration-permissions).

## O DefectDojo não consegue acessar o Jira (ou outros serviços externos) de forma alguma

Se a integração do Jira no DefectDojo falhar com erros de conexão do tipo "connection refused", "no route to host" ou falhas genéricas no handshake TLS — e as credenciais em si forem válidas — sua instância do DefectDojo pode estar atrás de um firewall que exige que o tráfego de saída passe por um proxy HTTPS de encaminhamento (forward proxy).

Para implantações Pro on-prem, defina as variáveis de ambiente `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` na implantação.  O `dojo-compose-cli` propaga essas variáveis automaticamente para os containers `uwsgi`, `celeryworker` e Connector.  Veja [Executando o DefectDojo Atrás de um Proxy HTTPS de Encaminhamento](/onprem_deployment/forward_proxy/) para o passo a passo completo da configuração.

> Nota: definir `HTTPS_PROXY` configura apenas o tráfego de **saída** do DefectDojo.  Isso não afeta a capacidade do Jira de entregar webhooks de **entrada** ao DefectDojo — veja [Alterações feitas em issues do Jira não atualizam os Achados no DefectDojo](#changes-made-to-jira-issues-are-not-updating-findings-in-defectdojo) abaixo para esse caso.

## Não é possível configurar o Jira no DefectDojo devido a erros 404, 401 ou 403
Jira Cloud:
- Consulte a documentação da API REST do Jira Cloud sobre autenticação: https://developer.atlassian.com/cloud/jira/software/basic-auth-for-rest-apis/
- Verifique na linha de comando se as credenciais fornecidas conseguem acessar as issues necessárias no Jira:

```
curl -D- \
   -u <emailaddress>:<personal_access_token> \
   -X GET \
   -H "Content-Type: application/json" \
   https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Por exemplo:
```
curl -D- \
   -u defectdojo@example.com:ATATT1234567890abcdefghijklmnopqrstuvwxyz \
   -X GET \
   -H "Content-Type: application/json" \
   https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Jira Data Center ou Server:
- Consulte a documentação da API REST do Jira Data Center sobre autenticação:
    - https://developer.atlassian.com/server/jira/platform/basic-authentication/ (usuário + senha)
    - https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html (token de acesso pessoal)
- Verifique na linha de comando se as credenciais fornecidas conseguem acessar as issues necessárias no Jira:

```
curl -u username:password -X GET -H "Content-Type: application/json" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Por exemplo:
```
curl -u defectdojo@example.com:123456 -X GET -H "Content-Type: application/json" https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Ao usar tokens de acesso pessoal:
```
curl -H "Authorization: Bearer <personal_access_token>" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Por exemplo:
```
curl -H "Authorization: Bearer ATATT1234567890abcdefghijklmnopqrstuvwxyz" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

## Contas de Serviço do Jira Não São Suportadas

Contas de Serviço do Jira Cloud (criadas pelo console de administração da Atlassian) usam um host de API diferente das contas de usuário padrão e **atualmente não são suportadas** pela integração do Jira no DefectDojo. Tentar usar um token de API de Conta de Serviço ou credenciais OAuth 2.0 de uma Conta de Serviço resultará em erros HTTP 403.

Para configurar a integração do Jira, crie uma conta de usuário padrão do Jira (com um endereço de e-mail válido) e gere um token de API a partir dessa conta. Se quiser identificar claramente as issues criadas pelo DefectDojo, crie um usuário dedicado com um nome como "DefectDojo" e use o token de API dessa conta para a integração.

## Não encontro um Epic Name ID para o meu Space
Determinados Spaces no Jira, como os Team-Managed Spaces, não usam Epics e, portanto, não terão um Epic Name ID.  Nesse caso, defina o Epic Name ID como 0 no DefectDojo.

## Achados em que uso 'Push To Jira' não aparecem no Jira
Usar o fluxo 'Push To Jira' dispara um processo assíncrono; no entanto, uma Issue deve ser criada no Jira bem rapidamente depois que 'Push To Jira' é acionado.

* Verifique suas notificações do DefectDojo para ver se o processo foi bem-sucedido.  Se o push falhar, você receberá uma resposta de erro do Jira em suas notificações.

Motivos comuns pelos quais issues não são criadas:
* O Default Issue Type selecionado não é utilizável com o Space do Jira
* As issues no Space possuem atributos obrigatórios que impedem sua criação pelo DefectDojo (o que pode ser tratado por meio de Custom Fields no Jira)


## Erro: Produto Mal Configurado ou sem permissões no Jira?

Essa mensagem de erro pode aparecer ao tentar adicionar uma configuração do Jira criada a um Produto.  O DefectDojo tentará validar uma conexão com o Jira e, se essa conexão falhar, exibirá essa mensagem de erro.

* Verifique se suas credenciais do Jira têm permissão para criar issues no Space do Jira selecionado.
* O campo "Project Key" precisa ser um Space válido do Jira. As issues do Jira podem usar várias Keys diferentes dentro de um único Space; a forma mais fácil de confirmar sua Project Key é observar a URL daquele Space específico do Jira: em geral, ela será parecida com `https://xyz.atlassian.net/jira/core/projects/JTV/board`.  Nesse caso, `JTV` é a Space Key.

## Alterações feitas em issues do Jira não atualizam os Achados no DefectDojo

* Comece confirmando que o receptor de webhook do DefectDojo está configurado corretamente e consegue receber atualizações com sucesso.

* Certifique-se de que o certificado SSL usado pelo Defect Dojo seja confiável para o JIRA. Para o JIRA Cloud, você deve usar [um certificado SSL/TLS válido, assinado por uma autoridade certificadora globalmente confiável](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

* Se você estiver tentando enviar alterações de status, confirme se os mapeamentos de transição do Jira estão configurados corretamente (Reopen / Close Transition IDs).

* [Teste](https://support.atlassian.com/jira/kb/testing-webhooks-in-jira-cloud/) seu webhook do JIRA usando um endpoint público como Pipedream ou Beeceptor:

* Confirme se o Achado está realmente vinculado à issue do Jira. Se a issue não estiver vinculada a um Achado do DefectDojo, a requisição de webhook ainda é aceita (HTTP `200`), mas nenhum Achado é atualizado.

* Lembre-se de que o endpoint **sempre retorna HTTP `200`**, independentemente de uma atualização ter sido aplicada ou não. Um `200` do lado de quem envia (um webhook de sistema ou uma regra de Jira Automation) não confirma que a alteração chegou a um Achado — verifique o corpo da resposta e os logs do DefectDojo para ver o resultado real.

* Se você estiver usando o **Jira Automation** (*Send web request*) em vez de um webhook de sistema, verifique o seguinte:
    * O **Body** da requisição está definido como **Custom data** e inclui um `webhookEvent` de nível superior igual a `"jira:issue_updated"` ou `"comment_created"`. As opções de body **Empty** e **Jira issue data** omitem esse campo, e o DefectDojo ignora qualquer requisição cujo `webhookEvent` não reconheça.
    * `Content-Type: application/json` está definido na requisição — o DefectDojo rejeita qualquer outro content type.
    * Para atualizações de issue, `issue.id` é o ID **numérico** da issue do Jira (`{{issue.id}}`), não a issue key, e os campos `resolution` e `updated` estão ambos presentes (`resolution` pode ser `null`). A ausência de `resolution`/`updated` faz com que a requisição seja ignorada silenciosamente.
    * Para comentários, a URL `comment.self` contém o `{{issue.id}}` numérico no segmento `.../issue/<id>/comment/...`, e tanto `body` quanto `updateAuthor` estão presentes.
    * Se os comentários não estiverem aparecendo, verifique a **prevenção de loop**: o DefectDojo ignora um comentário quando seu autor corresponde à conta do Jira que o DefectDojo usa para publicar comentários. Execute a regra de Automation como um usuário diferente do Jira se quiser que esses comentários sejam ingeridos.
    * Use a prévia de payload do Automation para confirmar que os smart values são resolvidos conforme esperado — seus nomes podem variar entre instâncias do Jira.

## Epics do Jira não estão sendo criados

`"Field 'customfield_xyz' cannot be set. It is not on the appropriate screen, or unknown."`

A integração do Jira no DefectDojo precisa de um valor de customfield para 'Epic Name'.  No entanto, as configurações do seu Projeto podem não usar 'Epic Name' como campo ao criar Epics.  A Atlassian fez uma alteração em [agosto de 2023](https://community.atlassian.com/t5/Jira-articles/Upcoming-changes-to-epic-fields-in-company-managed-projects/ba-p/1997562) que combinou os campos 'Epic Name' e 'Epic Summary'.

Spaces mais novos do Jira podem não usar esse campo ao criar Epics por padrão, o que resulta nessa mensagem de erro.

Para corrigir esse problema, você pode adicionar o campo 'Epic Name' à tela de criação de issues do seu Projeto:

1. Tente criar um Epic manualmente no Jira (pela interface do Jira).
2. Abra o menu "..."
3. Clique em 'Find Your Field'
4. Digite 'Epic Name'
5. Adicione Epic Name como campo a essa tela específica, seguindo as instruções do Jira.

![image](images/epic_name_error.png)

## Configurando Retentativas e Timeouts de Conexão do JIRA

A integração do JIRA no DefectDojo inclui configurações de retentativa (retry) e timeout configuráveis para lidar com limitação de taxa (rate limiting) e problemas de conexão. Essas configurações são importantes para manter a responsividade do sistema, especialmente ao usar workers do Celery.

### Variáveis de Configuração Disponíveis

As seguintes variáveis de ambiente controlam o comportamento da conexão com o JIRA:

- **`DD_JIRA_MAX_RETRIES`** (padrão: `3`): número máximo de tentativas de retentativa para erros recuperáveis. A integração tentará novamente automaticamente em caso de HTTP 429 (Too Many Requests), HTTP 503 (Service Unavailable) e erros de conexão. Veja a [documentação de rate limiting do JIRA](https://developer.atlassian.com/cloud/jira/platform/rate-limiting/) para mais informações.

- **`DD_JIRA_CONNECT_TIMEOUT`** (padrão: `10` segundos): timeout de conexão para estabelecer uma conexão com o servidor JIRA.

- **`DD_JIRA_READ_TIMEOUT`** (padrão: `30` segundos): timeout de leitura para aguardar uma resposta do servidor JIRA depois que a conexão é estabelecida.

**Nota sobre Rate Limiting**: a biblioteca jira tem um tempo máximo de espera embutido de 60 segundos para retentativas de rate limiting. Se o cabeçalho `Retry-After` do JIRA indicar um tempo de espera maior que 60 segundos, a requisição falhará e não será repetida. Essa é uma limitação da versão da biblioteca jira atualmente em uso.

### Por que valores conservadores são importantes

**Importante**: recomenda-se usar valores conservadores (mais baixos) para essas configurações. Veja o motivo:

1. **Bloqueio de Tarefas do Celery**: as operações do JIRA no DefectDojo são executadas como tarefas assíncronas do Celery. Quando uma tarefa está aguardando um atraso de retentativa, ela bloqueia esse worker do Celery de processar outras tarefas.

2. **Esgotamento do Pool de Workers**: se várias operações do JIRA estiverem em retentativa com atrasos longos, você pode esgotar rapidamente o pool de workers do Celery, fazendo com que outras tarefas (não apenas as relacionadas ao JIRA) fiquem em fila de espera.

3. **Responsividade do Sistema**: atrasos de retentativa longos podem fazer o sistema parecer sem resposta, especialmente durante interrupções do JIRA ou eventos de rate limiting.

O rate limiting do JIRA é novo, então nos conte no Slack ou no GitHub o que funciona melhor para você.

## Jira e DefectDojo estão fora de sincronia

Às vezes o Jira está fora do ar, ou o DefectDojo está fora do ar, ou houve um bug em um webhook. Nesse caso, o Jira pode ficar fora de sincronia com o DefectDojo. Se isso acontecer com muitas issues, a reconciliação manual pode não ser viável. Para esse cenário, existe o comando de gerenciamento 'jira_status_reconciliation'.

Como esse comando exige acesso ao backend, ele não está disponível para usuários Cloud do DefectDojo Pro; nesse caso, entre em contato com nossa equipe de Suporte para obter ajuda com esse problema.

{{< highlight bash >}}
usage: manage.py jira_status_reconciliation [-h] [--mode MODE] [--product PRODUCT] [--engagement ENGAGEMENT] [--dryrun] [--version] [-v {0,1,2,3}]

Reconcile finding status with JIRA issue status, stdout will contain semicolon seperated CSV results.
Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped.

optional arguments:
  -h, --help            show this help message and exit
  --mode MODE           - reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change
                        timestamp in both systems to determine which one is the correct status
                        - push_status_to_jira: update JIRA status for all JIRA issues
                        connected to a Defect Dojo finding (will not push summary/description, only status)
                        - import_status_from_jira: update Defect Dojo
                        finding status from JIRA
  --product PRODUCT     Only process findings in this product (name)
  --engagement ENGAGEMENT
                        Only process findings in this product (name)
  --dryrun              Only print actions to be performed, but make no modifications.
  -v {0,1,2,3}, --verbosity {0,1,2,3}
                        Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, 3=very verbose output
{{< /highlight >}}

Isso pode ser executado a partir do container docker uwsgi usando:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation'
{{< /highlight >}}

A saída de DEBUG pode ser obtida via `-v 3`, mas apenas depois de aumentar o nível de log para DEBUG no seu arquivo settings.dist.py ou local_settings.py

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation -v 3'
{{< /highlight >}}

Ao final do comando, um resumo em CSV separado por ponto e vírgula será exibido. Isso pode ser capturado redirecionando a saída padrão (stdout) para um arquivo:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation > jira_reconciliation.csv'
{{< /highlight >}}
