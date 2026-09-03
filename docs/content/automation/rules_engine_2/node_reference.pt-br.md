---
title: Referência de Nós
description: Todos os nós com que o Rules Engine 2.0 vem, e o que cada um faz
weight: 3
audience: pro
aliases:
- /pt-br/automation/rules_engine_v2/node_reference/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: o Rules Engine 2.0 é um recurso exclusivo do DefectDojo Pro.</span>

O Rules Engine 2.0 vem com 25 nós em quatro categorias. Esta página documenta todos eles.

Salvo indicação contrária, um nó recebe uma entrada, produz uma saída chamada `out`, e repassa a essa saída cada item que recebeu. Isso importa quando você encadeia nós: um nó de Achados altera o Achado e então repassa o item adiante, de modo que vários deles em sequência são todos aplicados.

## Gatilhos

Todo grafo tem exatamente um gatilho, e apenas um gatilho pode iniciar uma execução. Os três produzem itens de Achado, e os três recebem um **Scope** que restringe quais Achados eles produzem. Veja [Construindo Regras](../building_rules/) para saber como o escopo funciona.

### Em Evento de Achado

`trigger.finding`

É executado quando Achados são criados, atualizados, fechados ou reabertos.

| Setting | Default | Notes |
|---------|---------|-------|
| **Event** | `created` | Qual mudança do Achado ativa esta regra: `created`, `updated`, `closed`, `reopened`, ou `any` para as quatro. |
| **Scope** | vazio | Quais Achados esta regra considera. Vazio significa todo Achado que o proprietário da regra pode ver. |

Os Achados indicados pelo evento são comparados ao escopo antes de entrarem no grafo, de modo que o evento decide *quando* e o escopo decide *quais*.

### Em uma Programação

`trigger.schedule`

Varre todos os Achados no escopo em uma programação. A programação é configurada na regra e é limitada a marcas de quinze em quinze minutos.

| Setting | Default | Notes |
|---------|---------|-------|
| **Scope** | vazio | Quais Achados esta regra considera. |

### Execução Manual

`trigger.manual`

Varre todos os Achados no escopo quando você clica em **Run** na regra.

| Setting | Default | Notes |
|---------|---------|-------|
| **Scope** | vazio | Quais Achados esta regra considera. |

## Lógica

### Se / Filtro

`filter.if`

Direciona cada item para o ramo **true** ou **false**, de acordo com condições. Este é o único nó com duas saídas, e é assim que um grafo se ramifica.

| Setting | Default | Notes |
|---------|---------|-------|
| **Conditions** | vazio | Cada linha é um caminho, um operador e um valor. Veja [Condições](../building_rules/#conditions). |
| **Match** | `all` | Se toda condição precisa ser verdadeira (`all`), ou apenas uma delas (`any`). |

Uma lista de condições vazia passa tudo para o ramo true. Os dois ramos são opcionais: deixar o ramo false sem conexão simplesmente descarta os itens que falharam.

### Limite

`flow.limit`

Passa os primeiros N itens e descarta o restante. Útil como válvula de segurança enquanto você está testando uma regra, e para limitar quantos tickets ou mensagens uma única execução pode produzir.

| Setting | Default | Notes |
|---------|---------|-------|
| **Keep First** | `100` | Quantos itens repassar. |

### Deduplicar Dentro da Execução

`flow.dedupe_batch`

Mantém o primeiro item por chave e descarta os posteriores que carregam a mesma chave. Restrito à execução, então ele deduplica dentro de uma única execução, e não entre execuções.

| Setting | Default | Notes |
|---------|---------|-------|
| **Key Path** | `finding.hash_code` | O caminho do item cujo valor identifica uma duplicata. |

Um uso comum é `finding.component_name`, para notificar uma vez por componente afetado em vez de uma vez por Achado.

## Achados

Esses nós alteram Achados. Toda alteração é atribuída de volta à regra, à execução e ao nó que a fez, e aparece na linha do tempo de proveniência do Achado.

### Definir Severidade

`finding.set_severity`

Define a severidade, e recalcula a data de SLA e a prioridade com base nela.

| Setting | Options |
|---------|---------|
| **Severity** | `Critical`, `High`, `Medium`, `Low`, `Info` |

### Definir um Campo

`finding.set_field`

Define, anexa ao final de, ou insere no início de um campo de texto.

| Setting | Default | Notes |
|---------|---------|-------|
| **Field** | nenhum | Um de `component_name`, `component_version`, `cvssv3`, `cwe`, `description`, `file_path`, `impact`, `mitigation`, `service`, `title`. |
| **Mode** | `set` | `set`, `append` ou `prepend`. Um vetor CVSSv3 só pode ser substituído. |
| **Value** | nenhum | O texto a escrever. Suporta placeholders no estilo `{{finding.title}}`. |

### Definir Status

`finding.set_status`

Move o Achado para um status.

| Setting | Default | Notes |
|---------|---------|-------|
| **Status** | nenhum | `active`, `inactive`, `verified`, `unverified`, `false_positive`, `mitigated`, `reopen`. |
| **Note** | vazio | Uma nota opcional registrada junto com a mudança de status. |

### Adicionar Tags

`finding.add_tags`

Adiciona tags ao Achado. As tags existentes são mantidas.

| Setting | Notes |
|---------|-------|
| **Tags** | Separadas por vírgula. Suporta placeholders no estilo `{{product.name}}`, para que você possa marcar com dados do Achado. |

### Adicionar uma Nota

`finding.add_note`

Adiciona uma nota ao Achado.

| Setting | Notes |
|---------|-------|
| **Note** | O texto da nota. Suporta placeholders. |

### Definir Responsáveis

`finding.set_owners`

Torna um grupo responsável pelo Achado.

| Setting | Notes |
|---------|-------|
| **Group** | O grupo dono desses Achados. |

### Definir Revisores

`finding.set_reviewers`

Coloca o Achado em revisão pelos usuários selecionados.

| Setting | Notes |
|---------|-------|
| **Reviewers** | Um ou mais usuários que devem revisar esses Achados. |

### Aceitar Risco

`finding.risk_accept`

Aceita simplesmente o risco do Achado, ou o adiciona a um registro de aceitação de risco.

| Setting | Default | Notes |
|---------|---------|-------|
| **How** | `simple` | `simple` define aceitação de risco simples no Achado. `acceptance` o adiciona a um registro de aceitação de risco. |
| **Accepted** | ativado | Exibido para `simple`. Desative para desfazer a aceitação do risco. |
| **Risk Acceptance** | nenhum | Exibido para `acceptance`. A qual aceitação de risco adicionar esses Achados. |

### Definir Política de Mitigação

`finding.set_mitigation_policy`

Define a política de mitigação sob a qual o Achado é corrigido.

| Setting | Notes |
|---------|-------|
| **Mitigation Policy** | A política a aplicar. |

### Alterar Prioridade

`finding.set_priority`

Define a prioridade, ou a ajusta aritmeticamente. Isso substitui a prioridade calculada.

| Setting | Default | Notes |
|---------|---------|-------|
| **Operation** | `set` | `set`, `add`, `subtract`, `multiply`, `divide`. |
| **Value** | nenhum | A prioridade a definir, ou a quantidade a ajustar. |

### Definir Risco

`finding.set_risk`

Define o risco, substituindo o calculado.

| Setting | Options |
|---------|---------|
| **Risk** | `Low`, `Medium`, `Needs Action`, `Urgent` |

## Saída

Nós de saída são os nós que saem do DefectDojo. Cada um deles registra uma [Entrega](../deliveries/) antes de qualquer coisa ser enviada, e cada um deles respeita o modo **Simulate** ou **Live** da regra.

Vários deles oferecem a mesma opção **One Message per Finding**. Desativada, o nó envia uma mensagem descrevendo o lote inteiro, com uma divisão por severidade e uma lista limitada de Achados. Ativada, ele envia uma mensagem por Achado.

Um nó que envia uma mensagem por Achado para por padrão após 1.000 envios em uma única execução, e registra uma entrada ignorada visível dizendo sobre quantos Achados ele não enviou. Veja [Configuração](../configuration/#per-finding-send-ceiling).

### Quando um canal está indisponível

Um nó de saída depende de algo externo à regra: um token do Slack, um webhook do Microsoft Teams, uma configuração do JIRA, um conector licenciado. Quando isso está ausente ou desligado, o nó não consegue funcionar, e o Rules Engine 2.0 avisa disso em três momentos diferentes, em vez de falhar silenciosamente:

* **Na paleta**, um nó indisponível é marcado como tal, com o motivo, antes de você arrastá-lo para a tela.
* **Ao salvar**, um grafo contendo um nó indisponível é recusado. Esse é o momento em que alguém está presente para escolher outro.
* **Em tempo de execução**, a entrega é **ignorada** com o motivo anexado, não falha. Uma regra salva enquanto o Slack estava ativo não deveria começar a apresentar erros no dia em que alguém desativa o Slack. O registro honesto é uma entrega ignorada dizendo que o Slack está desligado.

### Criar uma Issue do JIRA

`ticket.jira`

Cria ou atualiza a issue do JIRA do Achado.

| Setting | Default | Notes |
|---------|---------|-------|
| **Skip Findings That Already Have an Issue** | ativado | Deixa intactos os Achados que já têm uma issue do JIRA. |
| **Update an Existing Issue** | desativado | Exibido quando a opção acima está desativada. Envia os Achados que já têm uma issue, para que o JIRA seja atualizado. |

O resumo, a descrição e a prioridade vêm da configuração do JIRA do produto, não deste nó. Um ticket criado por uma regra é, portanto, idêntico a um criado por push all issues.

### Criar um Ticket Downstream

`ticket.downstream`

Cria ou atualiza um ticket através de um [Downstream Connector](/connectors/downstream/about/).

| Setting | Default | Notes |
|---------|---------|-------|
| **Issue Trackers** | `auto` | `auto` usa os rastreadores de issues atribuídos ao engajamento ou ao produto. `mapping` direciona para um mapeamento específico. |
| **Issue Tracker Mapping** | nenhum | Exibido para `mapping`. Para qual mapeamento enviar. |
| **Operation** | `create` | `create` um ticket, ou `update` o que já existe. Uma atualização sem ticket existente o cria. |
| **Skip Findings That Already Have a Ticket** | ativado | Deixa intactos os Achados que já têm um ticket no mapeamento de destino. |

A regra substitui as configurações automáticas de push da atribuição: os filtros de severidade e apenas-ativos não são aplicados uma segunda vez aqui. Um Achado cujo ticket já existe é ignorado, não importa como aquele ticket tenha sido criado.

### Enviar uma Mensagem no Slack

`notify.slack`

Publica em um canal do Slack através de um Conector de Mensagens. A conexão carrega o token do bot; as configurações do Slack de toda a instância em **System Settings** não são usadas e não servem como alternativa.

| Setting | Default | Notes |
|---------|---------|-------|
| **Connection** | nenhuma | Um [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) desse tipo. Obrigatório. |
| **Destination** | vazio | Exibido assim que uma conexão é escolhida. Os campos dependem do fornecedor da conexão. |
| **One Message per Finding** | desativado | Desativado envia uma mensagem sobre o lote. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Renderizado por Achado. |
| **Findings Listed in the Digest** | `10` | Exibido para mensagens em lote. Quantos Achados a mensagem lista antes de dizer quantos mais existiam. |

### Enviar uma Mensagem no Microsoft Teams

`notify.msteams`

Publica um cartão através de um Conector de Mensagens. A conexão carrega a URL do fluxo de trabalho do Power Automate; o webhook do Teams de toda a instância em **System Settings** não é usado e não serve como alternativa.

| Setting | Default | Notes |
|---------|---------|-------|
| **Connection** | nenhuma | Um [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) desse tipo. Obrigatório. |
| **Destination** | vazio | Exibido assim que uma conexão é escolhida. Os campos dependem do fornecedor da conexão. |
| **One Message per Finding** | desativado | Desativado envia um cartão sobre o lote. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Renderizado por Achado. |
| **Findings Listed in the Digest** | `10` | Exibido para mensagens em lote. |

### Enviar um E-mail

`notify.email`

Envia e-mail para uma lista fixa de endereços através de um Conector de Mensagens. Os destinatários são o destino da conexão.

| Setting | Default | Notes |
|---------|---------|-------|
| **Connection** | nenhuma | Um [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) desse tipo. Obrigatório. |
| **Destination** | vazio | Exibido assim que uma conexão é escolhida. Os campos dependem do fornecedor da conexão. |

| **Subject** | `[DefectDojo] {{ctx.count}} finding(s) from rule {{ctx.rule_name}}` | Renderizado uma vez por mensagem. |
| **Body** | um corpo HTML contendo `{{ctx.findings_html}}` | HTML. `{{ctx.findings_html}}` renderiza a lista de Achados. |
| **One Message per Finding** | desativado | Desativado envia um e-mail sobre o lote. |
| **Findings Listed in the Body** | `25` | Quantos Achados `{{ctx.findings_html}}` lista antes de dizer quantos mais existiam. |

### Chamar um Webhook

`notify.webhook`

Envia um POST com JSON para um endpoint de webhook.

| Setting | Default | Notes |
|---------|---------|-------|
| **Webhook Endpoint** | nenhum | Um [notification webhook](/automation/api/notification_webhooks/) configurado. Seu cabeçalho personalizado é enviado com a requisição. |
| **URL** | vazio | Exibido quando nenhum endpoint é selecionado. Para onde fazer o POST. |
| | | Um dos dois acima é obrigatório. |
| **Signing Secret** | vazio | Assina o corpo como `X-DefectDojo-Signature: sha256=HMAC`. |
| **One Message per Finding** | desativado | Desativado publica o lote inteiro em uma única requisição. |

Duas coisas a saber. Um signing secret digitado aqui é armazenado junto com a regra, então, para qualquer coisa sensível, prefira um endpoint configurado e seu próprio cabeçalho. E um webhook chamado por uma regra nunca altera o status de saúde daquele endpoint, então uma regra não pode desativar seus webhooks de notificação ao falhar.

URLs em texto livre são validadas quando você salva. Veja [Configuration](../configuration/#outbound-destination-validation) para saber o que é rejeitado e como permitir endereços privados.

### Emitir um Alerta no Aplicativo

`notify.alert`

Cria um alerta no aplicativo sobre o lote.

| Setting | Default | Notes |
|---------|---------|-------|
| **Title** | `Rules Engine 2.0: {{ctx.rule_name}}` | Renderizado uma vez para o lote inteiro. |
| **Description** | `{{ctx.count}} finding(s) matched the rule {{ctx.rule_name}}.` | Renderizado uma vez para o lote inteiro. |
| **Recipients** | vazio | Nomes de usuário, separados por vírgula. Vazio alerta os administradores. |

Os destinatários ainda controlam isso por meio de sua própria configuração de notificação **Rules Engine Match**, de modo que um alerta não pode contornar as preferências de notificação de um usuário.

### Gerar um Relatório

`report.generate`

Gera um relatório a partir de um modelo, restrito aos Achados que chegaram a este nó, e pode anunciar o link de download.

| Setting | Default | Notes |
|---------|---------|-------|
| **Report Template** | nenhum | A partir de qual modelo gerar. Obrigatório. |
| **Format** | `pdf` | `pdf` ou `html`. |
| **Findings Included** | `batch_findings` | `batch_findings` limita o relatório aos Achados que chegaram a este nó. `template_default` permite que o modelo use seus próprios filtros. |
| **Announce Over** | nenhum | Um [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) pelo qual publicar o link de download assim que o relatório for gerado. Deixe vazio para não anunciar. |
| **Announce To** | vazio | Exibido assim que uma conexão é escolhida. Para onde essa conexão envia: um ID de canal do Slack, endereços de e-mail, e assim por diante. |
| **Announcement** | `Report ready: {{ctx.report_url}}` | Exibido ao anunciar. `{{ctx.report_url}}` é o link de download. |

`batch_findings` é o que uma regra consegue fazer e um relatório agendado não: reportar exatamente os Achados que acabaram de corresponder.

O anúncio é registrado como sua própria entrega, separada da geração do relatório, de modo que você pode ver o relatório ter sucesso e o anúncio falhar de forma independente.
