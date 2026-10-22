---
title: Conectores Downstream
weight: 1
audience: pro
aliases:
- /pt-br/en/share_your_findings/integrations
- /pt-br/issue_tracking/pro_integration/integrations/
---

**Disponibilidade:** os Conectores Downstream estão disponíveis de forma geral e ativados em todas as instâncias do DefectDojo Pro, tanto Cloud quanto On-Premise. Não há nada para habilitar, e eles não estão mais listados na página de Feature Flags.

Os Conectores Downstream permitem enviar seus Achados e Grupos de Achados para sistemas de rastreamento de tickets, integrando facilmente a remediação de segurança ao fluxo de trabalho de desenvolvimento já existente da sua equipe.

Conectores Downstream suportados:
- Azure Devops
- Bitbucket
- Freshservice
- GitHub
- GitLab Boards
- Jira
- Linear
- Opsgenie
- PagerDuty
- ServiceDesk Plus
- ServiceNow
- ServiceNow SecOps / Vulnerability Response
- Shortcut
- Zendesk

## Abrindo a página de Conectores Downstream

A página de Conectores Downstream pode ser encontrada em **Import > Connectors > Downstream Connectors** na barra lateral.

![image](images/integrators_3.png)

## Configurando um Conector Downstream

Um Conector Downstream é configurado com três componentes principais:

- **Instância de Integração**: este é o método de conexão principal que o DefectDojo usará com um sistema de terceiros. A Instância incluirá detalhes como um rótulo, localização e credenciais de conexão, além de qualquer outra informação que possa ser exigida pelo fornecedor.
- **Mapeamento do Issue Tracker**: é aqui que as informações de mapeamento são armazenadas, definindo os detalhes necessários para se conectar a um determinado "projeto" no fornecedor. Esses detalhes incluem o nome ou ID do "projeto", e os mapeamentos entre a severidade e o status dos Achados do DefectDojo e o campo correspondente no "ticket" do fornecedor. Você pode ter vários mapeamentos configurados se estiver tentando enviar Achados para vários locais de "projeto".
- **Atribuição do Issue Tracker**: é aqui que Produtos e Engajamentos do DefectDojo são atribuídos a um determinado Mapeamento do Issue Tracker, com opções por Produto/Engajamento para definir como um Achado será enviado a um determinado sistema do fornecedor.

Esses componentes são hierárquicos: cada **Instância** tem um ou mais **Mapeamentos**, que por sua vez têm uma ou mais **Atribuições de Tracker**.

![image](images/integrators_2.png)

## Enviando Achados e Grupos de Achados

Depois que esses componentes estiverem configurados, Achados e Grupos de Achados podem ser enviados a um determinado Issue Tracker de duas formas: manualmente ou automaticamente.

- **Manualmente**: Achados e Grupos de Achados contidos em um Produto/Engajamento com um **Mapeamento do Issue Tracker** atribuído terão a opção "Enviar para o Integrador". Isso criará um Issue no Issue Tracker com as informações correspondentes do Achado/Grupo de Achados. "Enviar para o Integrador" também pode ser usado para atualizar um Issue existente.

### Envio automático de Achados

Achados também podem ser enviados automaticamente, com a **Atribuição do Issue Tracker** determinando como esses objetos serão enviados. Estas são as quatro opções:

- **Publicar Alterações no Destino Apenas Explicitamente**: esta opção desativa qualquer comportamento automático no Produto ou Engajamento atribuído. A única forma de enviar um Achado ou Grupo de Achados será explicitamente, conforme mencionado acima.
- **Vincular Automaticamente Novo Achado ao Destino**: quando novos Achados ou Grupos de Achados são **criados** no Produto ou Engajamento atribuído, o DefectDojo enviará automaticamente o objeto para o Issue Tracker. Uma vez criados, esses Achados ou Grupos de Achados não serão atualizados sem uma ação manual de Enviar para o Integrador.
- **Atualizar Automaticamente Vínculo Existente ao Editar o Achado**: quando Achados ou Grupos de Achados são **atualizados** no Produto ou Engajamento atribuído, o objeto é enviado automaticamente para o Issue Tracker caso um vínculo existente já tenha sido criado manualmente.
- **Vincular Novo e Atualizar Vínculo Existente Automaticamente ao Editar o Achado**: quando Achados ou Grupos de Achados são criados **ou** atualizados no Produto ou Engajamento atribuído, o objeto é enviado automaticamente para o Issue Tracker.

#### Filtros de Envio

Cada Atribuição do Issue Tracker pode, opcionalmente, restringir quais Achados são enviados **automaticamente**:

- **Severidade Mínima**: cria tickets automaticamente apenas para Achados com severidade igual ou superior à selecionada. Deixe em branco para incluir todas as severidades.
- **Apenas Achados Ativos**: cria tickets automaticamente apenas para Achados ativos, ignorando aqueles que já estão Mitigado, Falso positivo ou Risco aceito no momento em que a atribuição os identifica pela primeira vez.

Esses filtros se aplicam apenas à **criação** automática. Atualizações em um Achado que já possui um ticket vinculado são sempre enviadas, portanto mudanças de status (incluindo fechamentos) continuam sendo propagadas. Um "Enviar para o Integrador" manual sempre ignora os filtros. Deixar ambos com os valores padrão preserva o comportamento original de enviar todos os Achados.

#### Atribuindo vários Produtos

Uma Atribuição do Issue Tracker tem como alvo um único Produto ou Engajamento. Para cobrir vários ativos, crie uma Atribuição por Produto (ou Engajamento). Se você também precisar que os campos do fornecedor sejam diferentes por ativo — por exemplo, um **Assignment group** ou **Assigned to** distinto no ServiceNow, ou um projeto diferente no Jira — crie um Mapeamento do Issue Tracker separado (com seus próprios Mapeamentos de Campos Personalizados) para cada ativo e aponte cada Atribuição para o Mapeamento correspondente.

## Representação do Ticket no Issue Tracker

Os Tickets do Issue Tracker são representados por uma série de ícones na coluna "Integrator Tickets" ao visualizar e listar
Achados e Grupos de Achados

Ícones da esquerda para a direita:

- **Tipo de Integração**: o tipo de Issue Tracker ao qual o Ticket está associado
- **ID do Ticket**: o ID do Ticket, conforme definido pelo Issue Tracker
- **Link do Ticket**: o link direto para o Ticket, conforme definido pelo Issue Tracker
- **Changelog**: especifica quando o Ticket do Issue Tracker foi associado a um Achado ou Grupo de Achados, além da última vez que o DefectDojo fez uma alteração no ticket

![image](images/integrators_1.png)

## Requisitos Específicos do Fornecedor

Cada fornecedor terá requisitos variados quanto à forma como o DefectDojo precisará interagir com ele. Isso pode ser na forma de um mecanismo de autenticação, campos adicionais por "projeto", ou mapeamentos de severidade/status.

Para a lista completa de requisitos, abra as páginas específicas de cada fornecedor abaixo:

- [Azure Devops](/connectors/downstream/downstream_toolreference/#azure-devops-boards)
- [Bitbucket](/connectors/downstream/downstream_toolreference/#bitbucket)
- [Freshservice](/connectors/downstream/downstream_toolreference/#freshservice)
- [GitHub](/connectors/downstream/downstream_toolreference/#github)
- [GitLab Boards](/connectors/downstream/downstream_toolreference/#gitlab)
- [Jira](/connectors/downstream/downstream_toolreference/#jira)
- [Linear](/connectors/downstream/downstream_toolreference/#linear)
- [Opsgenie](/connectors/downstream/downstream_toolreference/#opsgenie)
- [PagerDuty](/connectors/downstream/downstream_toolreference/#pagerduty)
- [ServiceDesk Plus](/connectors/downstream/downstream_toolreference/#servicedesk-plus)
- [ServiceNow](/connectors/downstream/downstream_toolreference/#servicenow)
- [ServiceNow SecOps / Vulnerability Response](/connectors/downstream/downstream_toolreference/#servicenow-secops)
- [Shortcut](/connectors/downstream/downstream_toolreference/#shortcut)
- [Zendesk](/connectors/downstream/downstream_toolreference/#zendesk)

## Tratamento de Erros e Depuração

Conectores Downstream podem produzir erros por diversos motivos, como conectividade, autenticação, permissões etc. Para ajudar na depuração desses erros, cada Mapeamento do Issue Tracker possui uma tabela de erros que lista quando o erro ocorreu, o motivo pelo qual ocorreu, e o Achado ou Grupo de Achados que falhou ao ser enviado.

Esses erros podem ser encontrados na página All Issue Tracker Mappings & Assignments, na coluna ⚠️ Total Errors.

![image](images/integrators_4.png)

Clicar na entrada Total Errors leva você a uma página com descrições mais detalhadas dos erros associados a este Conector Downstream.

### Ver todas as falhas em um só lugar

A tabela de erros por mapeamento cobre um único Conector Downstream. O [Diagnósticos](/admin/diagnostics/pro__diagnostics/) cobre todos eles, além de todas as outras tentativas de integração na instância — conectores upstream, importações, Jira, SSO e o motor de regras — com os mesmos recursos de filtragem e ordenação sobre tudo isso.

Use-o quando a pergunta for mais ampla do que um único mapeamento:

* uma tentativa que **nunca foi concluída** em vez de falhar, o que nenhuma tabela de erros reporta, porque nada gerou erro
* se uma falha é específica de uma integração ou está ocorrendo em várias ao mesmo tempo
* quem ou o que disparou uma tentativa, e contra qual configuração

Credenciais citadas em um erro são removidas antes que a linha seja armazenada, e o detalhe técnico completo é restrito a superusuários.

## Layout da página de Conectores Downstream

Os Conectores Downstream são listados em duas seções, **Configured Connectors** e **Available Connectors**, cada uma ordenada alfabeticamente com uma contagem do que é exibido ao lado do seu título. Uma ferramenta pode ter várias configurações; cada uma é seu próprio bloco, intitulado `<Tool> - <label>`, ordenado por rótulo. O bloco **Request Downstream Connector** no DefectDojo Pro Cloud não é contabilizado.
