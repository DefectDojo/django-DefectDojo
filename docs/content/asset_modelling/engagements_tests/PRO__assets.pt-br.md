---
title: Ativos
description: Entendendo os Ativos no DefectDojo Pro
audience: pro
weight: 2
---

Organizações → **ATIVOS** → Engajamentos → Testes → Achados

## Visão geral

**Ativos** estão no centro de como o trabalho de segurança é organizado dentro da hierarquia de objetos do DefectDojo. Os Ativos representam qualquer projeto, programa, software ou ativo físico que sua equipe de segurança esteja testando, e hospedam todo o trabalho de segurança e o histórico de testes relacionados ao objetivo do teste. Exemplos de Ativos podem incluir:
- Versões de software
- Software de terceiros
- Máquinas virtuais ou ativos em produção
- Uma única aplicação
- Um microsserviço
- Uma API
- Uma plataforma SaaS
- Um aplicativo móvel
- Um sistema interno
- Um serviço de negócio
- Uma plataforma voltada para o cliente
- Um ambiente de nuvem ou domínio de infraestrutura

Em geral, um Ativo deve representar a "coisa" cuja postura de segurança você deseja acompanhar ao longo do tempo. Isso inclui o histórico de testes associado, os Achados, as métricas, a propriedade, as integrações e os fluxos de trabalho de correção relacionados a essa "coisa".

### Exemplos de Ativos

Os Ativos podem se tornar ainda mais granulares, dependendo das necessidades da sua organização. Por exemplo, você pode considerar criar Ativos separados no DefectDojo nos seguintes cenários:

- "AtivoExemplo" tem uma versão para Windows, uma versão para Mac e uma versão para Nuvem
- "AtivoExemplo 1.0" usa componentes de software completamente diferentes de "AtivoExemplo 2.0", e ambas as versões são ativamente suportadas pela sua empresa.
- A equipe designada para trabalhar na "versão A do AtivoExemplo" é diferente da equipe de Ativo designada para trabalhar na "versão B do AtivoExemplo", e, como resultado, precisa ter permissões de segurança diferentes atribuídas.

Embora você também possa optar por representar essas variações como Engajamentos dentro de um único Ativo, o RBAC só pode ser definido no nível de Ativos ou Organizações, o que pode limitar o acesso dos usuários ao Engajamento apropriado (bem como aos Testes e Achados dentro desses Engajamentos) caso estejam organizados dessa forma. Para mais informações sobre RBAC e permissões no DefectDojo, clique [aqui](/admin/user_management/about_perms_and_roles/).

## Dados do Ativo

Os Ativos sempre incluirão os seguintes componentes:

- **Organização**
- **Nome exclusivo**
- **Descrição**
- **Configuração de SLA**
- **Motor de Priorização**

Os metadados opcionais do Ativo incluem:

- **Tags**
- **Criticidade de negócio**
- **Registros de usuários** (ou seja, o número estimado de registros de usuários no Ativo)
- **Receita**
- **Informações de pessoal** (por exemplo, Gerente do Ativo, Gerente da Equipe, Contato Técnico, etc.)
- **Regulamentações** (por exemplo, HIPAA, GLBA, OPPA, etc.)
- **Plataforma** (por exemplo, API, Desktop, IoT, Mobile, Web, etc.)
- **Ciclo de vida** (por exemplo, Construção, Produção, Desativação, etc.)
- **Origem** (por exemplo, Biblioteca de Terceiros, Adquirido, Código Aberto, etc.)

Esses metadados melhoram a filtragem, os relatórios e a priorização em todo o seu programa de segurança, mas o mais importante é que os Ativos também contêm todos os Engajamentos, Testes e Achados relacionados aos esforços de teste em torno desse Ativo. Todos os Achados dos Testes, em última instância, são consolidados no nível do Ativo, permitindo o acompanhamento de longo prazo, a análise de tendências e a geração de relatórios.

## Acessando Ativos

Os Ativos são acessíveis pela barra lateral. O submenu oferece acesso à [Hierarquia de Ativos](/asset_modelling/engagements_tests/pro__assets/#asset-nesting) e a Todos os Ativos, além da opção de criar um novo Ativo.

![image](images/assets_ss1.png)

### Permissões

Os Ativos podem ter regras de Controle de Acesso Baseado em Função (RBAC) aplicadas, que limitam a capacidade dos membros da equipe de visualizá-los e interagir com eles.

As permissões são propagadas para baixo, o que significa que o acesso a um Ativo concede automaticamente acesso a todos os objetos dentro desse Ativo (por exemplo, Engajamentos, Testes e Achados).

Para mais informações sobre funções de usuário, consulte nosso artigo [Introdução às Funções](/admin/user_management/set_user_permissions/#introduction-to-permission-types).

## Visualização do Ativo

As visualizações de Ativo contêm uma variedade de tabelas e gráficos para interpretar o status de um Ativo rapidamente. Isso inclui:

- **Severidade dos Achados Abertos**
    - Uma lista dos Achados abertos dentro do Ativo, agrupados por severidade
- **Visão Geral do Ativo**
    - Um detalhamento de vários recursos do Ativo, incluindo Descrição, Componentes, Contatos, [Grupos de Usuários](/admin/user_management/create_user_group/
), Membros, Tecnologias e Regulamentações.
        - Tecnologias: next.js, vue.js, npm v.1.2.3, Django, nginx, Hugo
- **Metadados**
    - Incluindo Ativos pais e filhos, Organização, criticidade de negócio, receita e outros detalhes adicionados nas configurações do Ativo.
- **Acordo de Nível de Serviço por Severidade**
    - Aplica a configuração de SLA do Ativo, definida nas configurações, aos Achados dentro do Ativo.
- **Detalhamento de Severidade dos Achados**
    - Um gráfico dos Achados dentro do Ativo, organizados por severidade.
- **Distribuição de Achados**
    - Um detalhamento dos Achados dentro do Ativo, organizados por status (por exemplo, Ativo, Mitigado, Estático e Dinâmico)
- **Todos os Engajamentos**
    - Uma lista dos Engajamentos contidos no Ativo.

## Trabalhando com Ativos

### Criar Ativos

Existem duas maneiras de criar Ativos:

- Na opção **Novo Ativo** no menu lateral
- No botão **Novo Ativo** no topo da lista Todos os Ativos

## Editar Ativos

Os Ativos podem ser editados clicando em **Editar Ativo** no menu de engrenagem no canto superior direito da visualização do Ativo. O mesmo menu também pode ser acessado clicando no menu kebab ⋮ à esquerda do Ativo na visualização Todos os Ativos.

Todos os campos subsequentes que podem ser editados também estão disponíveis quando o Ativo está sendo criado.

![image](images/assets_ss2.png)

### Excluir Ativos

A exclusão de um Ativo pode ser realizada selecionando **Excluir Ativo** nas configurações do Ativo. Essa ação não pode ser desfeita. Os Ativos não podem ser fechados e reabertos posteriormente.

A exclusão de um Ativo também excluirá o seguinte:
- Quaisquer Engajamentos e Testes contidos no Ativo
- Todo o histórico de segurança associado, incluindo Achados e integrações
- Quaisquer Epics do Jira vinculados
- Todas as notas e uploads de arquivos associados aos Engajamentos e Testes do Ativo

## Limites do Ativo

### Deduplicação

Os Ativos são "isolados" e não interagem com outros Ativos. Os Recursos Inteligentes do DefectDojo, como a Deduplicação, aplicam-se apenas no contexto de um único Ativo. Os Achados de diferentes Ativos não serão deduplicados automaticamente.

### Relatórios e Métricas

A maioria dos relatórios e métricas agrega dados no nível do Ativo, tornando os Ativos a unidade principal para medir e acompanhar o risco.

Como resultado, muitas métricas importantes são calculadas por Ativo, incluindo:

- Número total de Achados (por severidade ou status)
- Tempo médio de correção (MTTR)
- Conformidade e taxas de violação de SLA
- Tendências de risco ao longo do tempo

Isso significa que a forma como os Ativos são estruturados impactará diretamente a precisão e a utilidade dos relatórios. Por exemplo, agrupar vários sistemas não relacionados em um único Ativo pode obscurecer a visibilidade do risco, enquanto estruturas de Ativo excessivamente granulares podem fragmentar os relatórios, dificultando a identificação de tendências mais amplas.

### Connectors

No DefectDojo Pro, os Connectors são mapeados para diferentes Ativos, tornando-os o principal ponto de integração entre o DefectDojo e seu ecossistema de segurança mais amplo.

Depois que um Connector é anexado a um Ativo, ele importará os resultados da varredura e criará ou atualizará Engajamentos, Testes e Achados dentro desse Ativo.

Para mais informações sobre Connectors, clique [aqui](/connectors/upstream/about/#main-content).

### Pipelines de CI/CD

Os pipelines de CI/CD automatizam a importação dos resultados de varredura. Independentemente do método de integração, todas as importações de varredura devem estar associadas a um Ativo, tornando o Ativo o ponto de ancoragem para os dados de segurança orientados por pipeline.

Quando um pipeline envia resultados de varredura, ele deve:

- Especificar um Ativo existente (e, opcionalmente, um Engajamento), ou
- Estar configurado de forma a mapear consistentemente os resultados para o Ativo correto

Todos os Achados importados herdarão o contexto do Ativo, incluindo propriedade, permissões, configuração de prioridade/risco e escopo de relatórios.

Na prática, os Ativos devem ser definidos de forma a refletir como os sistemas são construídos e implantados dentro do CI/CD, a fim de garantir que os resultados de segurança sejam consistentemente associados à aplicação ou ao serviço correto.

### SLAs, Prioridade e Risco

No DefectDojo Pro, os Achados herdam suas metas de SLA, Prioridade e Risco do Ativo que os contém. Os metadados do Ativo (por exemplo, criticidade de negócio, receita, etc.) são usados para calcular automaticamente os valores de Prioridade e Risco.

Isso significa que a mesma vulnerabilidade pode receber uma pontuação de Prioridade ou Risco diferente, dependendo se ela afeta um sistema de desenvolvimento interno ou um ativo de produção que suporta operações de negócio críticas.

### Relacionamentos com Jira / Connectors Downstream

Os Ativos podem ser mapeados diretamente para instâncias do [Jira](/connectors/downstream/pro__jira_guide/#main-content) ou [Integrators](/connectors/downstream/downstream_toolreference/#main-content) (por exemplo, GitHub, GitLab, ServiceNow, etc.), que enviam os Achados do Ativo para fora, rumo a sistemas externos de tickets/gerenciamento de trabalho.

Como os Achados herdam risco, prioridade e propriedade do Ativo pai, o Ativo efetivamente determina o contexto de correção que flui para os tickets do Jira e para os fluxos de trabalho dos Connectors Downstream.

É importante destacar que os Ativos também são o principal fator determinante nas características de SLA de um Achado. Portanto, o SLA de um Achado depende da configuração de SLA do seu Ativo pai. Mais informações sobre configurações de SLA podem ser encontradas [aqui](/asset_modelling/pro_hierarchy/priority_sla/#working-with-slas).

## Aninhamento de Ativos

O DefectDojo oferece suporte a um relacionamento pai-filho entre dois Ativos dentro da mesma Organização. Isso pode ser configurado durante a criação do Ativo ou nas configurações do Ativo.

Você pode visualizar a estrutura dos Ativos no DefectDojo e alterar relacionamentos usando a opção **Hierarquia de Ativos** na barra lateral.

Depois de selecionar os Ativos a serem visualizados na tabela correspondente, clique em **Ver Hierarquia de Ativos** para gerar um fluxograma do relacionamento entre os Ativos escolhidos, se houver algum.

Mais informações sobre o efeito do aninhamento de Ativos na deduplicação, no RBAC e em outros detalhes, bem como exemplos de casos de uso, podem ser encontradas [aqui](/asset_modelling/pro_hierarchy/asset_hierarchy/#asset-nesting-examples).
