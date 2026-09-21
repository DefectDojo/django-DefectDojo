---
title: Ativos
description: Entendendo os Ativos no DefectDojo OS
audience: opensource
weight: 2
aliases:
- /pt-br/asset_modelling/engagements_tests/os__products/
- /pt-br/en/asset_modelling/engagements_tests/os__products/
---

Organizações → **ATIVOS** → Engajamentos → Testes → Achados

## Visão Geral

Os **Ativos** estão no centro de como o trabalho de segurança é organizado na hierarquia de objetos do DefectDojo. Os Ativos representam qualquer projeto, programa, software ou ativo físico que sua equipe de segurança esteja testando, e abrigam todo o trabalho de segurança e o histórico de testes relacionados ao objetivo do teste. Exemplos de Ativos podem incluir:
- Lançamentos de software
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

Em geral, um Ativo deve representar a “coisa” cuja postura de segurança você deseja acompanhar ao longo do tempo. Isso inclui o histórico de testes associado, os Achados, as métricas, a titularidade, as integrações e os fluxos de remediação relacionados a essa “coisa”.

### Exemplos de Ativos

Os Ativos podem se tornar ainda mais granulares dependendo das necessidades da sua organização. Por exemplo, você pode considerar criar Ativos separados no DefectDojo nos seguintes cenários:

- “ExampleAsset” tem uma versão para Windows, uma versão para Mac e uma versão em nuvem
- “ExampleAsset 1.0” usa componentes de software completamente diferentes de “ExampleAsset 2.0”, e ambas as versões são ativamente mantidas pela sua empresa.
- A equipe designada para trabalhar em “ExampleAsset versão A” é diferente da equipe de Ativo designada para trabalhar em “ExampleAsset versão B”, e por isso precisa ter permissões de segurança diferentes atribuídas.

Embora você também possa optar por representar essas variações como Engajamentos dentro de um único Ativo, o RBAC só pode ser definido no nível de Ativos ou Organizações, o que pode limitar o acesso dos usuários ao Engajamento apropriado (assim como aos Testes e Achados dentro desses Engajamentos) se estiverem organizados dessa forma. Para mais informações sobre RBAC e permissões no DefectDojo, clique [aqui](/admin/user_management/about_perms_and_roles/).

## Dados do Ativo

Os Ativos sempre incluirão os seguintes componentes:

- **Nome exclusivo**
- **Descrição**
- **Organização**
- **Configuração de SLA**

Os metadados opcionais do Ativo incluem:

- **Tags**
- **Informações de pessoal** (por exemplo, Gerente do Ativo, Gerente da Equipe, Contato Técnico, etc.)
- **Regulamentações** (por exemplo, HIPAA, GLBA, OPPA, etc.)
- **Criticidade para o negócio**
- **Plataforma** (por exemplo, API, Desktop, IoT, Mobile, Web, etc.)
- **Ciclo de vida** (por exemplo, Construção, Produção, Desativação, etc.)
- **Origem** (por exemplo, Biblioteca de Terceiros, Adquirido, Código Aberto, etc.)
- **Registros de usuários** (ou seja, o número estimado de registros de usuários no Ativo)
- **Receita**

Esses metadados melhoram a filtragem, os relatórios e a priorização em todo o seu programa de segurança, mas, mais importante, os Ativos também contêm todos os Engajamentos, Testes e Achados relacionados aos esforços de teste em torno desse Ativo. Todos os Achados dos Testes acabam consolidados no nível do Ativo, permitindo acompanhamento de longo prazo, análise de tendências e relatórios.

## Acessando Ativos

Os Ativos são acessíveis pela barra lateral. O submenu também oferece a opção de criar um novo Ativo.

![image](images/asset_ss3.png)

### Permissões

Os Ativos podem ter regras de Controle de Acesso Baseado em Função (RBAC) aplicadas, o que limita a capacidade dos membros da equipe de visualizá-los e interagir com eles.

As permissões se propagam em cascata, o que significa que o acesso a um Ativo concede automaticamente acesso a todos os objetos dentro desse Ativo (por exemplo, Engajamentos, Testes e Achados).

Para mais informações sobre funções de usuário, veja nosso [artigo de Introdução às Funções](/admin/user_management/about_perms_and_roles/).

## Visualização do Ativo

As visualizações de Ativo contêm uma variedade de tabelas e gráficos para interpretar rapidamente o status de um Ativo. Isso inclui:

- **Metadados**
    - Incluindo Organização, criticidade para o negócio, receita e outros detalhes adicionados nas configurações do Ativo.
- **Métricas**
    - Uma lista de Achados abertos dentro do Ativo, agrupados por severidade
- **Acordo de Nível de Serviço por Severidade**
    - Aplica a configuração de SLA do Ativo, definida nas configurações, aos Achados dentro do Ativo.
- **Tecnologias**
    - Por exemplo, next.js, vue.js, npm v.1.2.3, Django, nginx, Hugo
- **Regulamentações**
- **Progresso de Benchmark**
- **Membros**
- **Grupos**
- **Contatos**
- **Notificações**
    - Ativa e desativa notificações dependendo de eventos específicos (por exemplo, um Engajamento foi adicionado ou encerrado)

## Trabalhando com Ativos

### Criar Ativos

Existem várias maneiras de criar um novo Ativo, incluindo:

- O botão **Add Asset** na lista de Todos os Ativos

![image](images/asset_ss2.png)

- No menu suspenso da tabela de Ativos dentro da visualização de uma Organização
    - Isso criará automaticamente o Ativo dentro dessa Organização.

![image](images/asset_ss1.png)

- O botão **Add Asset** na barra lateral

![image](images/asset_ss5.png)

### Editar Ativos

Um Ativo pode ser editado a partir de suas configurações, que podem ser acessadas de duas formas:

- O botão **Edit** dentro do menu kebab (⋮) à esquerda do Ativo, na visualização de Todos os Ativos

![image](images/asset_ss6.png)

- O botão **Edit** dentro do menu suspenso **Settings** na visualização do Ativo

![image](images/asset_ss7.png)

### Excluir Ativos

A opção de excluir um Ativo pode ser encontrada na parte inferior dos mesmos menus descritos na seção **Editar Ativos** acima. Essa ação não pode ser desfeita. O Ativo não pode ser fechado e reaberto posteriormente.

Excluir um Ativo também excluirá o seguinte:
- Quaisquer Engajamentos e Testes contidos no Ativo
- Todo o histórico de segurança associado, incluindo Achados e integrações
- Quaisquer Épicos do Jira vinculados
- Todas as notas e uploads de arquivos associados aos Engajamentos e Testes do Ativo

## Limites do Ativo

### Deduplicação

Os Ativos são “isolados” e não interagem com outros Ativos. Os Smart Features do DefectDojo, como a Deduplicação, aplicam-se apenas no contexto de um único Ativo. Achados em Ativos diferentes não serão deduplicados automaticamente.

### Métricas

A maior parte dos relatórios e métricas agrega dados no nível do Ativo, tornando os Ativos a unidade principal para medir e acompanhar o risco.

Como resultado, muitas métricas-chave são calculadas por Ativo, incluindo:

- Número total de Achados (por severidade ou status)
- Tempo médio de remediação (MTTR)
- Taxas de conformidade e violação de SLA
- Tendências de risco ao longo do tempo

Isso significa que a forma como os Ativos são estruturados impactará diretamente a precisão e a utilidade dos relatórios. Por exemplo, agrupar vários sistemas não relacionados sob um único Ativo pode obscurecer a visibilidade de risco, enquanto estruturas de Ativo excessivamente granulares podem fragmentar os relatórios, dificultando a identificação de tendências mais amplas.

As métricas específicas do Ativo podem ser acessadas pelo botão **Metrics** na barra superior da visualização do Ativo escolhido.

![image](images/asset_ss8.png)

### Pipeline de CI/CD

Os pipelines de CI/CD automatizam a importação dos resultados de varredura. Independentemente do método de integração, todas as importações de varredura devem estar associadas a um Ativo, tornando o Ativo o ponto de ancoragem para os dados de segurança orientados por pipeline.

Quando um pipeline envia resultados de varredura, ele deve:

- Especificar um Ativo existente (e opcionalmente um Engajamento), ou
- Estar configurado de forma a mapear consistentemente os resultados para o Ativo correto

Todos os Achados importados herdarão o contexto do Ativo, incluindo titularidade, permissões, configuração de SLA e escopo de relatórios.

Na prática, os Ativos devem ser definidos de forma a refletir como os sistemas são construídos e implantados dentro do CI/CD, garantindo que os resultados de segurança sejam consistentemente associados à aplicação ou serviço correto.

### Relações com o Jira

Os Ativos podem ser mapeados diretamente para Projetos do Jira, que enviam os Achados do Ativo para uma instância do Jira.

Como os Achados herdam risco, prioridade e titularidade de seu Ativo pai, o Ativo determina efetivamente o contexto de remediação que flui para os tickets do Jira e para os fluxos de trabalho dos Downstream Connectors.

É importante notar que os Ativos também são o principal fator determinante nas características de SLA de um Achado. Portanto, o SLA de um Achado depende da configuração de SLA de seu Ativo pai. Mais informações sobre configurações de SLA podem ser encontradas [aqui](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content).
