---
title: Organizações
description: Entendendo as Organizações no DefectDojo OS
audience: opensource
weight: 1
aliases:
- /pt-br/asset_modelling/engagements_tests/os_producttype/
- /pt-br/en/asset_modelling/engagements_tests/os_producttype/
---

**ORGANIZAÇÕES** → Ativos → Engajamentos → Testes → Achados

## Visão geral

**Organizações** ficam bem no topo da hierarquia de objetos do DefectDojo. As Organizações são diferentes dos objetos descendentes na hierarquia — Ativos, Engajamentos, Testes e Achados — porque não são alvos técnicos de varredura, mas servem principalmente como abstrações organizacionais que compartimentam seus esforços de segurança de acordo com:
- Domínio de negócio
- Equipe de desenvolvimento
- Equipe de segurança
- Aplicações de software
- Família de produtos abrangente
- Cliente ou subsidiária
- Estrutura de relatórios
- etc.

O tema dos exemplos acima ilustra a utilidade essencial das Organizações: elas geralmente devem representar limites estáveis e duradouros dentro do seu programa de segurança.

## Dados e estrutura da Organização

Como as Organizações não são varridas diretamente, o único campo obrigatório para criá-las é um nome. Além disso, elas funcionam como contêineres para Ativos e seus Engajamentos, Testes e Achados descendentes.

Ao criar uma Organização, considere como sua estrutura influenciará seus relatórios. Você precisa principalmente que as Organizações representem as equipes que trabalham nos projetos (Ativos) que as Organizações vão conter? Ou as Organizações representariam melhor projetos abrangentes que contêm diferentes iterações dos projetos (Ativos) dentro deles?

Se você tem uma única Organização que contém todas as informações relevantes para um determinado domínio de negócio ou equipe de desenvolvimento, representá-la como uma Organização facilitará relatórios mais consistentes, em vez de ter que reunir um relatório a partir de vários Ativos e Organizações.

Se um determinado projeto de software tem muitas implantações ou versões distintas, pode valer a pena criar uma única Organização que cubra o escopo de todo o projeto e deixar cada versão existir como Ativos individuais. Em alguns fluxos de trabalho, as Organizações também podem ser usadas para separar estágios do ciclo de vida do software: uma Organização para "Em Desenvolvimento", outra Organização para "Em Produção", etc.

As Organizações podem ser usadas para determinar o acesso a subsidiárias, empresas adquiridas ou outras unidades de negócio regulamentadas para fins de RBAC. Em empresas complexas, onde há muitos projetos únicos com regras de acesso diferentes, as Organizações são particularmente relevantes.

Em última análise, a decisão de como usar Organizações e Ativos depende de como você deseja melhor refletir sua estrutura organizacional exclusiva e as necessidades da sua equipe de segurança.

Abaixo estão alguns exemplos de estruturas para orientar como você designa seus objetos como Organizações ou Ativos.

- **Organização**: Divisão de Pagamentos
    - Ativo: API de Pagamentos - Produção
    - Ativo: API de Pagamentos - Homologação
    - Ativo: Worker de Faturamento

- **Organização**: Produto de Software A
    - Ativo: Portal Web
    - Ativo: Backend Mobile

Além disso, o guia a seguir ilustra se algo é melhor representado por uma Organização ou por um Ativo:

| Organizações | Ativos |
|--------------|--------|
| Unidades de negócio | Aplicações individuais |
| Departamentos | Implantações/ambientes |
| Domínios de propriedade de segurança | Componentes de infraestrutura |
| Famílias de produtos | Microsserviços específicos |
| Relatórios em nível de portfólio | Alvos de varredura |
| Clientes | Versões específicas de software |

Conforme observado, sua estrutura pode variar de acordo com as necessidades de segurança exclusivas da sua equipe.

## Acessando Organizações

As Organizações são acessíveis pela barra lateral. O submenu também oferece a opção de criar novas Organizações.

![image](images/organization_ss1.png)

### Visualização da Organização

A visualização de uma Organização contém uma variedade de tabelas e gráficos para interpretar seu status rapidamente. Isso inclui:
- **Descrição**
- **Caixa de seleção Chave/Crítica**
    - Marcar Crítica ou Chave é usado somente para fins de filtragem
- **Lista de Ativos dentro da Organização**
- **Usuários autorizados** (Usuários do DefectDojo)

## Trabalhando com Organizações

### Criar Organizações

Existem duas maneiras de criar Organizações:

- Na opção **Adicionar Organização** no menu lateral
- No botão **Adicionar Organização** no topo da lista Todas as Organizações

### Editar Organizações

As Organizações podem ser editadas clicando em **Editar** no menu suspenso no canto superior direito da tabela de Descrição na visualização da Organização. O mesmo menu também pode ser acessado clicando no menu kebab ⋮ à esquerda da Organização na lista Todas as Organizações.

Todos os campos subsequentes que podem ser editados também estão disponíveis quando a Organização está sendo criada.

### Excluir Organizações

A exclusão de uma Organização pode ser realizada selecionando **Excluir Organização** nas configurações da Organização.

Como as Organizações ficam no topo da hierarquia, excluí-las remove todo o histórico de segurança, relacionamentos e objetos filhos a jusante, tais como:
- Quaisquer Ativos, Engajamentos e Testes contidos na Organização
- Todo o histórico de segurança associado, incluindo Achados e integrações
- Quaisquer Epics do Jira vinculados
- Todas as notas e uploads de arquivos associados aos Ativos, Engajamentos e Testes dentro dessa Organização

A exclusão de uma Organização não pode ser desfeita. Se você quiser "desativar" uma Organização sem excluir os dados subjacentes (por exemplo, preservando registros de testes de software legados para fins de auditoria), você pode alterar o nome da Organização ou adicionar uma Tag para indicar que ela está em um estado obsoleto.

## Organizações vs. Metadados

As Organizações têm como objetivo representar a propriedade estrutural ou os limites de relatórios, e não classificações leves. Atributos como status de implantação, rótulos internos ou estados de fluxo de trabalho temporários podem ser melhor representados por meio de tags ou metadados, em vez de Organizações separadas.

## Limites das Organizações

As Organizações estabelecem tanto limites de relatórios quanto de acesso dentro do DefectDojo. Como integrações, permissões de RBAC, propriedade, métricas e modelos de deduplicação frequentemente herdam a estrutura das Organizações, projetar limites claros desde o início ajuda a evitar a expansão descontrolada da hierarquia e a fragmentação de relatórios mais tarde.

### Achados e automação

Embora as integrações normalmente sejam configuradas em objetos de nível inferior, como Ativos, Engajamentos ou Achados, as Organizações ainda definem os limites de propriedade, relatórios e acesso dentro dos quais essas integrações operam.

As permissões são propagadas para baixo, o que significa que o acesso a uma Organização concede automaticamente acesso a todos os objetos dentro dessa Organização (por exemplo, Ativos, Engajamentos, Testes e Achados).

O modelo de RBAC do DefectDojo pode ser usado para controlar o acesso de usuários humanos, mas também pode restringir o acesso de tokens de API a Organizações específicas.

Para mais informações sobre funções de usuário, consulte nosso artigo [Permissões](/admin/user_management/os__authorized_users/).

### Propriedade

Como objetos de nível superior, as Organizações também implicam propriedade sobre os objetos filhos dentro delas. O acompanhamento de SLA, os fluxos de trabalho de correção, o roteamento de tickets e a governança geral fluem com mais tranquilidade quando as Organizações foram configuradas para refletir com precisão os indivíduos responsáveis por elas.

### Métricas/Relatórios

Os painéis, blocos e visualizações de métricas podem ser filtrados por Organização, tornando-os um componente essencial de como seus dados de segurança são calculados, visualizados e, por fim, exportados.

Para fins de relatório, geralmente é mais fácil combinar várias Organizações em um único documento do que subdividir uma única Organização em documentos separados. Portanto, recomendamos configurar as Organizações no nível mais granular que fizer sentido para os relatórios da sua equipe. Por exemplo, não há necessidade de representar uma grande divisão de negócios como uma Organização se você for reportar principalmente para departamentos individuais dentro dessa divisão.

Estruturar suas Organizações de forma eficaz para refletir as necessidades de relatório da sua equipe é fundamental para avaliar com precisão sua postura de segurança. Para mais informações sobre Métricas, clique [aqui](/metrics_reports/dashboards/introduction_dashboard/).

### Deduplicação

A deduplicação no DefectDojo ocorre no nível do Ativo e não é afetada pela Organização pai.
