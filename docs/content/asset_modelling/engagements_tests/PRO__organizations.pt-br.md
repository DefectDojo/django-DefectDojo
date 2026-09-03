---
title: Organizações
description: Entendendo as Organizações no DefectDojo Pro
audience: pro
weight: 1
---

**ORGANIZAÇÕES** → Assets → Engagements → Tests → Findings

## Overview

**Organizações** ficam no topo da hierarquia de produtos do DefectDojo. As Organizações são distintas dos objetos descendentes na hierarquia — Ativos, Engajamentos, Testes e Achados — porque não são alvos técnicos de scan, mas sim servem principalmente como abstrações organizacionais que compartimentam seus esforços de segurança de acordo com:
- Domínio de negócio
- Equipe de desenvolvimento
- Equipe de segurança
- Aplicações de software
- Família de produtos abrangente
- Cliente ou subsidiária
- Estrutura de relatórios
- etc.

O tema dos exemplos acima ilustra a utilidade essencial das Organizações: elas devem, de modo geral, representar limites estáveis e duradouros dentro do seu programa de segurança.

## Organization Data and Structure

Como as Organizações não são escaneadas diretamente, o único campo obrigatório para criá-las é um nome. Além disso, elas atuam como contêineres para Ativos e seus Engajamentos, Testes e Achados descendentes.

Ao criar uma Organização, considere como sua estrutura vai influenciar seus relatórios. Você precisa principalmente que as Organizações representem as equipes que trabalham nos projetos (Ativos) que as Organizações conterão? Ou as Organizações representariam melhor projetos abrangentes que contêm diferentes iterações dos projetos (Ativos) dentro deles?

Se você tiver uma única Organização que contenha todas as informações relevantes para um determinado domínio de negócio ou equipe de desenvolvimento, representar isso como uma Organização facilitará relatórios mais fluidos, em vez de precisar reunir um relatório a partir de vários Ativos e Organizações.

Se um projeto de software específico tiver muitos deployments ou versões distintas, pode valer a pena criar uma única Organização que cubra o escopo de todo o projeto, com cada versão existindo como Ativos individuais. Em alguns fluxos de trabalho, as Organizações também podem ser usadas para separar estágios do ciclo de vida do software: uma Organização para “Em Desenvolvimento”, uma Organização para “Em Produção”, etc.
​
As Organizações podem ser usadas para determinar o acesso a subsidiárias, empresas adquiridas ou outras unidades de negócio regulamentadas para fins de RBAC. Em empresas complexas, onde há muitos projetos exclusivos com diferentes regras de acesso, as Organizações são particularmente relevantes.

Em última análise, a decisão de como usar Organizações e Ativos depende de como você deseja refletir melhor sua estrutura organizacional exclusiva e as necessidades da sua equipe de segurança.

Abaixo estão algumas estruturas de exemplo para orientar como você designa seus objetos como Organizações ou Ativos.

- **Organização**: Divisão de Pagamentos
    - Ativo: Payments API - Production
    - Ativo: Payments API - Staging
    - Ativo: Billing Worker

- **Organização**: Software Product A
    - Ativo: Web Portal
    - Ativo: Mobile Backend

Além disso, o guia a seguir ilustra se algo é melhor representado por uma Organização ou por um Ativo:

| Organizações | Ativos |
|--------------|--------|
| Unidades de negócio | Aplicações individuais |
| Departamentos | Deployments/ambientes |
| Domínios de propriedade de segurança | Componentes de infraestrutura |
| Famílias de produtos | Microsserviços específicos |
| Relatórios em nível de portfólio | Alvos de scan |
| Clientes | Versões específicas de software |

Como observado, sua estrutura pode variar de acordo com as necessidades exclusivas de segurança da sua equipe.

## Accessing Organizations

As Organizações são acessíveis pela barra lateral. O submenu oferece acesso a Todas as Organizações, bem como a opção de criar uma nova Organização.

![image](images/org_ss1.png)

## Organization View

A visualização de uma Organização contém uma variedade de tabelas e gráficos para interpretar seu status rapidamente. Isso inclui:

- **Descrição**
- **Commerce**
    - Se a Organização foi determinada como Crítica ou Chave
        - Marcar Crítica ou Chave é usado exclusivamente para fins de filtragem
- **Membros Atribuídos** (Usuários do DefectDojo)
- **Grupos de Usuários Atribuídos**
    - Grupos de usuários que foram atribuídos à Organização para controle de permissões. Mais informações sobre grupos de usuários podem ser encontradas [aqui](/admin/user_management/create_user_group/).
- **Lista de Ativos dentro da Organização**

## Working with Organizations

### Create Organizations

Existem duas formas de criar Organizações:

- Pela opção **Nova Organização** no menu lateral
- Pelo botão **Nova Organização** no topo da lista de Todas as Organizações

### Edit Organizations

As Organizações podem ser editadas clicando em **Editar Organização** no menu de engrenagem no canto superior direito da visualização da Organização. O mesmo menu também pode ser acessado clicando no menu kebab ⋮ à esquerda da Organização na visualização de Todas as Organizações.

Todos os campos subsequentes que podem ser editados também estão disponíveis quando a Organização está sendo criada.

### Delete Organizations

A exclusão de uma Organização pode ser realizada selecionando **Excluir Organização** nas configurações da Organização.

Como as Organizações ficam no topo da hierarquia, excluí-las remove todo o histórico de segurança, relacionamentos e objetos filhos posteriores, tais como:
- Quaisquer Ativos, Engajamentos e Testes contidos na Organização
- Todo o histórico de segurança associado, incluindo Achados e integrações
- Quaisquer Jira Epics vinculados
- Todas as notas e uploads de arquivos associados aos Ativos, Engajamentos e Testes dentro dessa Organização

A exclusão de uma Organização não pode ser desfeita. Se você quiser “desativar” uma organização sem excluir os dados subjacentes (por exemplo, preservando registros legados de testes de software para fins de auditoria), você pode alterar o nome da Organização ou adicionar uma Tag para indicar que ela está em um estado obsoleto.

## Organiations vs. Metadata

As Organizações têm como objetivo representar limites estruturais de propriedade ou de relatório, e não classificações leves. Atributos como status de deployment, rótulos internos ou estados temporários de fluxo de trabalho podem ser melhor representados por meio de tags ou metadados, em vez de Organizações separadas.

## Organization Boundaries

As Organizações estabelecem limites de relatório e de acesso dentro do DefectDojo. Como integrações, permissões de RBAC, propriedade, métricas e modelos de deduplicação frequentemente herdam a estrutura das Organizações, projetar limites claros desde o início ajuda a evitar a expansão descontrolada da hierarquia e a fragmentação de relatórios mais tarde.

### Findings and Automation

Embora as integrações geralmente sejam configuradas em objetos de nível inferior, como Ativos, Engajamentos ou Achados, as Organizações ainda definem os limites de propriedade, relatório e acesso dentro dos quais essas integrações operam.

As permissões são propagadas em cascata para baixo, o que significa que o acesso a uma Organização concede automaticamente acesso a todos os objetos dentro dessa Organização (por exemplo, Ativos, Engajamentos, Testes e Achados).

O modelo de RBAC do DefectDojo pode ser usado para controlar o acesso de usuários humanos, mas também pode restringir o acesso de tokens de API a Organizações específicas.

Para mais informações sobre papéis de usuário, veja nosso artigo [Introdução aos Tipos de Permissão](/admin/user_management/set_user_permissions/#introduction-to-permission-types).

### Ownership

Como objetos de nível superior, as Organizações também implicam a propriedade sobre os objetos filhos que contêm. O rastreamento de SLA, os fluxos de trabalho de remediação, o roteamento de tickets e a governança geral fluem de forma mais tranquila quando as Organizações são configuradas para refletir com precisão os indivíduos responsáveis por elas.

### Metrics/Reporting

Painéis, tiles e visualizações de métricas podem ser filtrados por Organização, o que os torna um componente crítico na forma como seus dados de segurança são calculados, visualizados e, por fim, exportados.

Para fins de relatório, geralmente é mais fácil combinar várias Organizações em um único documento do que subdividir uma única Organização em documentos separados. Por isso, recomendamos configurar as Organizações no nível de granularidade que fizer mais sentido para os relatórios da sua equipe. Por exemplo, não há necessidade de representar uma grande divisão de negócios como uma Organização se você for reportar principalmente para departamentos individuais dentro dessa divisão.

Estruturar efetivamente suas Organizações para refletir suas necessidades de relatório é fundamental para avaliar com precisão sua postura de segurança. Para mais informações sobre Métricas, clique [aqui](/metrics_reports/pro_metrics/pro__overview/).

### Deduplication

A deduplicação no DefectDojo ocorre no nível do Ativo, e não é afetada pela Organização pai.
