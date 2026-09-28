---
title: Casos de Uso Comuns
description: Casos de uso e exemplos
draft: 'false'
weight: 2
chapter: true
aliases:
- /pt-br/en/about_defectdojo/examples_of_use
---

Este artigo é baseado no Office Hours de fevereiro de 2025 da DefectDojo, Inc.: "Tackling Common Use Cases".
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=ilRBlfo-wvX5DPVg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Exemplos de Casos de Uso

O DefectDojo foi projetado para lidar com qualquer implementação de segurança, independentemente do tamanho da sua equipe de segurança, do nível de complexidade de TI ou do volume de relatórios. As histórias a seguir têm como objetivo servir de ponto de partida para as suas próprias necessidades, mas são baseadas em exemplos reais da nossa comunidade e da equipe do DefectDojo Pro.

### Grande Empresa: RBAC e Engajamentos

A 'BigCorp' é uma grande empresa multinacional, com um Chief Information Security Officer (CISO) e um grupo centralizado de segurança de TI que inclui a AppSec.

A segurança na BigCorp é altamente centralizada. Certas atividades são delegadas a Business Information Security Officers (BISO).

As principais preocupações da BigCorp são:

- Definir e manter um método de teste consistente em todas as unidades de negócio da organização
- Atender aos requisitos de conformidade e evitar problemas regulatórios

#### Modelo de Testes

A BigCorp lida com dados de segurança provenientes de muitas fontes:

- Jobs de CI/CD que executam automaticamente ferramentas de SAST, SCA e varredura de segredos (Secret scanning)
- Pen testing de terceiros para determinados Produtos
- Auditoria de conformidade PCI para determinados Produtos

Cada uma dessas categorias de relatório pode ser tratada por um Engajamento separado, com um Teste separado para cada tipo de varredura no DefectDojo.

![image](images/example_product_hierarchy_bigcorp.png)

- Se um Produto tiver um pipeline de CI/CD, todos os resultados desse pipeline podem ser importados continuamente para um único Engajamento em aberto. Cada ferramenta utilizada criará um Teste separado dentro do Engajamento de CI/CD, que pode ser atualizado continuamente com novos dados.  
(Veja nosso guia sobre [Reimportação](/import_data/import_intro/reimport/))
- Cada esforço de Pen Test pode ter um Engajamento separado criado para conter todos os resultados: por exemplo, "Q1 Pen Test 2024", "Q2 Pen Test 2024", etc.
- É provável que a BigCorp queira realizar sua própria auditoria PCI simulada para se preparar para a auditoria real. Os resultados dessas auditorias também podem ser armazenados como um Engajamento separado.

#### Modelo de RBAC

- Cada BISO tem acesso de Leitor atribuído para cada unidade de negócio (Tipo de Produto) sob sua responsabilidade.
- Cada Product Owner tem acesso de Escritor para o Produto sob sua responsabilidade.  Dentro do seu Produto, os Product Owners podem interagir com o DefectDojo mantendo notas, configurando [pipelines de CI/CD](/import_data/import_scan_files/api_pipeline_modelling/), criando Aceitações de risco e usando outros recursos.
- Os desenvolvedores da BigCorp não têm acesso algum ao DefectDojo, e não precisam dele. O Product Owner pode enviar tickets do Jira diretamente do DefectDojo contendo todas as informações relevantes sobre a vulnerabilidade.  Os desenvolvedores já utilizam o Jira, então não precisam acompanhar a remediação de forma diferente de qualquer outra tarefa de desenvolvimento.

### Sistemas Embarcados: Relatórios com Controle de Versão

A Cyber Robotics é uma empresa que vende hardware de manufatura equipado com sistemas de software embarcado.  Ela conta com um Chief Product Officer (CPO) que supervisiona tanto o produto quanto a segurança cibernética como um todo.

Embora tenham informações de segurança menos diversificadas para gerenciar do que a BigCorp, ainda é essencial contextualizar adequadamente essas informações de segurança para que possam responder proativamente a qualquer Achado significativo.

Principais preocupações da Cyber Robotics:

- Eles têm uma linha de produtos limitada, mas **muitas** versões de cada produto que precisam ser devidamente catalogadas.
- A manutenção de seus produtos é complexa e os custos são altos, portanto é preciso evitar trabalho desnecessário.

#### Modelo de Testes

A Cyber Robotics possui um processo de testes padronizado para todos os seus sistemas embarcados: 

- Testes de CI/CD, SAST e SCA são executados
- Revisões de Controle de Segurança
- Varreduras de Rede
- Revisão de Código por Terceiros

No entanto, como cada versão do software é isolada, inevitavelmente terão muitos dados para organizar, grande parte dos quais só é útil em um único contexto (ou seja, a versão específica do software que estão executando).

A Cyber Robotics pode resolver esse problema usando Tipos de Produto para representar uma única linha de produtos, e Produtos individuais para cada versão separada.  Isso permitirá que eles investiguem em detalhe para determinar quais Produtos estão associados a uma única vulnerabilidade.

![image](images/example_product_hierarchy_robotics.png)

Atribuir versões de software a Produtos, em vez de a Engajamentos, permite que a Cyber Robotics limite o acesso a uma versão específica do software, quando necessário.  Técnicos de campo e a equipe de suporte podem receber acesso a uma única versão do software sem que seja necessário conceder acesso a toda a linha de produtos.

#### Modelo de RBAC

A equipe de AppSec aqui possui Papéis Globais atribuídos que regem seu nível de interação.

- O CPO tem acesso Global de Leitor ao DefectDojo, assim como o CISO na BigCorp.
- Os Product Owners individuais têm acesso Global de Leitor a qualquer Produto no DefectDojo, além de acesso de Escritor ao Produto que possuem.

No lado do Suporte:

- A equipe de suporte recebe temporariamente acesso de Leitor aos Produtos específicos que está encarregada de manter, mas não tem acesso a todos os dados do DefectDojo.

### Ambientes de TI Dinâmicos e Microsserviços: Empresa de Serviços em Nuvem

A Kate's Cloud Service opera em um ambiente que muda rapidamente e utiliza Kubernetes, microsserviços e automação.  A Kate's Cloud Service tem um VP de Cloud que supervisiona as questões de Segurança em Nuvem.  Eles também têm um CISO que gerencia o desenvolvimento de software oferecido, mas, para este exemplo, vamos nos concentrar especificamente nas preocupações de segurança em nuvem.

A Kate's Cloud Service automatizou totalmente todos os seus relatórios e ingere dados no DefectDojo assim que os relatórios são produzidos.

Principais Preocupações da Kate's Cloud Service:

- Gerenciar a segurança em nuvem multi-tenant, evitando a interação entre clientes ao mesmo tempo em que viabiliza a entrega de serviços compartilhados.
- Lidar com mudanças rápidas em seu ambiente de nuvem.

#### Marcação de Serviços Compartilhados

Como o modelo da Kate contém muitos serviços compartilhados que podem impactar outros Produtos, a equipe aplica [Tags](/asset_modelling/tags/os__tagging_objects/) em seus Produtos para indicar quais ofertas de nuvem dependem desses serviços.  Isso permite que qualquer problema com serviços compartilhados seja filtrado entre os Produtos e relatado às equipes relevantes.  Cada um desses serviços compartilhados está em um único Tipo de Produto que os separa das principais ofertas de nuvem.

![image](images/example_product_hierarchy_microservices.png)

Como a empresa está crescendo rapidamente e os tech leads mudam com frequência, a Kate pode usar Tags para rastrear qual tech lead é atualmente responsável por cada produto de nuvem, evitando a necessidade de atualizações manuais constantes no seu sistema DefectDojo. Essas associações de tech lead são rastreadas por um serviço externo ao DefectDojo, que pode governar os pipelines de importação ou chamar a API do DefectDojo.

Para mais informações sobre Marcação (Tagging), veja nosso guia sobre [Tags](/asset_modelling/tags/os__tagging_objects/).

#### Modelo de RBAC

No lado de Segurança/Conformidade:

- A equipe de Segurança de Produto responsável pelo DefectDojo tem acesso de administrador a todo o sistema.
- Os analistas que trabalham para o VP de Cloud recebem acesso somente leitura em todo o sistema, permitindo que gerem os relatórios e métricas necessários para que o VP avalie a segurança das diversas ofertas de nuvem.

No lado de desenvolvimento:

- Os Tech Leads de cada produto de nuvem específico (por exemplo, computação, armazenamento, serviços compartilhados) têm **acesso de Mantenedor** ao Produto atribuído a eles, a fim de triar os resultados de segurança relacionados à sua oferta específica de produto de nuvem. Eles podem revisar Achados e tomar ações dentro do seu Produto, além de reorganizar significativamente os dados de Achados.
- Os desenvolvedores que trabalham em Produtos específicos recebem **Acesso de Escritor** ao Produto em que estão trabalhando, permitindo que comentem em Achados, solicitem Revisões por Pares e criem Aceitações de risco.

### Integrando Novas Aquisições: SaaSy Software

A SaaSy Software é uma empresa em rápido crescimento que frequentemente adquire outras empresas de software.  Toda vez que uma nova empresa é adquirida, o Diretor de Engenharia de Qualidade e a equipe de AppSec passam a ser subitamente responsáveis por muitos novos repositórios de código, desenvolvedores e processos.  O modelo de DefectDojo deles garante que consigam se atualizar o mais rápido possível.

Principais Preocupações da SaaSy Software:

- Evitar problemas públicos de segurança mantendo, ao mesmo tempo, os programas de conformidade (como o SOC2).
- Capacidade de integrar com confiança ferramentas e processos de novos produtos.
- Capacidade de relatar e categorizar vulnerabilidades tanto em branches em produção quanto em branches em desenvolvimento.

#### Modelo de Testes

Os testes na SaaSy têm foco em uma abordagem mais ampla, em vez do uso padronizado de ferramentas, já que cada aquisição vem com suas próprias ferramentas e processos de AppSec.  A SaaSy precisa realizar tanto avaliações internas (CI/CD, DAST, varreduras de contêiner e modelagem de ameaças) quanto avaliações externas (pen tests de terceiros, auditorias de conformidade).

Para ajudar na integração de novas aplicações, a SaaSy Software tem uma abordagem padrão para seu modelo de dados: toda vez que a SaaSy integra uma nova aplicação, ela cria um novo Tipo de Produto para essa aplicação e cria subprodutos para os repositórios que a compõem (Front-End, API de Backend, etc).

![image](images/example_product_hierarchy_saas.png)

Cada um desses Produtos é ainda subdividido em Engajamentos, um para o branch principal e um para cada branch de desenvolvimento.  Os Testes dentro desses Engajamentos são usados para categorizar os esforços de teste.  Os branches de desenvolvimento têm Testes separados que armazenam os resultados das varreduras de CI/CD e SCA.  O branch principal também os tem, mas acrescenta Testes que armazenam relatórios de Revisão Manual de Código e de Modelagem de Ameaças.

Todos esses Testes são em aberto e podem ser atualizados regularmente usando a Reimportação.  A [Deduplicação](/triage_findings/finding_deduplication/about_deduplication/) é tratada apenas no nível do Engajamento, o que impede que Achados em um branch de código fechem Achados em outro.

Ao aplicar esse modelo de forma consistente, a SaaSy tem um modelo que pode aplicar a qualquer nova aquisição de software, e a equipe de AppSec pode rapidamente começar a monitorar os dados para garantir a conformidade.

#### Modelo de RBAC

No lado de Segurança/Conformidade:

- A equipe de AppSec da SaaSy Software é responsável pelo DefectDojo e tem acesso total de administrador ao software.
- As equipes de QE e Conformidade têm acesso somente leitura a todo o sistema, para extrair relatórios e explorar os dados quando necessário.

No lado de desenvolvimento:

- Cada Product Owner tem acesso de Escritor ao Produto que possui no DefectDojo, o que lhes permite registrar Aceitações de risco e visualizar métricas do Produto.
- Os desenvolvedores têm acesso somente leitura a cada Produto em que trabalham.  Eles podem Solicitar Revisões por Pares em Achados ou problemas que estão tentando remediar.
