---
title: Hierarquia de Ativos
description: DefectDojo Pro - Reformulação da Hierarquia de Produtos
audience: pro
weight: 1
aliases:
- /pt-br/en/working_with_findings/organizing_engagements_tests/pro_assets_organizations
- /pt-br/asset_modelling/pro_hierarchy/assets_organizations
---

O DefectDojo Pro está estendendo as classes de objeto Produto/Tipo de Produto para oferecer maior flexibilidade ao modelo de dados.

## Habilitando o recurso de Hierarquia

As duas partes abaixo são separadas e controladas por meios diferentes.

### Hierarquia de Ativos

**Hierarquia de Ativos** habilita relações pai/filho entre Ativos. A hierarquia é visualizada e gerenciada a partir da aba **Produto** na navegação.

A Hierarquia de Ativos está disponível de forma geral e ativa para toda instância, seja Cloud ou On-Premise. Não há nada a habilitar, e ela não está mais listada na página de Feature Flags.

### Alterações de rótulo (opcional)

**Alterações de rótulo** renomeia "Tipo de Produto" para "Organização" e "Produto" para "Ativo" em toda a UI. Esta é uma etapa separada da habilitação da hierarquia e pode ser feita ao mesmo tempo ou posteriormente.

As alterações de rótulo estão ativas por padrão a partir da versão 3.0. Existem dois controles, cobrindo partes diferentes da aplicação:

* **UI Pro** (a UI padrão): um superusuário alterna "Organization / Asset Relabeling" em **Settings > Feature Flags**, tanto em instâncias Cloud quanto On-Premise. Os novos rótulos aparecem no próximo carregamento de página. Veja [Feature Flags](/admin/feature_flags/pro__feature_flags/).
* **Páginas da UI Clássica e relatórios gerados**: seus rótulos e URLs vêm da configuração de implantação `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`, que é lida quando o DefectDojo é iniciado. No modelo on-premise, defina-a e reinicie o DefectDojo. No [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), envie um e-mail para [support@defectdojo.com](mailto:support@defectdojo.com) com a URL da sua instância.

Ambos vêm ativados por padrão, e o valor de Feature Flags foi originado a partir da configuração de implantação, portanto os dois concordam a menos que você altere um deles. Mantenha-os sincronizados se você também usar a UI Clássica, além da UI Pro.

Observe que as alterações de rótulo são apenas cosméticas: os endpoints da API e os nomes de campo permanecem inalterados, portanto a automação existente continuará funcionando.

## Alterações significativas

* **Tipos de Produto** foram renomeados para "Organizações", e **Produtos** foram renomeados para "Ativos". A partir da versão 3.0, essa mudança de nome está ativa por padrão. Veja [Alterações de rótulo](#label-changes-optional) para os controles que a desativam.
* **Ativos** agora podem ter relações pai/filho entre si para subcategorizar ainda mais os componentes organizacionais.

### Organizações

Assim como os Tipos de Produto, as **Organizações** devem ser entendidas como uma categoria de nível superior. Você pode usá-las para separar as principais aplicações de software, departamentos ou funções de negócio da sua empresa.

Por exemplo, você poderia criar uma Organização para diversos agrupamentos de repositórios: "Aplicação Principal", "Infraestrutura", "DevOps", "Analytics", "SDK" poderiam conter, cada uma, múltiplos repositórios de código.

Tenha em mente que, para fins de relatório, é mais fácil combinar múltiplas Organizações em um único documento do que subdividir uma única Organização em documentos separados. Portanto, recomendamos configurar as Organizações no nível mais granular que fizer sentido para os relatórios da sua equipe. Por exemplo, não há necessidade de representar uma grande divisão de negócio como uma Organização se você pretende, principalmente, gerar relatórios sobre departamentos individuais dentro dessa divisão.

### Ativos

Os Ativos têm o objetivo de representar subdivisões das suas Organizações. No entanto, diferentemente dos Produtos, os Ativos podem ser aninhados e ter relações pai-filho entre si.

## Exemplos de aninhamento de Ativos

### Representação de branch no nível de Ativo

Branches de desenvolvimento e de funcionalidades podem ser representados de várias formas; Engajamentos ou Testes separados são formas já existentes de representar a diferença entre seus branches de Produção, Dev e outras funcionalidades.

Você também pode representar isso usando Ativos aninhados. Considere a seguinte árvore de Ativos:

```
Core Application [Organization]
└── webapp-frontend
    ├── webapp-frontend/prod
    └── webapp-frontend/dev
        ├── webapp-frontend/dev/feature-a
        └── webapp-frontend/dev/feature-b
```

Nesse ambiente, cada branch (`prod`, `dev`, `feature a`, `feature b`) poderia ter seus próprios Engajamentos e Testes, isolados dos demais Ativos, de modo que não deduplicam entre si. Essa configuração também pode facilitar a navegação, já que os nomes dos Ativos podem corresponder diretamente ao caminho no Git.

### Mono-repo: componentes separados

Se você usa um único repositório para todo o seu código, mas tem diferentes equipes contribuindo para diretórios dentro desse repositório, você pode configurar o aninhamento de Ativos para representar essa estrutura.

```
Core Application [Organization]
├── webapp-frontend [Parent Asset]
│   ├── mobile-ios
│   ├── mobile-android
│   └── mobile-sdk
├── webapp-backend [Parent Asset]
│   ├── database
│   └── api
└── infra [Parent Asset]
    ├── docker
    ├── kubernetes
    └── nginx
```

Neste diagrama, cada elemento sob "Core Application" poderia ser registrado como um Ativo separado, com criticidade de negócio (veja: [Priority & Risk](/asset_modelling/pro_hierarchy/priority_sla/#prioritization-engines)), RBAC e Engajamentos e Testes correspondentes próprios. Você poderia continuar testando e armazenando resultados no Ativo pai (por exemplo, `webapp-backend`), mas também poderia executar testes isolados em um Ativo filho específico (por exemplo, `database`).

### Testes de invasão: RBAC isolado

Se você quiser armazenar resultados de testes de invasão dentro de um único ativo, mas não quiser que os testadores consigam visualizar os dados do ativo, você poderia criar ativos filhos para que cada grupo de teste envie seus resultados.

```
Core Application [Organization]
└── webapp-frontend [Parent Asset]
    ├── Pen Test Group A
    └── Pen Test Group B
```

Fundamentalmente, dar a um usuário acesso RBAC a um único Ativo Filho (por exemplo, `Pen Test Group A`) aqui não permite que ele visualize nenhum Achado de outros Ativos Filhos (por exemplo, `Pen Test Group B`), nem permite que ele visualize Achados no Ativo Pai (`webapp-frontend`).

O Ativo Pai poderia conter Engajamentos representando resultados de CI/CD, Testes internos, dados históricos ou outros dados de Achados que você não deseja que terceiros consigam descobrir. Criar um Ativo Filho para resultados de testes específicos permite que sua equipe interna gere relatórios sobre esses resultados em combinação com o estado do Ativo pai.

## Visualizando Ativos - Hierarquia

Você pode visualizar a estrutura dos Ativos no DefectDojo e alterar as relações usando a opção Asset Hierarchy no menu.

![image](images/asset_hierarchy.png)

Abrir o Asset Hierarchy exibirá uma tabela com todos os seus Ativos, que pode ser filtrada. Selecionar um ou mais Ativos nessa tabela renderizará um diagrama de hierarquia.

![image](images/asset_hierarchy_diagram.png)

### Navegação no diagrama

Os ícones no canto superior esquerdo do diagrama de hierarquia permitem que você aumente e diminua o zoom. Clicar e arrastar nesse diagrama permite rolar por ele.

Cada Ativo é renderizado como um único nó nesse diagrama, que pode ser movido para fins de exibição.

Os Ativos são conectados entre si por meio de caminhos rotulados, que representam o tipo de relação que cada um tem com o outro. Atualmente, `parent` é o único rótulo suportado.

### Explorando nós de Ativo

É possível interagir com cada nó de Ativo clicando nos botões azuis. Esses botões aparecem somente quando um nó de Ativo está selecionado (clicando no nó).

![image](images/asset_hierarchy_node.png)

* 👁️ (ícone de olho) leva você diretamente para a View de Ativo correspondente (anteriormente conhecida como View de Produto).
* ✏️ (ícone de lápis) abre um modal com o formulário Edit Asset (anteriormente conhecido como formulário Edit Product)
* ➕ (ícone de mais) permite adicionar um novo Ativo Filho a este Ativo. O Ativo não precisa estar visível no diagrama no momento, mas deve fazer parte da mesma Organização.
* ✥ (ícone de quatro setas) permite alterar o Ativo Pai do Ativo atualmente selecionado.
* 🗑️ (ícone de lixeira) permite remover a relação de Ativo pai de um Ativo. Este ícone só aparece se um Ativo já tiver um Pai.

Se o seu diagrama exibir um Ativo com Ativos Pai não selecionados, você pode clicar no botão Load More para preencher o diagrama com o Ativo Pai (assim como os filhos desse Ativo Pai).

![image](images/assets_loadmore.png)

## Notas

* Observe que os escopos de deduplicação não mudaram; os Ativos deduplicam Achados apenas dentro de si mesmos, e não consideram Achados em outros Ativos, independentemente das relações Pai/Filho.
* Os escopos de RBAC não mudaram nesse sistema; cada Ativo ainda é considerado um objeto individual para fins de atribuição de permissões. Nenhuma nova herança de RBAC foi criada.
  * Conceder a um usuário acesso a uma Organização inteira ainda dará a esse usuário acesso a todos os Ativos contidos nessa Organização (assim como ocorre com os Tipos de Produto).
  * Conceder a um usuário acesso a um único Ativo não dá a esse usuário acesso a nenhum Ativo Pai ou Filho relacionado, nem acesso à Organização.
* Não há limite para o número de relações Pai/Filho que podem ser criadas. Teoricamente, você poderia representar toda a estrutura de diretórios de um repositório usando Ativos separados, se quisesse.
* Relações cíclicas não são permitidas: Ativos Pai não podem ser Filhos de seus Ativos Filhos.
