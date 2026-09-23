---
title: Marcação de Objetos
description: Use Tags para criar um novo recorte do seu modelo de dados
draft: false
weight: 2
exclude_search: false
audience: pro
aliases:
- /pt-br/en/working_with_findings/organizing_engagements_tests/tagging_objects
---

Tags são ideais para agrupar objetos de forma que possam ser filtrados em blocos menores e mais fáceis de analisar.  Podem ser usadas para indicar status ou para criar conjuntos personalizados de Tipo de Produto, Produtos, Engajamentos ou Achados em todo o modelo de dados.

No DefectDojo, as tags são um cidadão de primeira classe e são reconhecidas como as facilitadoras
da organização em cada nível do modelo de dados.

Aqui está um exemplo com um Produto com duas tags e quatro achados, cada um com uma única tag:

![High level example of usage with tags](images/tags-high-level-example.png)

### Formatos de Tag

As tags podem ser formatadas de qualquer uma das seguintes maneiras:
- StringWithNoSpaces
- string-with-hyphens
- string_with_underscores
- colons:acceptable

## Gerenciamento de Tags (Pro UI)

### Adicionando e Removendo

As tags podem ser gerenciadas das seguintes formas:

1. **Criando ou Editando novos objetos**

   Quando um novo objeto é criado ou editado pela UI ou pela API, há um campo para especificar
   as tags a serem definidas em um determinado objeto.

   ![tag](images/tags_product.png)

2. **Ao Importar/Reimportar Achados**

  As tags estão disponíveis no formulário de Importação/Reimportação, tanto na UI quanto via API.  Quando esse formulário é enviado, o **Teste** será marcado com `[tag]` e `[daily-import]`.  Se "Apply Tags to Findings" ou "Apply Tags to Endpoints" estiver selecionado, esses objetos também serão marcados.  As tags oferecem a oportunidade de anexar detalhes de execução de automação e informações da ferramenta que talvez não sejam capturadas diretamente no objeto Teste ou Achado. 

   ![tag](images/tags_importscan.png)

3. **Via Edição em Massa**

  Quando muitos Achados são selecionados em uma tabela, você pode usar o menu de Edição em Massa para alterar as Tags associadas a vários Achados simultaneamente.  Observe que isso substituirá todas as Tags no nível do Achado pelas Tags especificadas; as Tags existentes do Achado serão sobrescritas.

  ![bulk editing findings](images/Bulk_Editing_Findings.png)


## Gerenciamento de Tags (Classic UI / OpenSource)

### Adicionando e Removendo

As tags podem ser gerenciadas das seguintes formas:

1. Criando ou Editando novos objetos

   Quando um novo objeto é criado ou editado pela UI ou pela API, há um campo para especificar
   as tags a serem definidas em um determinado objeto. Esse campo é um campo de seleção múltipla que também conta com
   preenchimento automático, tornando fácil buscar e adicionar tags existentes. Veja como o campo
   se parece no Produto a partir da captura de tela da seção anterior:

   ![Tag management on an object](images/tags-management-on-object.png)

2. Importar e Reimportar

    As tags também podem ser aplicadas a um determinado teste no momento da importação ou reimportação. Esse é um caso de uso muito
    útil ao importar via API com automação, pois oferece a oportunidade de
    anexar detalhes de execução de automação e informações da ferramenta que talvez não sejam capturadas diretamente no objeto teste
    ou achado. 

    O campo se parece e se comporta exatamente como em um determinado objeto

3. Menu de Edição em Massa (apenas Achados)

    Quando é necessário atualizar muitos Achados com o mesmo conjunto de tags, o menu de edição em massa pode ser
    usado para facilitar essa tarefa.

    No exemplo a seguir, digamos que eu queira atualizar as tags dos dois achados com a tag "tag-group-alpha" para uma nova lista de tags como esta ["tag-group-charlie", "tag-group-delta"]. 
    Primeiro eu selecionaria as tags a serem atualizadas:

    ![Select findings for bulk edit tag update](images/tags-select-findings-for-bulk-edit.png)

    Uma vez selecionado um achado, um novo botão aparece com o nome "Bulk Edit". Clicar nesse botão
    exibe um menu suspenso com muitas opções, mas por enquanto o foco é apenas nas tags. Atualize o
    campo com a lista de tags desejada, conforme a seguir, e clique em enviar

    ![Apply changes for bulk edit tag update](images/tags-bulk-edit-submit.png)

    As tags nos Achados selecionados serão atualizadas para o que foi especificado no campo de tags
    dentro do menu de edição em massa

    ![Completed bulk edit tag update](images/tags-bulk-edit-complete.png)

## Herança de Tags

**Nota da Pro UI: embora a herança de Tags possa ser configurada usando a Pro UI, as Tags herdadas atualmente só podem ser acessadas e filtradas pela Classic UI ou pela API.**

Quando a Herança de Tags está habilitada, as tags aplicadas a um determinado Produto serão automaticamente aplicadas a todos os objetos abaixo de Produtos na [Hierarquia de Produtos](/asset_modelling/os_hierarchy/product_hierarchy/).

### Configuração

A Herança de Tags pode ser habilitada nos seguintes níveis de escopo:
- Escopo Global
  - Todo Produto do sistema passará a aplicar tags a todos os objetos filhos (Engajamentos, Testes e Achados)
  - Isso é definido nas Configurações do Sistema
- Escopo de Produto
  - Apenas o Produto selecionado passará a aplicar tags a todos os objetos filhos (Engajamentos, Testes e Achados)
  - Isso é definido na página de criação/edição do Produto

### Comportamentos

Quando a Herança de Tags está habilitada, as Tags padrão podem ser adicionadas e removidas dos objetos da forma usual.
No entanto, as tags herdadas não podem ser removidas de um objeto filho sem removê-las do objeto pai
Veja o exemplo a seguir de adição de uma tag "test_only_tag" ao objeto Teste e de uma tag "engagement_only_tag" ao Engajamento.

![Example of inherited tags](images/tags-inherit-exmaple.png)

Quando são feitas atualizações na lista de tags de um Produto, as mesmas alterações são feitas de forma assíncrona em todos os objetos dentro do Produto. A duração dessa tarefa está diretamente relacionada ao número de objetos contidos em um achado.

**Open-Source:** Se as alterações de Tag não forem observadas dentro de um período razoável, consulte os logs do celery worker para identificar onde possam ter surgido problemas.


### Filtrando por Tags (Classic UI)

As tags podem ser filtradas de várias maneiras, tanto pela UI quanto pela API. Por exemplo, aqui está um trecho
dos filtros de Achado:

![Snippet of the finding filters](images/tags-finding-filter-snippet.png)

Existem dez campos relacionados a tags:

 - Tags: filtra por quaisquer tags que estejam anexadas a um determinado Achado
   - Exemplos:
     - O Achado será retornado
       - Tags do Achado: ["A", "B", "C"]
       - Consulta do Filtro: "B"
     - O Achado *não* será retornado
       - Tags do Achado: ["A", "B", "C"]
       - Consulta do Filtro: "F"
 - Not Tags: filtra por quaisquer tags que *não* estejam anexadas a um determinado Achado
   - Exemplos:
     - O Achado será retornado
       - Tags do Achado: ["A", "B", "C"]
       - Consulta do Filtro: "F"
     - O Achado *não* será retornado
       - Tags do Achado: ["A", "B", "C"]
       - Consulta do Filtro: "B"
 - Tag Name Contains: filtra por quaisquer tags que contenham parte ou a totalidade da consulta no Achado em questão
   - Exemplos:
     - O Achado será retornado
       - Tags do Achado: ["Alpha", "Beta", "Charlie"]
       - Consulta do Filtro: "et" (parte de "Beta")
     - O Achado *não* será retornado
       - Tags do Achado: ["Alpha", "Beta", "Charlie"]
       - Consulta do Filtro: "meg" (parte de "Omega")
 - Not Tags: filtra por quaisquer tags que *não* contenham parte ou a totalidade da consulta no Achado em questão
   - Exemplos:
     - O Achado será retornado
       - Tags do Achado: ["Alpha", "Beta", "Charlie"]
       - Consulta do Filtro: "meg" (parte de "Omega")
     - O Achado *não* será retornado
       - Tags do Achado: ["Alpha", "Beta", "Charlie"]
       - Consulta do Filtro: "et" (parte de "Beta")

Quanto aos outros seis filtros de tag, eles seguem as mesmas regras de "Tags" e "Not Tags" como acima,
mas em níveis diferentes do modelo de dados:

 - Tags (Test): filtra por quaisquer tags que estejam anexadas ao Teste de um determinado Achado
 - Not Tags (Test): filtra por quaisquer tags que *não* estejam anexadas ao Teste de um determinado Achado
 - Tags (Engagement): filtra por quaisquer tags que estejam anexadas ao Engajamento de um determinado Achado
 - Not Tags (Engagement): filtra por quaisquer tags que *não* estejam anexadas ao Engajamento de um determinado Achado
 - Tags (Product): filtra por quaisquer tags que estejam anexadas ao Produto de um determinado Achado
 - Not Tags (Product): filtra por quaisquer tags que *não* estejam anexadas ao Produto de um determinado Achado
