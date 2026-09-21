---
title: Aplicando Tags a Objetos
description: Use Tags para criar um novo recorte do seu modelo de dados
draft: false
weight: 2
exclude_search: false
audience: opensource
---

As Tags são ideais para agrupar objetos de uma forma que pode ser filtrada em partes menores e mais digeríveis. Elas podem ser usadas para indicar status ou para criar conjuntos personalizados de Organizações, Ativos, Engajamentos ou Achados em todo o modelo de dados.

No DefectDojo, as tags são um elemento de primeira classe e são reconhecidas como facilitadoras
da organização em cada nível do modelo de dados.

Aqui está um exemplo de um Ativo com duas tags e quatro achados, cada um com uma única tag:

![Exemplo de alto nível do uso de tags](images/tags-high-level-example.png)

### Formatos de Tag

As tags podem ser formatadas de qualquer uma das seguintes maneiras:
- StringWithNoSpaces
- string-with-hyphens
- string_with_underscores
- colons:acceptable

## Gerenciamento de Tags

### Adicionando e Removendo

As tags podem ser gerenciadas das seguintes formas:

1. Criando ou Editando novos objetos

   Quando um novo objeto é criado ou editado pela UI ou pela API, há um campo para especificar
   as tags a serem definidas em um determinado objeto. Esse campo é um campo de múltipla seleção que também
   conta com autocompletar, tornando muito mais fácil buscar e adicionar tags existentes. Veja como o campo
   aparece no Ativo do print de tela da seção anterior:

   ![Gerenciamento de tags em um objeto](images/tags-management-on-object.png)

2. Importação e Reimportação

    As tags também podem ser aplicadas a um determinado teste no momento da importação ou reimportação. Esse é
    um caso de uso muito útil ao importar via API com automação, pois oferece a oportunidade de anexar
    detalhes da execução da automação e informações da ferramenta que talvez não sejam capturadas
    diretamente no objeto de teste ou de achado.

    O campo tem a mesma aparência e o mesmo comportamento de quando está em um objeto qualquer

3. Menu de Edição em Massa (somente achados)

    Quando é necessário atualizar muitos Achados com o mesmo conjunto de tags, o menu de edição em massa pode
    ser usado para facilitar o trabalho.

    No exemplo a seguir, digamos que eu queira atualizar as tags dos dois achados com a tag "tag-group-alpha" para uma nova lista de tags como esta ["tag-group-charlie", "tag-group-delta"].
    Primeiro, eu selecionaria as tags a serem atualizadas:

    ![Selecionar achados para atualização de tags em massa](images/tags-select-findings-for-bulk-edit.png)

    Depois que um achado é selecionado, um novo botão aparece com o nome "Bulk Edit". Ao clicar nesse botão,
    aparece um menu suspenso com várias opções, mas o foco por enquanto é apenas nas tags. Atualize o
    campo com a lista de tags desejada, como a seguir, e clique em enviar

    ![Aplicar alterações da atualização de tags em massa](images/tags-bulk-edit-submit.png)

    As tags dos Achados selecionados serão atualizadas para o que foi especificado no campo de tags
    dentro do menu de edição em massa

    ![Atualização de tags em massa concluída](images/tags-bulk-edit-complete.png)

## Herança de Tags

Quando a Herança de Tags está habilitada, as tags aplicadas a um determinado Ativo serão automaticamente aplicadas a todos os objetos abaixo dos Ativos na [Hierarquia de Ativos](/asset_modelling/os_hierarchy/os__asset_hierarchy/).

### Configuração

A Herança de Tags pode ser habilitada nos seguintes níveis de escopo:
- Escopo Global
  - Todo Ativo em todo o sistema passará a aplicar tags a todos os objetos filhos (Engajamentos, Testes e Achados)
  - Isso é definido nas Configurações do Sistema
- Escopo de Ativo
  - Somente o Ativo selecionado passará a aplicar tags a todos os objetos filhos (Engajamentos, Testes e Achados)
  - Isso é definido na página de criação/edição do Ativo

### Comportamentos

Quando a Herança de Tags está habilitada, as Tags padrão podem ser adicionadas e removidas dos objetos da forma usual.
No entanto, as tags herdadas não podem ser removidas de um objeto filho sem removê-las do objeto pai
Veja o exemplo a seguir de adição de uma tag "test_only_tag" ao objeto Teste e uma tag "engagement_only_tag" ao Engajamento.

![Exemplo de tags herdadas](images/tags-inherit-exmaple.png)

Quando são feitas atualizações na lista de tags de um Ativo, as mesmas alterações são aplicadas de forma assíncrona a todos os objetos dentro do Ativo. A duração dessa tarefa está diretamente relacionada à quantidade de objetos contidos em um achado.

**Open Source:** Se as alterações de tags não forem observadas em um período de tempo razoável, consulte os logs do worker do celery para identificar onde possíveis problemas podem ter ocorrido.


### Filtragem por Tags (UI Clássica)

As tags podem ser filtradas de várias formas, tanto pela UI quanto pela API. Por exemplo, aqui está um trecho
dos filtros de Achado:

![Trecho dos filtros de achado](images/tags-finding-filter-snippet.png)

Há dez campos relacionados a tags:

 - Tags: filtra por quaisquer tags que estejam anexadas a um determinado Achado
   - Exemplos:
     - O Achado será retornado
       - Tags do Achado: ["A", "B", "C"]
       - Consulta de Filtro: "B"
     - O Achado *não* será retornado
       - Tags do Achado: ["A", "B", "C"]
       - Consulta de Filtro: "F"
 - Not Tags: filtra por quaisquer tags que *não* estejam anexadas a um determinado Achado
   - Exemplos:
     - O Achado será retornado
       - Tags do Achado: ["A", "B", "C"]
       - Consulta de Filtro: "F"
     - O Achado *não* será retornado
       - Tags do Achado: ["A", "B", "C"]
       - Consulta de Filtro: "B"
 - Tag Name Contains: filtra por quaisquer tags que contenham parte ou toda a consulta no Achado em questão
   - Exemplos:
     - O Achado será retornado
       - Tags do Achado: ["Alpha", "Beta", "Charlie"]
       - Consulta de Filtro: "et" (parte de "Beta")
     - O Achado *não* será retornado
       - Tags do Achado: ["Alpha", "Beta", "Charlie"]
       - Consulta de Filtro: "meg" (parte de "Omega")
 - Not Tags: filtra por quaisquer tags que *não* contenham parte ou toda a consulta no Achado em questão
   - Exemplos:
     - O Achado será retornado
       - Tags do Achado: ["Alpha", "Beta", "Charlie"]
       - Consulta de Filtro: "meg" (parte de "Omega")
     - O Achado *não* será retornado
       - Tags do Achado: ["Alpha", "Beta", "Charlie"]
       - Consulta de Filtro: "et" (parte de "Beta")

Os outros seis filtros de tags seguem as mesmas regras que "Tags" e "Not Tags" acima,
mas em níveis diferentes do modelo de dados:

 - Tags (Teste): filtra por quaisquer tags anexadas ao Teste de um determinado Achado
 - Not Tags (Teste): filtra por quaisquer tags que *não* estejam anexadas ao Teste de um determinado Achado
 - Tags (Engajamento): filtra por quaisquer tags anexadas ao Engajamento de um determinado Achado
 - Not Tags (Engajamento): filtra por quaisquer tags que *não* estejam anexadas ao Engajamento de um determinado Achado
 - Tags (Ativo): filtra por quaisquer tags anexadas ao Ativo de um determinado Achado
 - Not Tags (Ativo): filtra por quaisquer tags que *não* estejam anexadas ao Ativo de um determinado Achado
