---
title: Gerenciando Operações
description: Verifique o status das Operações de Discover e Sync do seu Conector
aliases:
- /pt-br/import_data/pro/connectors/manage_operations/
- /pt-br/en/connecting_your_tools/connectors/manage_operations
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Conectores Upstream são um recurso exclusivo do DefectDojo Pro.</span>

Depois que um Conector Upstream é configurado, ele executará duas Operações de forma recorrente:

* **Discover** vai aprender a estrutura da ferramenta conectada e criará registros no DefectDojo para quaisquer dados não mapeados;
* **Sync** vai importar novos Findings da ferramenta com base nos seus mapeamentos.

Ambas essas Operações são gerenciadas na página de Operações de um Conector. A tabela também registrará as execuções anteriores dessas Operações, para que você possa garantir que seu Conector esteja atualizado.

Para acessar a página de Operações de um Conector, abra **Manage Records & Operations** para o Conector com o qual deseja trabalhar, e depois mude para a aba **</\> Operations From (tool)**.

![image](images/operations_discover.png)

A página **Manage Records & Operations** também pode ser usada para gerenciar Records; que são os mapeamentos individuais de Produto da sua ferramenta conectada.  Veja [Gerenciando Records](../manage_records) para mais informações.

## A Página de Operações

![image](images/operations_page.png)

Cada entrada na tabela da página de Operações é o registro de um evento de operação, com as seguintes características:

* **Type** descreve se o evento foi uma operação de **Sync** ou de **Discover**.
* **Status** descreve se o evento foi executado com sucesso.
* **Trigger** descreve como o evento foi disparado \- foi uma operação **Scheduled**, executada automaticamente, ou uma operação **Manual**, disparada por um usuário do DefectDojo?
* O **Start \& End Time** de cada operação é registrado aqui, junto com a **Duration**.

## Operações de Discover

O primeiro passo que um Conector do DefectDojo precisa dar é fazer o **Discover** do ambiente da sua ferramenta para ver como você está organizando seus dados de scan.

Digamos que você tenha uma ferramenta BurpSuite, configurada para escanear cinco repositórios diferentes em busca de vulnerabilidades. Seu Conector vai identificar essa estrutura organizacional e configurar **Records** para ajudar a traduzir esses repositórios separados na hierarquia de Produto/Engajamento/Teste do DefectDojo.

### Criando Novos Records

Toda vez que seu Conector executa uma operação de **Discover**, ele vai procurar por novos **Vendor-Equivalent-Products (VEPs)**. O DefectDojo observa a forma como a ferramenta do fornecedor está configurada e criará **Records** de VEPs com base em como sua ferramenta está organizada.

![image](images/operations_discover_2.png)

### Executar o Discover Manualmente

As operações de **Discover** são executadas automaticamente em uma base regular, mas também podem ser executadas manualmente. Se você estiver configurando esse Conector pela primeira vez, pode clicar no botão **Discover** ao lado do cabeçalho **Unmapped Records**. Depois de atualizar a página, você verá sua lista inicial de **Records**.

![image](images/operations_discover_3.png)

Para saber mais sobre como trabalhar com records e configurar mapeamentos para Produtos, veja nosso guia [Gerenciando Records](../manage_records).

## Operações de Sync

Diariamente, o DefectDojo vai verificar cada **Mapped Record** em busca de novos dados de scan. O DefectDojo então executará uma **Reimport**, que compara o estado dos dados de scan existentes com um relatório recebido.

### Onde os dados de vulnerabilidade são armazenados?

* O DefectDojo criará um **Engagement** aninhado sob o Produto especificado no **Record Mapping**. Esse Engagement será chamado de **Global Connectors**.
* O Engagement **Global Connectors** rastreará cada Conector separado associado ao Produto como um **Test**.
* Nessa sincronização, e em cada sincronização subsequente, o **Test** armazenará cada vulnerabilidade encontrada pela ferramenta como um **Finding**.

### Como o Sync lida com novos dados de vulnerabilidade

Sempre que o Sync é executado, ele compara os dados de scan mais recentes com a lista existente de Findings em busca de alterações.

* Se houver novos Findings detectados, eles serão adicionados ao Test como novos Findings.
* Se houver Findings que não forem detectados no scan mais recente, eles serão marcados como Inactive no Test.

Para saber mais sobre Products, Engagements, Tests e Findings, veja nossa [Visão Geral da Hierarquia de Produtos](/asset_modelling/os_hierarchy/product_hierarchy/).

### Executando o Sync Manualmente

Para que o DefectDojo execute uma operação de Sync fora do horário agendado:

1. Navegue até a página **Manage Records \& Operations** do conector que deseja usar. Na página **Upstream Connectors**, clique no menu suspenso **Manage Configuration** do Conector com o qual deseja trabalhar, e selecione **Manage Records \& Operations**.
​
2. Nessa página, clique no botão **Sync**. Esse botão está localizado ao lado do cabeçalho **Mapped Records**.

![image](images/operations_sync.png)
