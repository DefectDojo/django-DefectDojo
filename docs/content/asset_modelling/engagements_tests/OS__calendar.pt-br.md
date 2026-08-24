---
title: Calendário
description: Como usar o Calendário no DefectDojo Pro
audience: opensource
weight: 9
---

O Calendário do DefectDojo oferece uma visão cronológica centralizada de todos os Engajamentos e Testes com datas de início e término definidas, permitindo que os Usuários entendam rapidamente a atividade de testes entre os Produtos, identifiquem sobreposições de agenda e naveguem diretamente para os objetos relacionados.

Quando um Usuário cria um Engajamento ou Teste e define as datas de início e término, uma entrada correspondente é adicionada automaticamente ao Calendário. As entradas aparecem em todas as datas a partir da data de início definida até a data de término definida, inclusive.

## Acessando o Calendário

A página do Calendário é acessível por meio do botão Calendar na barra lateral.

![image](images/OSC_ss3.png)

## Visibilidade e Permissões

### Visibilidade

A página do Calendário inclui filtros na parte superior e uma grade mensal do Calendário abaixo. Use os controles de navegação acima do Calendário para se mover entre os meses.

A visualização mensal é exibida como uma grade fixa de seis semanas, começando pela semana que contém o primeiro dia do mês selecionado.

As entradas visíveis no Calendário podem ser filtradas com base no tipo de objeto (Engajamentos ou Testes) e no Líder de Testes, definido nas configurações do Engajamento ou Teste. Depois de selecionar os critérios de filtro, clique em Apply para atualizar a visualização do Calendário.

Apenas um tipo de objeto pode ser exibido por vez. Alternar entre Engajamentos e Testes atualiza a visualização do Calendário de acordo.

### Permissões

O Calendário respeita as permissões em nível de objeto do DefectDojo. Os Usuários só veem os Engajamentos e Testes aos quais têm autorização para acessar.

## Visualizando e Interagindo com Entradas

Dentro de cada célula de data, as entradas são ordenadas alfabeticamente com base no nome do objeto. Clicar em uma entrada redireciona para o objeto correspondente.

O número de entradas visíveis em cada dia é dinâmico e varia dependendo do tamanho da tela e do nível de zoom do navegador. Se o número de entradas exceder o espaço disponível em uma célula de data, um link no formato “+X more” aparece na parte inferior da célula.

![image](images/OSC_ss1.png)

Clique no link “+X more” para abrir um modal exibindo todas as entradas daquela data.

![image](images/OSC_ss2.png)

É importante notar que o Calendário em si é uma visualização somente leitura. As datas devem ser modificadas nas configurações do próprio objeto de Engajamento ou Teste.

### Lógica de Nomenclatura

A nomenclatura das entradas no Calendário varia ligeiramente dependendo do tipo de objeto.

As entradas de Engajamento incluem:
- Nome do Produto
- Nome do Engajamento
- Líder de Testes

As entradas de Teste incluem:
- Nome do Produto
- Nome do Engajamento
- Tipo de Teste
- Líder de Testes
