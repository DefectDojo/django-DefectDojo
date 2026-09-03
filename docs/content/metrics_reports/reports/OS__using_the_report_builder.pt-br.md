---
title: Usando o Construtor de Relatórios
description: Crie, execute e obtenha um relatório personalizado no DefectDojo open
  source
draft: false
audience: opensource
weight: 24
slug: using-the-report-builder
aliases:
- /pt-br/en/share_your_findings/pro_reports/working_with_generated_reports
- /pt-br/metrics_reports/reports/working_with_generated_reports
---

O construtor de relatórios do DefectDojo permite montar um relatório personalizado a partir de um conjunto de widgets de conteúdo, executá-lo e exportar o resultado (por exemplo, imprimindo-o em PDF). Relatórios personalizados podem resumir os Achados ou Endpoints que você deseja compartilhar com um público externo, e podem incluir identidade visual e texto padrão.

> **Nota:** No DefectDojo open source, você cria um relatório, o executa e obtém sua saída como um esforço pontual. Os layouts de relatório (templates) e a saída do relatório gerado **não são salvos** na versão open source. Para reutilizar um layout, você o reconstrói no construtor de relatórios. Para salvar Temas, Blocos e Templates reutilizáveis, e manter um histórico persistente dos relatórios gerados, consulte o [Report Builder](../report-builder/) do DefectDojo Pro.

## Abrindo o Construtor de Relatórios

O Construtor de Relatórios pode ser aberto a partir da página **📄 Relatórios** na barra lateral.

![image](images/Using_the_Report_Builder.png)

A página do construtor de relatórios é organizada em duas colunas. A coluna esquerda **Formato do Relatório** é onde você projeta seu relatório, usando widgets da coluna direita **Widgets Disponíveis**.

![image](images/Using_the_Report_Builder_2.png)

## Etapa 1: Definir as opções do relatório

![image](images/Using_the_Report_Builder_3.png)

Na seção Opções do Relatório, você pode realizar as seguintes ações:

* Definir um **Nome do Relatório** para o relatório
* Incluir **Notas do Achado** criadas pelo usuário no relatório
* Incluir **Imagens do Achado** no relatório
* Fazer upload de uma imagem de cabeçalho **Image** para o relatório

### Selecionar uma imagem de cabeçalho para o seu relatório

Para adicionar uma imagem ao topo do seu relatório, clique no botão **Choose File** e faça upload de uma imagem para o DefectDojo.

A imagem será redimensionada automaticamente para se ajustar ao documento, e será renderizada diretamente acima do seu **Nome do Relatório**.

![image](images/Using_the_Report_Builder_4.png)

## Etapa 2: Adicionar conteúdo com widgets

Depois de definir as opções do relatório, você pode começar a projetar seu relatório usando os widgets do DefectDojo.

Widgets são elementos de conteúdo de um relatório que você adiciona arrastando e soltando na coluna **Formato do Relatório**. O relatório final será gerado com base na posição de cada widget, com o **Nome do Relatório** e a **Imagem de Cabeçalho** renderizados no topo.

* Os elementos do seu relatório podem ser reordenados arrastando e soltando seus widgets em uma nova ordem.
* Para remover um widget de um relatório, clique e arraste-o de volta para a coluna direita.
* Os widgets também podem ser recolhidos clicando no cabeçalho cinza, para facilitar a navegação pelo construtor de relatórios.
* O widget de Achados, o widget WYSIWYG e o widget de Endpoints podem ser usados mais de uma vez cada.

Para mais informações sobre os widgets de relatório, consulte o [Índice de widgets de relatório](./#report-widget-index).

## Etapa 3: Executar e visualizar o relatório

Depois de concluir a construção do seu relatório, você pode gerá-lo clicando no botão verde **Run** na parte inferior da seção **Formato do Relatório**.

O DefectDojo gera o relatório a partir dos widgets que você montou. Quando a geração é concluída, você pode visualizar o relatório HTML resultante no seu navegador.

![image](images/Using_the_Report_Builder_14.png)

Um relatório gerado é uma captura pontual dos dados: ele reflete os dados no DefectDojo no momento em que foi executado e não é atualizado automaticamente conforme seus dados mudam.

## Etapa 4: Exportar o relatório

Os relatórios são configurados para que possam ser exportados ou impressos facilmente.

O método mais simples é imprimir em PDF. Com o relatório HTML aberto, abra uma caixa de diálogo de **Impressão** no seu navegador e defina **Salvar como PDF** como o **Destino de Impressão**.

![image](images/Using_the_Report_Builder_15.png)

## Sugestões de formatação de relatório

* Seções WYSIWYG podem ser usadas para contextualizar ou resumir listas de Achados. Considere usar esse widget ao longo do seu relatório, entre widgets de Achados ou de Endpoints Vulneráveis.

## Índice de widgets de relatório

### Widget Cover Page

O widget Cover Page permite definir um título, um subtítulo e metadados adicionais para o seu relatório. Você só pode ter uma única Cover Page para um determinado relatório.

![image](images/Using_the_Report_Builder_5.png)

### Widget Executive Summary

O widget Executive Summary tem como objetivo resumir seu relatório rapidamente. Ele contém um título (o padrão é Executive Summary), além de uma caixa de texto que pode conter qualquer informação que você julgue necessária para resumir o relatório.

![image](images/Using_the_Report_Builder_6.png)

Você também pode **Incluir SLAs** no seu resumo executivo. Para adicionar imagens, formatação de marcação ou qualquer coisa além de texto puro, considere adicionar um **widget WYSIWYG Content** imediatamente após o resumo executivo.

* Você só pode ter um único Executive Summary para um determinado relatório.
* Se o seu relatório contiver múltiplas configurações de SLA (por exemplo, você tem Achados de Produtos separados, cada um com seus próprios padrões de SLA), cada configuração de SLA será listada no Executive Summary como uma linha separada.

### Widget Severities

Como cada organização terá definições diferentes para cada nível de severidade, o widget Severities permite definir os níveis de severidade usados no seu relatório para facilitar o entendimento.

![image](images/Using_the_Report_Builder_7.png)

### Widget Table of Contents

O widget Table of Contents cria uma lista de cada Achado no seu relatório, para acesso mais rápido a Achados específicos. O índice cria um título separado para cada severidade contida no relatório. Cada Achado listado no índice possui um link âncora anexado para pular rapidamente até o Achado no relatório.

![image](images/Using_the_Report_Builder_8.png)

* Você pode adicionar uma seção de **Custom Content**, que adicionará texto abaixo do título.
* Você pode fazer upload de uma imagem para o Table of Contents clicando no botão **Choose File** ao lado da linha **Image**. A imagem enviada será renderizada diretamente acima do título selecionado. As imagens serão redimensionadas para se ajustar ao documento.

### Widget WYSIWYG Content

O widget WYSIWYG (What You See Is What You Get) pode ser usado para adicionar uma seção contendo texto e imagens no seu relatório. Múltiplas cópias desse widget podem ser adicionadas para fornecer contexto a outras seções do seu relatório.

![image](images/Using_the_Report_Builder_9.png)

* O WYSIWYG Content pode incluir um título opcional.
* Imagens podem ser adicionadas a um widget WYSIWYG arrastando e soltando diretamente na caixa **Content**. Imagens inseridas na caixa Content serão renderizadas em sua resolução total.
* Você pode adicionar múltiplos widgets WYSIWYG a um relatório.

### Widget Findings

O widget Findings fornece uma lista e um resumo de cada Achado que você deseja incluir no seu relatório. Você pode definir o escopo dos Achados que deseja incluir usando filtros.

O widget Findings é dividido em duas seções. A seção superior contém uma lista de filtros que podem ser usados para determinar quais Achados você deseja incluir, e a seção inferior contém a lista resultante de Achados após a aplicação dos filtros.

Para aplicar filtros ao seu widget Findings, defina os parâmetros de filtro e clique no botão **Apply Filter** na parte inferior. Você pode pré-visualizar os resultados do seu filtro conferindo a lista de Achados localizada abaixo da seção Filters.

![image](images/Using_the_Report_Builder_10.png)

* Assim como os widgets, a seção Filters pode ser expandida e recolhida clicando no cabeçalho cinza Filters.
* Você pode adicionar múltiplos widgets Findings separados ao seu relatório com diferentes parâmetros de filtro, caso deseje que o relatório contenha mais de uma lista de Achados.
* Apenas os Achados que você está autorizado a visualizar são incluídos nessas listagens, respeitando o Controle de Acesso Baseado em Função.

#### Exemplo de lista de Achados renderizada

![image](images/Using_the_Report_Builder_11.png)

### Widget Vulnerable Endpoints

O widget Vulnerable Endpoints é semelhante ao widget Findings. Você pode usar esse widget para listar todos os Achados de Endpoints específicos, e ordenar a lista de Achados por Endpoint em vez de por nível de severidade.

O widget **Vulnerable Endpoints** lista cada Achado ativo para os Endpoints selecionados. Em vez de criar uma única lista de Achados não ordenados, esse recurso os separa por contexto de Endpoint.

Assim como o widget Findings, o widget Vulnerable Endpoints é dividido em uma seção Filter e uma lista de Endpoints resultantes dos parâmetros de filtro.

![image](images/Using_the_Report_Builder_12.png)

Selecione aqui os parâmetros para os Endpoints que deseja incluir e clique no botão **Apply Findings** na parte inferior. Você pode pré-visualizar os resultados do seu filtro conferindo a lista de Endpoints localizada abaixo da seção Filters.

* Você pode adicionar múltiplos widgets Vulnerable Endpoints separados ao seu relatório com diferentes parâmetros de filtro, caso deseje que o relatório contenha mais de uma lista.
* Apenas os Achados que você está autorizado a visualizar são incluídos nessas listagens, respeitando o Controle de Acesso Baseado em Função.

### Widget ---- (separador)

Esse widget renderiza uma linha horizontal cinza-claro para dividir as seções.

![image](images/Using_the_Report_Builder_13.png)
