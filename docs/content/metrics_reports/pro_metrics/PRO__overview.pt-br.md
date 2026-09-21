---
title: Visão Geral das Métricas Pro
description: Como aproveitar as métricas no DefectDojo Pro
audience: pro
weight: 2
---

A interface do DefectDojo Pro conta com vários painéis de Métricas para ajudar a visualizar sua postura de segurança atual. Cada painel permite que as partes interessadas em diferentes níveis da organização tomem decisões informadas sem precisar interpretar dados brutos ou navegar por Achados individuais. Esses painéis incluem:
* [Insights Executivos](/metrics_reports/pro_metrics/pro__executive_insights/#main-content)
* [Insights de Prioridade](/metrics_reports/pro_metrics/pro__priority_insights/#main-content)
* [Insights do Programa](/metrics_reports/pro_metrics/pro__program_insights/#main-content)
* [Insights de Remediação](/metrics_reports/pro_metrics/pro__remediation_insights/#main-content)
* [Insights de Ferramentas](/metrics_reports/pro_metrics/pro__tool_insights/#main-content)

![Visão geral das métricas](images/metrics_image1.png)

## Recursos de Métricas

Antes de detalhar cada painel específico, vale a pena revisar alguns pontos em comum entre todos eles.

### Filtragem

Todas as Métricas podem ser filtradas por período, Organização, Ativo e Tag. Depois de ajustar o filtro conforme desejado, é preciso clicar em Apply Filter para que ele entre em vigor. Se quiser exportar em PDF todos os gráficos, tabelas e diagramas do painel com a filtragem atual, clique em Export as PDF. 

O período de filtragem é limitado ao último ano, mas pode ser ajustado para incluir os últimos 7, 14, 30, 90 ou 180 dias.

Observe que os parâmetros de filtro são exibidos na URL, então você pode salvar como favoritas várias páginas com diferentes parâmetros de filtro.  Isso pode ser útil para referência rápida ou para gerar de forma consistente um determinado tipo de relatório.

### Submenus 

Cada gráfico tem um menu kebab ⋮ no canto superior direito de cada visualização, com os seguintes recursos:
* Force Refresh — Atualiza manualmente para incorporar novas atualizações nos dados. 
* Expand Plot — Abre o mesmo gráfico em um modal pop-up maior.
* Download Plot as SVG — Baixa o gráfico como um arquivo SVG.
* View as Table — Mostra os dados do gráfico em formato de tabela.
    * Cada coluna da tabela pode ser alternada para ordem crescente ou decrescente ao ser clicada. Também é possível baixar cada tabela.

![Conteúdo do menu kebab](images/metrics_image2.png)

### Acesso

A seção de Métricas exibirá apenas os dados das Organizações e Ativos que cada Usuário tem permissão para visualizar. Um Usuário com acesso limitado a um único Ativo só poderá ver as Métricas desse Ativo específico, mas, se ele não tiver acesso aos demais Ativos dentro da Organização pai, os dados desses outros Ativos não aparecerão nas Métricas. 

### Visualizando Dados nos Gráficos

O eixo X dos gráficos de linha sempre representará o período de filtragem atual. Passar o cursor sobre um gráfico de linha faz aparecer um modal com a contagem dos valores no eixo Y naquele ponto no tempo. 

![Modal pop-up do gráfico](images/metrics_image3.png)

### Alternando Resultados

Os Usuários podem alternar certas categorias de Achados entre visíveis e ocultas no gráfico clicando na respectiva cor/nome na parte superior de cada gráfico. 

Por exemplo, no gráfico de Achados Ativos por Severidade abaixo, se você quisesse ver apenas Achados com severidade Alto ou Crítica, bastaria clicar em Médio, Baixo e Informativa na parte superior para remover esses resultados do gráfico. Clicar em Médio, Baixo e Informativa novamente faria esses resultados reaparecerem. 

![GIF de alternância dos resultados do gráfico](images/metrics_image4.gif)
