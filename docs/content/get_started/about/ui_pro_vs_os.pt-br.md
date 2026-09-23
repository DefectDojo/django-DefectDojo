---
title: 🎨 Alterações da UI Pro
description: Trabalhando com diferentes UIs no DefectDojo
draft: 'false'
weight: 5
audience: pro
aliases:
- /pt-br/en/about_defectdojo/ui_pro_vs_os
---

No final de 2023, a DefectDojo, Inc. lançou uma nova UI para o DefectDojo Pro, que agora é a UI padrão desta edição.

A UI Pro traz os seguintes aprimoramentos para o DefectDojo:

- Design moderno e elegante usando Vue.js.
- Entrega de dados e tempos de carregamento otimizados, especialmente para grandes conjuntos de dados.
- Acesso a novos recursos Pro, incluindo as visualizações de [Upstream Connectors](/connectors/upstream/about/), [Universal Importer](/import_data/pro/specialized_import/external_tools/) e [Pro Metrics](/metrics_reports/pro_metrics/pro__overview/).
- Fluxos de trabalho de UI aprimorados: melhor filtragem, painéis e navegação.

## Alternando para a UI Pro

Para acessar a UI Pro, abra o menu de Opções do usuário no canto superior direito. Você também pode voltar para a UI Clássica pelo mesmo menu.

![image](images/beta-classic-uis.png)

## Alterações de navegação

![image](images/pro_ui_overview.png)

1. A **Barra lateral** foi reorganizada em quatro categorias principais: Dashboards, Import, Manage e Settings.

2. A Página inicial, os [recursos nativos de conexão de API baseados em IA](/metrics_reports/ai/mcp_server_pro/), as Métricas Pro e a visualização de Calendário estão todos acessíveis em Dashboards.

4. Os métodos de importação podem ser encontrados na seção Import: configure [Connectors](/connectors/about/) para trazer achados dos seus scanners (Upstream) ou enviá-los para rastreadores de issues (Downstream), use o formulário [Add Findings](/import_data/import_scan_files/pro__import_scan_ui/) para adicionar achados, use o [Smart Upload](/import_data/pro/specialized_import/smart_upload/) para lidar com ferramentas de scan de infraestrutura, ou use nossas ferramentas externas — [Universal Importer e DefectDojo CLI](/import_data/pro/specialized_import/external_tools/) — para simplificar os processos de importação e reimportação de Achados e objetos associados.

5. A seção **Manage** permite visualizar diferentes objetos na [Hierarquia de produtos](/asset_modelling/os_hierarchy/product_hierarchy/), com visualizações para Tipos de produto, Produtos, Engajamentos, Testes, Achados, Aceitações de risco, Endpoints e Componentes.  Há seções adicionais para gerar relatórios (Report Builder), usar pesquisas (Surveys), além de um [Rules Engine](/automation/rules_engine/about/).

5. A seção **Settings** permite configurar sua instância do DefectDojo, incluindo sua Licença, Configurações de nuvem, Usuários, Configuração de recursos e Configurações empresariais de nível administrativo. (As integrações foram movidas para **Import > Connectors > Downstream Connectors**.)

6. A seção **Settings** contém as páginas administrativas, agrupadas como System, Users & Permissions, Finding Workflow, Configuration, Notifications, Operations e License & Support, com uma página **All Settings** que lista e permite pesquisar todas elas. Veja [O menu de configurações](/navigation/pro__settings_menu/).

7. A UI Pro também possui um **novo formato de tabela**, usado na [Hierarquia de produtos](/asset_modelling/os_hierarchy/product_hierarchy/) para ajudar na navegação. Cada coluna pode ser clicada para aplicar um filtro relevante, e as colunas podem ser reordenadas para apresentar os dados da forma que você preferir.

8. A tabela também possui um menu **"Toggle Columns"**, que pode adicionar ou remover colunas da tabela.

## Filtrando a tabela

Nesta captura de tela, estamos filtrando todos os Achados que estão em "Sam's Awesome Product." Ao clicar em Apply, o conteúdo desta lista de Achados será atualizado para refletir o filtro escolhido.

![image](images/pro_ui_sams_filter.png)

## Novos painéis

Novas visualizações de Métricas estão incluídas na UI Pro. Todos esses relatórios podem ser filtrados e exportados como PDFs para compartilhá-los com um público mais amplo.

![image](images/program_insights.png)

- O painel **Executive Insights** exibe o estado atual dos seus Produtos e Tipos de produto.
- **Priority Insights** mostra os achados mais críticos com a opção de filtrar por diversos períodos, Tipos de produto, Produtos e Tags.
- O painel **Program Insights** exibe a eficácia da sua equipe de segurança e a economia de custos associada à separação de duplicados e falsos positivos dos Achados acionáveis.
- **Remediation Insights** exibe a eficácia da sua equipe na remediação de Achados.
- **Tool Insights** exibe a eficácia do seu conjunto de ferramentas (e dos pipelines de Upstream Connector) na detecção e no reporte de vulnerabilidades.
