---
title: Painel Principal do DefectDojo
description: Trabalhando com a página inicial do DefectDojo
weight: 1
audience: opensource
aliases:
- /pt-br/en/customize_dojo/dashboards/Introduction_dashboard
- /pt-br/en/customize_dojo/dashboards/pro_dashboards
---

O Painel é provavelmente a primeira página que você verá ao abrir o DefectDojo. Ele resume o desempenho da sua equipe e oferece ferramentas de acompanhamento para monitorar áreas específicas do seu ambiente de gestão de vulnerabilidades.

<div class="version-opensource">

![imagem](images/dashboard.png)

</div>
<div class="version-pro">

> **💡 DefectDojo Pro:** No DefectDojo Pro, a página inicial é um **painel totalmente personalizável** — você o monta a partir de widgets e os organiza você mesmo, em vez de usar o layout fixo descrito abaixo. Consulte **[Painéis Personalizáveis](../custom-dashboards/)** para conhecer os conceitos e um passo a passo da interface. O restante desta página descreve o Painel Principal da versão open source.

</div>

<div class="version-opensource">

## Componentes do Painel

O painel da versão open source oferece uma visão geral de alto nível da sua postura de segurança com os seguintes componentes integrados:

### Cartões de Resumo

A linha superior do painel exibe quatro cartões de resumo que oferecem uma visão rápida da atividade:

* **Engajamentos Ativos** — número total de Engajamentos atualmente abertos em todos os Produtos.
* **Achados dos Últimos 7 Dias** — novos Achados criados na última semana.
* **Encerrados nos Últimos 7 Dias** — Achados que foram resolvidos recentemente.
* **Aceitos nos Últimos 7 Dias** — Achados que tiveram o risco aceito recentemente.

Cada cartão leva diretamente à lista filtrada correspondente, permitindo aprofundar a análise com um único clique.

### Histórico de Severidade dos Achados

Esse gráfico de pizza detalha todos os Achados já criados no DefectDojo por Severidade (Crítica, Alto, Médio, Baixo, Informativa), oferecendo uma leitura rápida da distribuição geral de vulnerabilidades no seu ambiente.

### Severidade dos Achados Reportados por Mês

Esse gráfico de linha traça o volume e a severidade dos Achados recebidos mês a mês, ajudando você a identificar tendências, como picos após a integração de um novo scanner ou melhora sustentada resultante dos esforços de remediação.

### Configuração do Painel

Superusuários podem alternar quais gráficos aparecem no painel. Navegue até o menu de engrenagem no canto superior direito e selecione **Edit Dashboard Configuration** para mostrar ou ocultar:

* **Exibir Gráficos** — controla os gráficos de Histórico de Severidade dos Achados e de Severidade dos Achados Reportados.
* **Exibir Pesquisas** — controla a tabela de Questionários de Engajamento Respondidos Não Atribuídos.
* **Exibir Tabelas de Dados** — controla as tabelas dos 10 Melhores / 10 Piores Produtos Avaliados.

Selecione **Reset Dashboard Configuration** no mesmo menu para restaurar os padrões.

</div>
