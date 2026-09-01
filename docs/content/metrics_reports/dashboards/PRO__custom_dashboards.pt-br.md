---
title: Painéis Personalizáveis
description: Monte painéis personalizados no DefectDojo Pro a partir de widgets organizados
  em uma grade de arrastar e soltar
draft: false
audience: pro
weight: 10
slug: custom-dashboards
aliases:
- /pt-br/en/customize_dojo/dashboards/about_custom_dashboard_tiles
- /pt-br/metrics_reports/dashboards/about_custom_dashboard_tiles
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Observação: os Painéis Personalizáveis (layouts, widgets e o catálogo de widgets) são um recurso do DefectDojo Pro. Eles ficam desativados por padrão — um superusuário pode ativá-los em **Settings > Feature Flags**, tanto em instâncias Cloud quanto On-Premise.</span>

Os Painéis Personalizáveis do DefectDojo Pro permitem que cada usuário monte sua própria página inicial a partir de **widgets** — contadores, gráficos, rankings, feeds e notas — organizados em uma grade de arrastar e soltar. Em vez de um único painel fixo para todos, você constrói os **layouts** que fazem sentido para você: uma visão executiva, uma fila de triagem, um painel de velocidade de remediação, uma visão de eficácia de scanners. Você pode manter layouts privados, publicá-los para toda a sua equipe, definir um deles como sua página inicial padrão e clonar qualquer layout (seu ou um modelo compartilhado) como ponto de partida.

![Um painel personalizável do DefectDojo Pro — o layout Painel Padrão.](images/pro_dashboard_v2_default.png)

## Comparação com a versão open source

O DefectDojo open source tem um único [Painel Principal](../introduction_dashboard/) integrado, com um conjunto fixo de cartões de resumo e gráficos que um superusuário pode mostrar ou ocultar. Ele é igual para todos os usuários.

O DefectDojo Pro substitui essa página fixa por **painéis personalizáveis por usuário**. Você escolhe quais widgets aparecem, como são filtrados e onde ficam posicionados na grade. É possível criar qualquer número de layouts nomeados, alternar entre eles, compartilhá-los com sua equipe e controlar todo o sistema a partir da [REST API](../custom-dashboards-api/) ou de um [LLM](../custom-dashboards-llm/).

> **💡 Tip:** No DefectDojo Pro, **Ativos** eram anteriormente chamados de **Produtos**, e **Organizações** eram anteriormente **Tipos de Produto**. A interface usa a nova nomenclatura, mas algumas configurações internas de widgets ainda usam os nomes antigos — por exemplo, a maioria dos widgets recebe um `model` com valor `finding`, `product`, `engagement` ou `test`. Quando isso for relevante, será indicado abaixo.

## Ativando os Painéis Personalizáveis

Os Painéis Personalizáveis ficam desativados por padrão. Um superusuário pode ativá-los em **Settings > Feature Flags**, tanto em instâncias Cloud quanto On-Premise. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Depois de ativado, a página **🏠 Home** exibe seu painel personalizável, e a [Dashboards REST API](../custom-dashboards-api/) fica disponível.

> **🔑 Important:** Enquanto o recurso estiver desativado, a página inicial mantém o painel anterior e todo endpoint `/api/v2/dashboards/` retorna `403 Dashboards 2.0 is not enabled.` Ativar o recurso **não** altera o acesso de ninguém aos dados — cada widget continua respeitando o controle de acesso baseado em função do DefectDojo, portanto cada usuário só verá os Achados, Ativos e outros registros que estiver autorizado a visualizar.

## Conceitos fundamentais

Um painel personalizável é construído a partir de algumas peças simples.

### Layouts

Um **layout** é um painel nomeado: uma coleção de widgets e suas posições na grade. Cada layout pertence a você, e você pode ter quantos quiser — por exemplo, um painel "Daily Triage" e outro separado "Exec Overview." Um layout armazena três coisas:

- **widgets** — a lista ordenada de widgets que ele contém, cada um com seu próprio tipo, título e configuração.
- **layout** — onde cada widget fica posicionado e qual o seu tamanho na grade.
- **settings** — opções de exibição em nível de layout.

Na primeira vez que você abre os Painéis Personalizáveis, o DefectDojo fornece uma cópia pessoal do modelo inicial **Painel Padrão**, para que você nunca comece com uma página em branco.

### Widgets

Um **widget** é um único painel dentro do dashboard. Cada widget é uma instância de um **tipo** do catálogo (um Count, um Graph, um Top-N leaderboard, e assim por diante), e carrega sua própria **configuração**: qual **model** de dados ele lê (`finding`, `product`, `engagement` ou `test`), quais **filters** o delimitam, e opções de exibição específicas do tipo, como tipo de gráfico, cores ou agrupamento. Dois widgets do mesmo tipo com filtros diferentes são completamente independentes.

Cada widget também tem um **intervalo de atualização automática** opcional (desativado, 30 segundos, 1 minuto, 5 minutos ou 15 minutos) e um **título** editável.

### O catálogo de widgets

O **catálogo** é o menu fixo dos tipos de widget aceitos pela plataforma, agrupados em quatro categorias — **Numbers**, **Charts**, **Lists & Feeds** e **Static & Utility**. Ao adicionar um widget, você escolhe o tipo dele a partir do catálogo. O catálogo também está disponível pela [API](../custom-dashboards-api/), para que scripts e LLMs possam descobrir os tipos de widget disponíveis e uma configuração inicial já validada para cada um. Consulte [O catálogo de widgets](#the-widget-catalog-1) abaixo para a lista completa.

### A grade

Os widgets são posicionados em uma **grade de 12 colunas**. No modo de edição, você arrasta os widgets para movê-los e arrasta o canto inferior direito para redimensioná-los; a grade se compacta para cima para preencher os espaços vazios. Cada tipo de widget tem tamanhos mínimo e máximo adequados, para que gráficos e tabelas permaneçam legíveis.

### Compartilhamento, clonagem e padrões

- **Padrão** — um dos seus layouts é o seu padrão: aquele que carrega quando você abre a página inicial. Você pode alterar qual layout é o seu padrão a qualquer momento.
- **Clonar** — copia qualquer layout (um seu, ou um modelo compartilhado) para o seu próprio espaço como um novo ponto de partida independente. A clonagem dá à cópia seus próprios widgets, portanto editar o clone nunca afeta o original.
- **Compartilhar** — publica um dos seus layouts para toda a equipe como um **layout compartilhado**. Outros usuários podem vê-lo e cloná-lo, mas somente um **Mantenedor** da equipe pode publicar, editar ou descompartilhar um layout compartilhado. Compartilhar um layout compartilha apenas o seu *design* — cada pessoa que o visualiza continua vendo apenas os dados que suas próprias permissões permitem.
- **Modelos iniciais e compartilhados** — o DefectDojo inclui um conjunto de **modelos compartilhados** selecionados que você pode clonar para começar com vantagem (veja [Modelos compartilhados](#shared-templates) abaixo). O **Painel Padrão** é o modelo "inicial" especial que os novos usuários recebem automaticamente.

## Construindo um painel na interface

### A barra de ferramentas do painel

A barra de ferramentas na parte superior da página inicial é onde você alterna entre layouts e os gerencia. Ela inclui um **seletor de layout** (com selos que indicam seu layout padrão e quaisquer layouts/modelos compartilhados), além de botões para criar um **New Layout**, abrir **Manage Layouts**, atualizar (**Refresh**) todos os widgets e alternar o modo **Edit**.

![A barra de ferramentas do painel (destacada): o seletor de layout, além de New Layout, Manage Layouts, Refresh e Edit](images/pro_dashboard_v2_home.png)

### Etapa 1: Entrar no modo de edição

Clique em **Edit** para desbloquear o painel. A grade passa a ser arrastável e redimensionável, e um botão **Add Widget** aparece. Clique em **Done** quando terminar — o modo de edição também é desativado automaticamente ao trocar de layout.

![Um painel no modo de edição, mostrando alças de arrastar e redimensionar](images/pro_dashboard_v2_edit_grid.png)

### Etapa 2: Adicionar um widget

No modo de edição, clique em **Add Widget** para abrir o seletor. Ele tem duas abas:

- **By Type** — navegue pelo catálogo por categoria (Numbers, Charts, Lists & Feeds, Static & Utility). Cada cartão mostra o nome do widget e uma breve descrição. Selecionar um o adiciona à grade e abre sua caixa de diálogo de configuração.
- **From Catalog** — comece a partir de um widget pré-configurado retirado de um dos modelos compartilhados (por exemplo, o gráfico "Findings by Severity" do Painel Padrão). Esses vêm prontos, então caem diretamente na grade.

![O diálogo Add Widget, aba By Type](images/pro_dashboard_v2_add_widget.png)

### Etapa 3: Configurar o widget

Cada widget abre uma caixa de diálogo de configuração específica para o seu tipo. As configurações comuns incluem:

- **Title** — o título exibido no widget.
- **Model** — quais registros o widget lê (Finding, Asset, Engagement ou Test), quando aplicável.
- **Filters** — uma interface de filtro de lista incorporada que restringe o widget exatamente aos registros que você quer (por exemplo, achados Críticos ativos). Os filtros escolhidos aqui são os mesmos que você usaria na página de lista daquele objeto.
- **Refresh interval** — com que frequência o widget é recarregado automaticamente.
- **Type-specific options** — por exemplo, o tipo de gráfico e a dimensão de agrupamento para um Graph, os limites para um Gauge, ou a métrica para um Top-N leaderboard.

![Configurando um widget Graph](images/pro_dashboard_v2_widget_config.png)

> **💡 Tip:** Os dados de um widget sempre respeitam suas permissões. Se um layout compartilhado incluir um widget "My Work", cada pessoa que o visualiza vê *suas próprias* atribuições e menções — não as do autor do layout.

### Etapa 4: Organizar e salvar

Arraste os widgets para reorganizá-los e arraste um canto para redimensioná-los. Use o ícone de engrenagem de um widget para reconfigurá-lo, e o ícone de lixeira para removê-lo. As alterações de posição e tamanho são salvas automaticamente conforme você trabalha. Clique em **Done** para sair do modo de edição.

### Gerenciando layouts

A caixa de diálogo **Manage Layouts** (o botão de engrenagem na barra de ferramentas) é o centro de controle para tudo relacionado a layouts:

- **Your Layouts** — renomeie, defina como padrão, compartilhe/descompartilhe, clone ou exclua cada layout que você possui.
- **Create New** — inicie um layout novo e vazio para construir do zero.
- **Shared Templates** — navegue pelos layouts selecionados e publicados pela equipe, agrupados por categoria, e clique em **Use Layout** para clonar um para o seu próprio espaço.

![A caixa de diálogo Manage Layouts](images/pro_dashboard_v2_manage_layouts.png)

### Modelos compartilhados

O DefectDojo inclui quatro modelos compartilhados prontos para uso, que você pode clonar como ponto de partida:

| Template | Purpose |
|----------|---------|
| **Painel Padrão** | A visão inicial clássica — 12 contadores rápidos, gráficos de severidade e ativos com melhor/pior nota. É o modelo inicial que todo novo usuário recebe automaticamente. |
| **Layout de Prioridade** | Um painel focado em triagem, construído em torno da prioridade e do risco dos achados. |
| **Layout de Mitigação** | Um painel de velocidade de remediação (tendências de encerramento, MTTR/MTTD, envelhecimento). |
| **Layout de Ferramentas** | Um painel de eficácia de scanners, construído em torno dos tipos de teste e da atividade de scan recente. |

> **💡 Tip:** Clonar um modelo cria uma cópia independente. Personalize o clone livremente — você não afetará o modelo nem qualquer outra pessoa que o clone.

### O estado vazio

Um layout novinho em folha, sem widgets, mostra uma mensagem **"Build Your First Dashboard"**. Clique em **Add Your First Widget** para ir direto ao modo de edição e começar a escolher widgets.

![O estado de layout vazio](images/pro_dashboard_v2_empty_state.png)

## O catálogo de widgets

Os Painéis Personalizáveis vêm com os seguintes tipos de widget, organizados em quatro categorias. A maioria dos widgets lê um de quatro models — `finding`, `product` (Ativos), `engagement` ou `test` — e é delimitada pelos filtros que você escolher. As opções de configuração detalhadas de cada widget estão documentadas no [guia da API](../custom-dashboards-api/).

### Numbers

Métricas de relance — contadores, KPIs e medidores.

| Widget | O que exibe |
|--------|---------------|
| **Count** | Um único número resultante de uma consulta filtrada — por exemplo, "Open Critical Findings" ou "Active Engagements." Funciona com finding / asset / engagement / test. |
| **KPI / Trend** | Um número principal, mais sua variação em relação ao período anterior, com um sparkline opcional. |
| **Gauge** | Uma proporção representada como um medidor em arco — um filtro "universo" como denominador e um filtro "aprovado" como numerador. Use para conformidade com SLA, taxa de mitigação ou cobertura de scan, com limites configuráveis de aviso/normal. |
| **License Usage** | O status de uso de licença da sua conta, com um detalhamento por sinal (tamanho do banco de dados, volume semanal de achados, e assim por diante). *Requer a função Mantenedor.* |
| **Scan Coverage** | Qual fração dos ativos foi escaneada nos últimos 30 / 90 / 180 / 365 dias, como um resumo multi-janela. |

### Charts

Visualizações de séries temporais e distribuições.

| Widget | O que exibe |
|--------|---------------|
| **Graph** | Um gráfico de uso geral sobre qualquer model e dimensão de agrupamento — barras, linha, área, pizza ou rosca. Ex.: Achados por Severidade, Achados por Mês. |
| **Sankey** | Um diagrama de fluxo de uma dimensão de origem para uma dimensão de destino — por exemplo, Severidade → Status. |
| **Sunburst** | Um detalhamento radial de um ou dois níveis — por exemplo, Severidade e, dentro de cada severidade, o Tipo de Teste. |
| **Risk Matrix** | Um mapa de calor de achados cruzando probabilidade EPSS × risco — seguro no canto inferior esquerdo, perigoso no canto superior direito. |
| **Priority Histogram** | A distribuição das pontuações de **prioridade** dos achados geradas pelo motor de priorização, com faixas automáticas. |
| **Rate by Category** | Uma proporção por categoria (numerador / denominador) — por exemplo, Taxa de Falso Positivo por Ferramenta ou Taxa de Mitigação por Ativo. |
| **Finding Velocity** | Achados criados versus encerrados ao longo do tempo, mostrando se o backlog está crescendo ou diminuindo. |
| **MTTR / MTTD** | Tempo Médio de Remediação e Tempo Médio de Detecção, como séries temporais pareadas. |
| **Vulnerability Aging** | Achados abertos agrupados por faixa de idade (0–30d / 30–90d / 90–180d / 180d+), empilhados por severidade. |
| **Activity Heatmap** | Um calendário de atividade diária, no estilo GitHub, ao longo de uma janela móvel. |
| **Portfolio Treemap** | Retângulos aninhados para um resumo de portfólio (Organização → Ativo), dimensionados pela contagem e coloridos pela severidade. |

### Lists & Feeds

Listas classificadas, feeds e tabelas incorporadas.

| Widget | O que exibe |
|--------|---------------|
| **Top-N Leaderboard** | Uma lista classificada em um de dois modos: *aggregate* (principais grupos de uma dimensão por contagem, ex.: Top 10 CWEs) ou *records* (principais registros individuais por uma métrica, ex.: Top 10 Ativos por Nota). |
| **Embedded Table** | Uma visualização de lista completa (Achados, Ativos, Engajamentos, Testes, Aceitações de Risco, Organizações ou Tipos de Teste) com filtros e ordenação predefinidos — incluindo paginação, ordenação e exportação em CSV. |
| **Recent Activity** | Um feed rolável dos registros atualizados mais recentemente, com links para as páginas de detalhe. |
| **SLA Burndown** | Achados próximos de violar o SLA, classificados pelos dias restantes, com selos de contagem regressiva. |
| **My Work** | Sua fila pessoal — atribuições, menções e revisões de aceitação de risco pendentes. Sempre limitada a quem está visualizando. |
| **Saved Reports** | Acesso com um clique aos seus Modelos de Relatório salvos. *Requer o recurso de Relatórios.* |

### Static & Utility

Notas, atalhos e estrutura.

| Widget | O que exibe |
|--------|---------------|
| **Favorites** | Links rápidos, selecionados pelo usuário, para páginas específicas do aplicativo. |
| **Section Break** | Um divisor com rótulo para agrupar widgets relacionados sob um título. |
| **Markdown / Notes** | Um painel de texto rico embutido para cabeçalhos, notas de contexto ou links de referência. |
| **Quick Actions** | Botões de ação de um clique que navegam até uma página escolhida. |

## Próximos passos

- **[Automatizando Painéis com a API](../custom-dashboards-api/)** — descubra o catálogo de widgets, crie e atualize layouts, e renderize dados de widgets pela REST API, com um script completo.
- **[Construindo Painéis com um LLM](../custom-dashboards-llm/)** — deixe um LLM projetar e construir painéis para você (a API de dashboards foi criada pensando em agentes de IA).
