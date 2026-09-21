---
title: Report Builder
description: Crie relatórios personalizados e reutilizáveis no DefectDojo Pro com
  Temas, Blocos e Templates
draft: false
audience: pro
weight: 20
slug: report-builder
aliases:
- /pt-br/en/share_your_findings/pro_reports/using_the_report_builder
- /pt-br/metrics_reports/reports/using_the_report_builder
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: O Report Builder reutilizável (Temas, Blocos, Templates e Relatórios Gerados salvos) é um recurso do DefectDojo Pro, atualmente em beta.</span>

O Report Builder do DefectDojo Pro permite compor relatórios refinados a partir de partes reutilizáveis, para que você monte as peças uma vez e as reutilize em todos os lugares, em vez de reconstruir um relatório do zero a cada vez. Você o acessa pela área **📄 Reporting** na barra lateral.

## Como se compara à versão open source

O DefectDojo open source pode criar um relatório, executá-lo e permitir que você obtenha a saída, mas **não** salva templates de relatório nem persiste os relatórios que você gera. Cada relatório é um esforço pontual.

O DefectDojo Pro transforma a geração de relatórios em blocos de construção reutilizáveis. Você salva **Temas**, **Blocos** e **Templates** que pode combinar, misturar e reutilizar, e todo relatório que você executa é persistido como um **Relatório Gerado** que pode baixar ou executar novamente mais tarde. O Pro também expõe todo o fluxo de trabalho por meio de uma API REST completa e oferece suporte à criação assistida por LLM, de modo que os relatórios podem ser criados e executados de forma programática.

> **💡 Dica:** Se você está usando o DefectDojo open source, consulte o [construtor de relatórios open source](../using-the-report-builder/).

## Conceitos principais

O Report Builder é composto por quatro partes, cada uma disponível como um recurso REST em `/api/v2/`: `report_themes`, `report_blocks`, `report_templates` e `generated_reports`. Entender como elas se encaixam é a chave para criar relatórios com eficiência.

### Temas

Um **Tema** controla o estilo visual e a identidade de marca de um relatório: as cores, as imagens de cabeçalho e rodapé, e o texto do rodapé. Ao definir um Tema uma única vez, você pode aplicar uma identidade corporativa consistente a todos os relatórios que produzir.

Um Tema possui as seguintes configurações:

| Configuração | Finalidade | Padrão |
|---------|---------|---------|
| Name | Um rótulo para o Tema | — |
| Primary color | Cor principal da marca | `#1e3a5f` |
| Secondary color | Cor de apoio da marca | `#4a90a4` |
| Accent color | Cor de destaque | `#e67e22` |
| Text color | Cor do texto do corpo | `#333333` |
| Background color | Cor de fundo da página | `#ffffff` |
| Footer text | Texto exibido no rodapé da página | — |
| Show page numbers | Se deve imprimir números de página | On |
| Header image | Imagem exibida no cabeçalho | — |
| Footer image | Imagem exibida no rodapé | — |

> **💡 Dica:** As cinco cores são expressas como valores hexadecimais de 7 caracteres (por exemplo, `#1e3a5f`), para que você possa igualar a paleta de marca exata da sua organização.

Você pode criar isso pela interface (abaixo) ou automatizar com a [API](../report-builder-api/).

### Blocos

Um **Bloco** é uma unidade de conteúdo reutilizável. Você cria um Bloco uma vez, configura o que ele exibe e depois o insere em quantos Templates quiser. Existem quatro tipos de bloco:

| Tipo de bloco | O que produz |
|------------|------------------|
| **Stock** | Conteúdo não baseado em dados, como uma página de capa, um sumário, uma quebra de página, uma imagem ou um bloco de texto. |
| **Tabular** | Uma tabela de registros extraídos de uma única entidade. |
| **Detail** | Um layout por registro, ideal para campos longos que são renderizados como markdown (por exemplo, descrição, impacto, mitigação e referências). |
| **Chart** | Gráficos visuais. *Em breve* — esse tipo de bloco está definido no modelo de dados, mas ainda não está disponível na API ou na interface. |

Um bloco **Stock** é configurado escolhendo um dos cinco tipos de stock, junto com um título, subtítulo, conteúdo de texto ou imagem, conforme apropriado:

- **Cover page**
- **Table of contents**
- **Page break**
- **Image**
- **Text block**

Os blocos **Tabular** e **Detail** extraem ambos registros ativos de uma entidade. Você escolhe a entidade com uma seleção de modelo e, em seguida, seleciona quais campos incluir e como ordenar os registros. A escolha de modelo é exatamente uma destas sete entidades:

- **Organization**
- **Asset**
- **Engagement**
- **Test**
- **Finding**
- **Test type**
- **Risk acceptance**

> **💡 Dica:** No DefectDojo Pro, **Assets** eram anteriormente chamados de **Products** e **Organizations** eram anteriormente **Product Types**. Você ainda pode encontrar a nomenclatura legada em alguns nomes de campos e filtros subjacentes.

A diferença está na apresentação: um bloco **Tabular** organiza os registros como uma tabela de colunas, ideal para resumos e inventários, enquanto um bloco **Detail** renderiza um registro por vez em um layout longo, mais adequado para campos ricos em markdown, como descrição, impacto, mitigação e referências.

> **💡 Dica:** Os filtros ficam no Bloco, não no Template. Um Bloco carrega seus próprios filtros consigo, então reutilizar um Bloco reutiliza seus filtros de forma idêntica em todos os lugares em que ele aparece. Se você precisar do mesmo conteúdo, mas com um filtro diferente, duplique o Bloco e ajuste a cópia.

Você pode criar isso pela interface (abaixo) ou automatizar com a [API](../report-builder-api/).

### Templates

Um **Template** é uma lista ordenada de Blocos vinculada a um único Tema. O Template define o que aparece no relatório e em que ordem, enquanto o Tema ao qual está vinculado controla a aparência.

Como um Template referencia Blocos por inclusão, o mesmo Bloco pode aparecer em um Template mais de uma vez. Um Bloco reutilizável de quebra de página, por exemplo, pode ser inserido entre várias seções do mesmo relatório.

Você pode criar isso pela interface (abaixo) ou automatizar com a [API](../report-builder-api/).

### Relatórios Gerados

Executar um Template produz um **Relatório Gerado**: um arquivo PDF ou HTML persistido que você pode baixar e executar novamente sob demanda. Cada Relatório Gerado está **congelado no tempo** — ele captura seus dados do DefectDojo no momento em que foi gerado e **não** é atualizado automaticamente quando os dados subjacentes mudam depois. Para obter uma captura atualizada, execute o Template novamente.

Um Relatório Gerado passa pelos seguintes status enquanto é criado:

| Status | Significado |
|--------|---------|
| Pending | O relatório foi solicitado e está na fila. |
| Processing | O relatório está sendo montado. |
| Completed | O relatório está pronto para download. |
| Failed | O relatório não pôde ser gerado. |

> **🔑 Importante:** A geração de relatórios está ativada por padrão. Um superusuário pode ativá-la ou desativá-la em **Settings > Feature Flags** (consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/)). A visualização respeita o controle de acesso baseado em função (RBAC) do DefectDojo — os usuários só veem os dados que estão autorizados a visualizar, mesmo dentro de um relatório.

Você pode criar isso pela interface (abaixo) ou automatizar com a [API](../report-builder-api/).

## Criando um relatório pela interface

As etapas a seguir mostram como criar um relatório do início ao fim: criar um Tema, criar os Blocos que conterão seu conteúdo, montá-los em um Template e gerar o relatório final.

### Etapa 1: Criar um Tema

Comece na área de Temas. A lista de Temas mostra todos os Temas que você definiu e permite criar um novo.

![Themes list](images/pro_report_themes_list.png)

Abra um novo Tema para definir sua identidade visual. O formulário do Tema expõe as cinco cores, uma imagem opcional de cabeçalho e rodapé, o texto do rodapé e a opção de números de página. Escolha cores que combinem com a marca da sua organização para que todos os relatórios que você produzir tenham uma aparência consistente.

![Theme edit form](images/pro_report_theme_new.png)

### Etapa 2: Criar Blocos

Em seguida, crie os Blocos de conteúdo. A lista de Blocos mostra todos os seus Blocos de todos os tipos.

![Blocks list](images/pro_report_blocks_list.png)

Para criar um Bloco baseado em dados, escolha seu tipo e configure-o. O exemplo abaixo é um bloco **Tabular** nomeado para achados abertos: o Block Type está definido como Tabular, um cabeçalho é fornecido, o Model é **Finding**, os campos selecionados são Severity, Title, Product, Age (Days) e SLA Days Remaining, e os registros são ordenados por Numerical Severity em ordem decrescente. Como os filtros ficam no Bloco, as **Filter Entries** aqui delimitam exatamente quais registros esse Bloco trará onde quer que seja usado.

![Tabular block configuration](images/pro_report_block_new_tabular.png)

Você pode fazer o **Preview** de um Bloco para ver como ele será renderizado com um Tema aplicado antes de confirmá-lo em um Template. A pré-visualização abaixo mostra uma página de capa estilizada ("DefectDojo Security Report") adotando as cores e a identidade visual do Tema.

![Rendered block preview](images/pro_report_block_preview.png)

> **💡 Dica:** Use **Duplicate** para copiar um Bloco existente quando precisar do mesmo layout com um filtro diferente. Como os filtros viajam com o Bloco, duplicar é a maneira correta de produzir, por exemplo, uma tabela de "Achados críticos" e uma tabela de "Achados altos" a partir do mesmo layout de colunas.

### Etapa 3: Montar um Template

Com seus Blocos prontos, monte um Template. A lista de Templates mostra seus Templates salvos.

![Templates list](images/pro_report_templates_list.png)

No editor de Template, você seleciona um Tema e organiza os Blocos na ordem em que devem aparecer. O exemplo abaixo sequencia Cover Page → Executive Intro → Open Findings → KEV → Page Break → Asset Inventory. Use **Add Existing Block** para reutilizar um Bloco que você já criou, ou **Add New Block** para criar um na hora, e use as alças de arrastar para reordenar. Lembre-se de que o mesmo Bloco pode aparecer mais de uma vez — um único Bloco de quebra de página pode ser inserido entre várias seções.

![Template editor](images/pro_report_template_new.png)

### Etapa 4: Gerar e baixar

Quando o Template estiver pronto, gere o relatório. A caixa de diálogo de geração confirma o Template e permite escolher o formato de saída — **HTML** ou **PDF**.

![Generate report dialog](images/pro_generate_report_dialog.png)

Os relatórios gerados são reunidos na lista de Relatórios Gerados, que mostra o status de cada relatório, o formato do arquivo, o horário em que foi solicitado e concluído, e um link de download.

![Generated reports list](images/pro_generated_reports_list.png)

Você pode executar um Template novamente a qualquer momento para produzir um relatório atualizado. Lembre-se de que cada Relatório Gerado está congelado no tempo — ele reflete seus dados no momento em que foi gerado e não muda conforme os dados do DefectDojo mudam, então execute o Template novamente sempre que precisar de uma captura atualizada.

## Migrando do mecanismo de relatórios clássico

O mecanismo de relatórios clássico — as páginas **Report Builder**, **Report Templates** e **Generated
Reports** listadas em *Classic Report Engine* na barra lateral — será removido na versão
**3.3.0 (8 de setembro de 2026)**. Até lá, essas páginas exibem um aviso lembrando da
data, e tanto elas quanto este Report Builder oferecem uma migração de um clique.

### Migrando seus templates salvos

Use **Migrate to the new engine** em qualquer página clássica, ou **Import from Classic Engine**
em *All Report Templates* aqui. Ambos executam a mesma conversão, então não importa por qual
você comece, e ambos são seguros de executar mais de uma vez: um template clássico cujo nome
já existe aqui é reportado como *already migrated* em vez de duplicado.

Cada widget clássico se torna um Bloco:

| Widget clássico | Torna-se |
|----------------|---------|
| Cover Page | Bloco stock Cover Page |
| Table Of Contents | Bloco stock Table of Contents |
| Page Break | Bloco stock Page Break |
| Custom Content / WYSIWYG | Text Block |
| Findings | Bloco Tabular sobre Findings, mantendo os filtros do widget |
| Vulnerable Endpoints | Bloco Tabular sobre URLs |
| Severities | Bloco de gráfico Active Findings by Severity |

Dois não têm equivalente direto, e a migração informa isso por template, em vez de converter
esses widgets em algo aproximado:

- **Executive Summary** — o mecanismo clássico derivava isso de quaisquer widgets de Findings
  presentes no mesmo relatório. Não há Bloco agregado equivalente; reconstrua-o como um Text
  Block, se precisar.
- **Report Options** — não é um Bloco. Seu *Report name* se torna o nome do novo Template.
  Notas de achados, imagens de achados e quebras de página por widget são configurações em nível
  de Tema no novo mecanismo.

### O que acontece com os relatórios que você já executou

Nada. Os Relatórios Gerados produzidos pelo mecanismo clássico são arquivos finalizados, então não há
nada para converter. Eles permanecem listados e disponíveis para download até que o mecanismo seja removido — salve
tudo o que você quiser manter além da versão 3.3.0.

### Se o Report Builder estiver desativado

A migração ainda funciona com a feature flag **Reporting** desativada. Os Templates convertidos
simplesmente não aparecem até que a flag seja reativada, para que você possa migrar seus
templates no seu próprio ritmo.

## Próximos passos

- **[Report Builder API](../report-builder-api/)** — automatize todo o fluxo de trabalho (Temas, Blocos, Templates e Relatórios Gerados) para uma geração de relatórios repetível e automatizada.
- **[Report Builder com um LLM](../report-builder-llm/)** — use a criação assistida por LLM para projetar e criar relatórios de forma conversacional.
