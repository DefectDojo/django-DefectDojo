---
title: Formulário de Adicionar Achados
description: ''
weight: 1
audience: pro
aliases:
- /pt-br/en/connecting_your_tools/import_scan_files/import_scan_ui
---

Se você tem uma instância novinha em folha do DefectDojo, o Formulário de Importação de Scan é um primeiro passo lógico para aprender o software e configurar seu ambiente. Nesse formulário, você envia um arquivo de scan de uma ferramenta compatível, o que criará Achados para representar essas vulnerabilidades. Ao preencher o formulário, você pode decidir se deseja:

* Armazenar esses Achados em um Tipo de Produto / Produto / Engajamento existente **ou**
* Criar um novo Tipo de Produto / Produto / Engajamento para armazenar esses Achados

É fácil reorganizar sua Hierarquia de Produtos no DefectDojo, então não tem problema se você ainda não tem certeza de como configurar as coisas. 

Por enquanto, é bom saber que **Engajamentos** podem armazenar dados de múltiplas ferramentas, o que pode ser útil se você estiver executando diferentes ferramentas simultaneamente como parte de um único esforço de teste.

## Acessando o Formulário de Importação de Scan (Pro UI)

O formulário de Importação de Scan pode ser acessado em vários locais:

1. Pela opção de menu **Import > Add Findings** na barra lateral
2. No **Menu '⋮' (pontos horizontais)** de um **Produto**, a partir de uma **Tabela de Produtos**
3. No **Menu de Engrenagem ⚙️** em uma **Página de Produto**

## Preenchendo o Formulário de Importação de Scan

O formulário de Importação de Scan criará um novo Teste aninhado sob um Engajamento, que conterá um Achado exclusivo para cada vulnerabilidade contida no seu arquivo de scan.

O Teste será criado com um nome que corresponde ao Tipo de Scan: por exemplo, um scan da Tenable será intitulado 'Tenable Scan'.

### Opções do Formulário

* **Scan File:** clicando no botão Choose, você pode selecionar um arquivo do seu computador para enviar.
* **Scan Date (opcional):** se você quiser selecionar uma única Data de Scan a ser aplicada a todos os Achados resultantes desta importação, você pode selecionar a data neste campo.   
Se você não selecionar uma Data de Scan, os Achados criados a partir deste relatório usarão a data especificada pela ferramenta. Os SLAs de cada Achado serão calculados com base em sua data.
* **Scan Type:** selecione a ferramenta usada para criar esses dados.
* **Product Type / Product / Engagement Name:** selecione o Tipo de Produto, o Produto e o Nome do Engajamento sob os quais você deseja criar um novo Teste. Você também pode criar um novo Tipo de Produto, Produto e/ou Engajamento neste momento, se desejar, digitando os nomes dos objetos que deseja criar.
* **Environment:** selecione um Ambiente que corresponda aos dados que você está enviando.
* **Tags:** se você quiser usar tags para organizar ainda mais os dados do seu Teste, pode adicionar Tags usando este formulário. Digite o nome da tag que deseja criar e pressione Enter no teclado para adicioná-la à lista de tags.
* **Process Findings Asynchronously**: este campo é habilitado por padrão, mas pode ser desabilitado se você desejar. Veja a explicação abaixo.

### Process Findings Asynchronously

Quando este campo está habilitado, o DefectDojo usará um processo em segundo plano para popular seu arquivo de Teste com Achados. Isso permite que você continue trabalhando com o DefectDojo enquanto os Achados estão sendo criados a partir do seu arquivo de scan.

Quando este campo está desabilitado, o DefectDojo aguardará até que todos os Achados tenham sido criados com sucesso antes que você possa prosseguir para a próxima tela. Isso pode levar um tempo significativo dependendo do tamanho do seu arquivo.

Essa opção é especialmente relevante ao usar a API para importar dados. Se você enviar dados com o Process Findings Asynchronously **desativado**, o DefectDojo não retornará uma resposta de sucesso até que todos os Achados tenham sido criados com sucesso, 

### Optional Fields

Para abrir os Campos Opcionais, clique no botão rotulado **"Optional Fields +"** acima do botão **Submit**

![image](images/import_scan_ui.png)

#### Descrições dos Campos Opcionais
* **Minimum Severity**: Se você quiser criar Achados apenas para um determinado nível de Severidade e acima, pode selecionar o nível mínimo de Severidade aqui. Todas as vulnerabilidades com severidade menor do que este campo serão ignoradas.
* **Active**: se você quiser definir todos os Achados recebidos como Ativo ou Inativo, pode especificar isso aqui. Caso contrário, o DefectDojo usará os dados de vulnerabilidade da ferramenta para determinar se o Achado está Ativo ou Inativo. Essa opção é relevante se você precisar que sua equipe faça a triagem e verificação manual dos Achados de uma ferramenta específica.
* **Verified**: assim como com Active, você pode definir o novo conjunto de Achados como Verified ou Unverified por padrão. Isso depende das preferências de fluxo de trabalho da sua equipe. Por exemplo, se sua equipe preferir assumir que os Achados estão verificados a menos que se prove o contrário, você pode definir este campo como True.
* **Version, Branch Tag, Commit Hash, Build ID, Service** podem todos ser especificados se você quiser incluir esses detalhes no Teste.
* **Source Code Management URI** também pode ser especificado. Essa opção do formulário deve ser um URI válido.
* **Group By:** se você quiser criar Grupos de Achados a partir deste arquivo, pode especificar o método de agrupamento aqui.

### Close Old Findings

Ao importar um scan, você pode fechar automaticamente os Achados de scans anteriores que não estão mais presentes no novo relatório. Habilite isso marcando a caixa de seleção **Close Old Findings** na UI ou definindo `close_old_findings: true` na API.

#### Escopo: Engagement vs. Product

Por padrão, `close_old_findings` fecha Achados do mesmo tipo de scan dentro do **mesmo Engajamento**. O DefectDojo Pro adiciona uma segunda opção — **Close Old Findings Within This Product** — que amplia o escopo para todos os Achados do mesmo tipo de scan em todo o **Produto**, independentemente do Engajamento ao qual pertençam.

| Option | UI checkbox | API parameter | Scope |
|---|---|---|---|
| Fechar achados antigos (escopo de engajamento) | **Close Old Findings** | `close_old_findings: true` | Mesmo Engajamento |
| Fechar achados antigos (escopo de produto) | **Close Old Findings Within This Product** | `close_old_findings_product_scope: true` | Produto inteiro |

`close_old_findings_product_scope` requer que `close_old_findings` também esteja habilitado. Definir `close_old_findings_product_scope` sem `close_old_findings` não tem efeito.

> **Nota:** `close_old_findings_product_scope` se aplica apenas ao endpoint de Import (`/import-scan`). Não tem efeito no endpoint de Reimport (`/reimport-scan`), onde o escopo é sempre limitado ao Teste atual.

O campo `service` também é respeitado: apenas Achados com um valor de `service` idêntico (ou sem valor de `service`, caso nenhum tenha sido especificado no momento da importação) serão considerados para fechamento.

### Scanners sem triagem: campo Do Not Reactivate

Alguns scanners podem não incluir informações de triagem em seus relatórios (por exemplo, tfsec). Eles simplesmente escaneiam código ou dependências, sinalizam problemas e retornam tudo, independentemente de uma vulnerabilidade já ter sido triada ou não.

Para lidar com esse caso, o DefectDojo também inclui uma caixa de seleção "Do not reactivate" no envio de relatórios (também na API de reimport), para que você possa usar o DefectDojo como fonte da verdade para triagem, em vez de reativar seus Achados já triados a cada import / reimport.

### Usando o campo de Data de Conclusão do Scan (API: `scan_date`)

O DefectDojo oferece uma infinidade de relatórios de scanners compatíveis, mas nem todos contêm a informação mais importante para um usuário. O campo `scan_date` é um recurso inteligente e flexível que permite aos usuários definir a data de conclusão de um determinado relatório de scan, e propagá-la para todos os achados importados. Este campo **não** é obrigatório, mas o valor padrão para este campo é a data da importação (sempre que a requisição é processada e uma resposta de sucesso é retornada).

Aqui estão os seguintes casos de uso para este campo:

1. O relatório **não** define a data, e `scan_date` **não** é definido na importação
    - A data do Achado será o valor padrão de `scan_date`
2. O relatório **define** a data, e `scan_date` **não** é definido na importação
    - A data do Achado será o que o relatório definir
3. O relatório **não** define a data, e `scan_date` **é** definido na importação
    - A data do Achado será o que o usuário definir para `scan_date`
4. O relatório **define** a data, e `scan_date` **é** definido na importação
    - A data do Achado será o que o usuário definir para `scan_date`
