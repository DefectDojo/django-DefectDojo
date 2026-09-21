---
title: Formulário Import Scan
description: ''
weight: 1
audience: opensource
---

Depois que você configurar sua Hierarquia de Produtos com pelo menos um Tipo de Produto, Produto, Teste e Engajamento, você pode importar um arquivo de varredura para o DefectDojo e criar Achados.

É fácil reorganizar sua Hierarquia de Produtos no DefectDojo, então não há problema se você ainda não tiver certeza de como configurar tudo.

Por enquanto, é bom saber que os **Engajamentos** podem armazenar dados de múltiplas ferramentas, o que pode ser útil se você estiver executando ferramentas diferentes simultaneamente como parte de um único esforço de teste.

## Acessando o formulário Import Scan (Classic UI / Open Source)

No DefectDojo OS, você pode acessar esse formulário em dois locais:

* Na seção Testes de um Engajamento:
    ![image](images/import_scan_os.png)
* Na seção Achados da barra de navegação de um Produto:
    ![image](images/import_scan_os_2.png)

## Preenchendo o formulário Import Scan

![image](images/import_scan_ui.png)
O formulário Import Scan criará um novo Teste aninhado sob um Engajamento, que conterá um Achado exclusivo para cada vulnerabilidade contida no seu arquivo de varredura.

O Teste será criado com um nome que corresponde ao Scan Type: por exemplo, uma varredura Tenable será intitulada ‘Tenable Scan’.

### Opções do formulário

* **Scan File:** clicando no botão Choose, você pode selecionar um arquivo do seu computador para upload.
* **Scan Date (optional):** se você quiser selecionar uma única Scan Date a ser aplicada a todos os Achados resultantes desta importação, pode selecionar a data neste campo.
Se você não selecionar uma Scan Date, os Achados criados a partir deste relatório usarão a data especificada pela ferramenta. Os SLAs de cada Achado serão calculados com base em sua data.
* **Scan Type:** selecione a ferramenta usada para criar esses dados.
* **Environment:** selecione um Environment que corresponda aos dados que você está enviando.
* **Tags:** se você quiser usar tags para organizar ainda mais os dados do seu Teste, pode adicionar Tags usando este formulário. Digite o nome da tag que deseja criar e pressione Enter no teclado para adicioná-la à lista de tags.

### Campos opcionais

* **Minimum Severity**: se você quiser criar Achados apenas para um determinado nível de Severidade e acima, pode selecionar o nível mínimo de Severidade aqui. Todas as vulnerabilidades com severidade inferior a este campo serão ignoradas.
* **Ativo**: se você quiser definir todos os Achados recebidos como Ativo ou Inativo, pode especificar isso aqui. Caso contrário, o DefectDojo usará os dados de vulnerabilidade da ferramenta para determinar se o Achado está Ativo ou Inativo. Essa opção é relevante se você precisar que sua equipe trie e verifique manualmente os Achados de uma determinada ferramenta.
* **Verificado**: assim como o Ativo, você pode definir o novo conjunto de Achados como Verificado ou Não verificado por padrão. Isso depende das preferências de fluxo de trabalho da sua equipe. Por exemplo, se sua equipe prefere presumir que os Achados estão verificados a menos que se prove o contrário, você pode definir este campo como True.
* **Version, Branch Tag, Commit Hash, Build ID, Service** podem ser especificados se você quiser incluir esses detalhes no Teste.
* **Source Code Management URI** também pode ser especificado. Essa opção do formulário deve ser um URI válido.
* **Group By:** se você quiser criar Finding Groups a partir deste arquivo, pode especificar o método de agrupamento aqui.

### Scanners sem triagem: campo Do Not Reactivate

Alguns scanners podem não incluir informações de triagem em seus relatórios (por exemplo, tfsec). Eles simplesmente escaneiam código ou dependências, sinalizam problemas e retornam tudo, independentemente de uma vulnerabilidade já ter sido triada ou não.

Para lidar com esse caso, o DefectDojo também inclui uma caixa de seleção "Do not reactivate" no envio de relatórios (também na API de reimportação), para que você possa usar o DefectDojo como fonte da verdade para a triagem, em vez de reativar seus Achados já triados a cada importação/reimportação.

### Usando o campo Scan Completion Date (API: `scan_date`)

O DefectDojo oferece suporte a uma infinidade de relatórios de scanner, mas nem todos contêm as informações mais importantes para o usuário. O campo `scan_date` é um recurso inteligente e flexível que permite aos usuários definir a data de conclusão de um determinado relatório de varredura, propagando-a para todos os achados importados. Esse campo **não** é obrigatório, mas seu valor padrão é a data da importação (o momento em que a requisição é processada e uma resposta bem-sucedida é retornada).

Confira os seguintes casos de uso para este campo:

1. O relatório **não** define a data, e o `scan_date` **não** é definido na importação
    - A data do Achado será o valor padrão de `scan_date`
2. O relatório **define** a data, e o `scan_date` **não** é definido na importação
    - A data do Achado será a que o relatório definir
3. O relatório **não** define a data, e o `scan_date` **é definido** na importação
    - A data do Achado será a que o usuário definir para `scan_date`
4. O relatório **define** a data, e o `scan_date` **é definido** na importação
    - A data do Achado será a que o usuário definir para `scan_date`
