---
title: 🌐 Universal Parser
description: ''
draft: 'false'
weight: 1
audience: pro
aliases:
- /pt-br/en/connecting_your_tools/universal_parser
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: o Universal Parser está disponível apenas no DefectDojo Pro.</span>

O Universal Parser está ativo em todas as instâncias do DefectDojo Pro; não há nada que precise ser habilitado. Consulte nossa [apresentação de lançamento](https://community.defectdojo.com/universalparser) para mais informações.

## Sobre o Universal Parser
O DefectDojo tem uma biblioteca grande e regularmente atualizada de parsers para ajudar as equipes de segurança a ingerir dados.  No entanto, às vezes os usuários têm uma ferramenta que não é suportada pelos parsers, ou desejam importar dados para o modelo do DefectDojo de uma forma diferente da que o parser utiliza.

O Universal Parser do DefectDojo tem como objetivo oferecer aos usuários com tipos de relatório não suportados um caminho a seguir, para importar e mapear **qualquer arquivo JSON, CSV ou XML**.

**O Universal Parser é:**

* Uma forma rápida de suportar formatos de arquivo para os quais não temos parsers da Community, como relatórios produzidos por ferramentas internas
* Uma ferramenta para ajudar você a ingerir dados, mesmo que um parser da Community esteja desatualizado ou não estruture os achados da forma que você gostaria
* Uma alternativa à criação de scripts personalizados para transformar relatórios de ferramentas no formato CSV/JSON esperado pelo tipo de varredura "Generic Findings Import"
* Projetado para ser fácil de usar por qualquer pessoa, sem necessidade de programação e com configuração mínima

**O Universal Parser não é:**

* Um substituto abrangente para parsers open source, Connectors, ou relatórios "Generic Findings Import" cuidadosamente ajustados
* Capaz de lidar com lógica ramificada e sutil para estruturar achados

A configuração do Universal Parser está disponível apenas na UI do Pro, embora você ainda possa importar varreduras usando um Universal Parser pela UI antiga ou pela API.

## Etapa 1: criando um novo Universal Parser

Você pode criar um novo Universal Parser clicando no botão "New Universal Parser" na barra de navegação, na seção "Import", ou pelo link na página "Add Findings".

![image](images/universal_parser.png)

A primeira tela pedirá um arquivo de varredura e um nome de parser.

![image](images/universal_parser_2.png)

O arquivo deve:

* Ter uma extensão reconhecida (veja as extensões de arquivo suportadas abaixo)
* Conter objetos semelhantes a achados em número suficiente para ser representativo de relatórios reais - ou seja, um que inclua valores em todos os campos opcionais
* Não ter mais do que cerca de 1-2MB - além desse ponto, geralmente o único efeito é que a análise do arquivo demora mais, sem nenhum benefício

O nome do parser será usado ao criar o Test_Type para esse novo parser. Você encontrará o Universal Parser recém-criado na lista suspensa de tipos de varredura na página "Add Findings", com um nome como "Universal Parser - MyCustomParser". Os nomes de parser devem ser exclusivos para evitar confusão ao selecionar um tipo de varredura para importações.

## Etapa 2: mapeando os campos do seu Achado

![image](images/universal_parser_3.png)

Depois de enviar um arquivo de varredura de exemplo, selecionar um nome de parser e clicar em "Next", a página seguinte permitirá configurar como esse Universal Parser preencherá os campos de achado ao usar essa configuração para realizar importações. À direita, você encontrará uma seleção dos campos de achado do DefectDojo (campos de saída). Menus suspensos à esquerda de cada campo de saída permitem selecionar qual(is) item(ns) (campos de entrada) da estrutura do seu arquivo de varredura deve(m) ser usado(s) para preenchê-los.

Exemplo:

Se você enviou um arquivo de varredura em formato JSON parecido com este:

```
{
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345",
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "LOW",
            "CVE": "CVE-2025-54321",
            ...
        },
        ...

    ]
}
```

Você verá uma representação hierárquica dos campos exclusivos detectados com base na estrutura do arquivo de entrada, com ícones indicando o tipo de cada campo (quando é possível determiná-lo). Você pode então selecionar o campo de entrada "title" no menu suspenso que preenche o campo de saída "Title", o campo de entrada "description" pode ser associado ao campo de saída "Description", e assim por diante.

Os nomes dos campos de entrada não precisam corresponder aos nomes dos campos de saída, e seu arquivo de varredura pode não ter um equivalente para todos os campos de saída do DefectDojo.

### Campos de achado mapeáveis

A tabela abaixo lista todos os campos de achado do DefectDojo (campos de saída) aos quais você pode mapear um campo de entrada. Seu arquivo de varredura não terá necessariamente um equivalente para todos eles — mapeie apenas o que estiver presente.

* **Obrigatório** — esse campo de saída precisa ter pelo menos um campo de entrada mapeado antes que você possa salvar o parser.
* **Aceita múltiplas entradas** — esse campo de saída pode ser preenchido a partir de mais de um campo de entrada. Quando você mapeia vários, cada valor é apresentado sob um cabeçalho com o nome do respectivo campo de entrada (veja [Multi-select fields](#multi-select-fields)).

| Campo de saída | Obrigatório | Aceita múltiplas entradas | Descrição |
|---|:---:|:---:|---|
| Title | ✅ | | Uma breve descrição da falha. |
| Severidade | ✅ | | O nível de severidade desta falha (Crítica, Alto, Médio, Baixo, Informativa). O padrão é "Informativa" quando desconhecido. |
| Description | ✅ | ✅ | Informações mais longas e descritivas sobre a falha. |
| Date | | | A data em que a falha foi descoberta. |
| CWE | | | O número CWE associado a esta falha. |
| CVSS v3 Vector | | | Vetor do Common Vulnerability Scoring System versão 3 (CVSSv3) associado a esta falha. |
| CVSS v4 Vector | | | Vetor do Common Vulnerability Scoring System versão 4 (CVSSv4) associado a esta falha. |
| Mitigation | | ✅ | Texto descrevendo a melhor forma de corrigir a falha. |
| Impact | | ✅ | Texto descrevendo o impacto que esta falha tem sobre sistemas, produtos, a empresa, etc. |
| References | | ✅ | A documentação externa disponível para esta falha. |
| Severity Justification | | ✅ | Texto descrevendo por que uma determinada severidade foi associada a esta falha. |
| Steps to Reproduce | | ✅ | Texto descrevendo os passos que devem ser seguidos para reproduzir a falha/bug. |
| Component Name | | | Nome do componente afetado (nome da biblioteca, parte de um sistema, ...). |
| Component Version | | | Versão do componente afetado. |
| File Path | | | Arquivo(s) identificado(s) contendo a falha. |
| Line Number | | | Número da linha de código do vetor de ataque. |
| Ativo | | | Indica se esta falha está ativa ou não. O padrão é true. |
| Verificado | | | Indica se esta falha foi verificada manualmente pelo testador. O padrão é false. |
| Falso positivo | | | Indica se esta falha foi considerada um falso positivo pelo testador. O padrão é false. |
| Duplicado | | | Indica se esta falha é uma duplicata de outras falhas relatadas. O padrão é false. |
| EPSS Score | | | Pontuação EPSS do CVE — a probabilidade de a vulnerabilidade ser explorada nos próximos 30 dias. O valor deve estar entre 0.0 e 1.0. |
| EPSS Percentile | | | Percentil EPSS do CVE — quantos CVEs têm pontuação igual ou inferior a este. O valor deve estar entre 0.0 e 1.0. |
| Unique ID From Tool | | | ID técnico da vulnerabilidade proveniente da ferramenta de origem. Permite o rastreamento de vulnerabilidades exclusivas. |
| Vuln ID from Tool | | | ID técnico não exclusivo, proveniente da ferramenta de origem, associado ao tipo de vulnerabilidade. |
| Tags | | | Tags de texto que ajudam a descrever este achado. |
| Endpoints | | | Os hosts/URLs dentro do produto que estão suscetíveis a esta falha. |
| Vulnerability IDs | | | Um ou mais identificadores de aviso de vulnerabilidade associados a este achado (mais comumente, CVEs). |

> **Nota:** No exemplo acima, um campo de entrada `CVE` seria mapeado para o campo de saída **Vulnerability IDs** — o DefectDojo não possui um campo de achado literalmente chamado "CVE".

### Campos obrigatórios
Os seguintes campos de saída exigem o mapeamento de um campo de entrada:

* Title
* Severidade
* Description

### Sobre as severidades
Um Universal Parser aceitará qualquer variação de maiúsculas/minúsculas das severidades do DefectDojo - "CRITICAL", "Critical", "cRiTiCaL", etc. - e a aplicará aos seus achados. Qualquer valor que não corresponda a uma severidade do DefectDojo será substituído por "Informativa". Isso reflete o funcionamento atual dos parsers e Connectors: valores desconhecidos geralmente são mapeados para "Informativa".

### Multi-select fields
Alguns campos de saída aceitam múltiplos campos de entrada. Se você decidir selecionar mais de um campo de entrada, forneceremos o valor desse campo sob um cabeçalho com o nome do respectivo campo de entrada.

Exemplo

`description`

Isso foi extraído de um campo chamado "description" no arquivo de entrada

`detailed_description`

Isso foi extraído de um campo chamado "detailed_description" no arquivo de entrada

## Etapa 3: pré-visualizando seus Achados

Depois de selecionar seus mapeamentos de campos de entrada para campos de saída, você pode clicar no botão "Next" para ver uma pré-visualização de como os Achados do seu arquivo de entrada ficarão depois de importados para o DefectDojo com a configuração escolhida. Alguns campos terão um botão "expand" ao lado, permitindo visualizar o MarkDown completo e renderizado de como esse campo ficará. Renderizaremos pré-visualizações apenas dos primeiros 25 Achados do seu arquivo de entrada, mas você também poderá ver quantos achados foram detectados em todo o arquivo de varredura.

Se as pré-visualizações não corresponderem ao esperado, você pode clicar no botão "Back" para ajustar os mapeamentos. Quando estiver satisfeito com sua configuração, clique no botão "Submit" para criar seu novo Universal Parser. Isso não realizará uma importação automaticamente.

Depois que seu Universal Parser for criado, você será redirecionado para a página "Add Findings", onde poderá enviar e importar um arquivo de varredura que corresponda à estrutura do arquivo de exemplo fornecido na Etapa 1.

## Notas adicionais sobre a configuração do Universal Parser

### Escolhendo os campos de entrada corretos

Cada fornecedor pode produzir formatos de relatório de varredura muito diferentes, alguns dos quais se mapeiam mais de perto ao modelo de achado do DefectDojo do que outros. Permitimos flexibilidade significativa quanto ao que aceitamos, mas precisamos impor alguma estrutura para garantir que os achados não fiquem corrompidos na conversão de entrada para saída. Embora possamos acomodar campos de entrada opcionais, não aceitamos campos "globais", ou campos que ocorrem um número de vezes diferente do número de objetos de achado.

#### Exemplo

```
{
    "scan_type": "MyToolScan", // <- There is only one instance of this field, which doesn't match the number of findings
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345", // <- This optional field only appears in Finding 1 - that's okay!
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "CRITICAL",
            ...  // <- While there is no "CVE" field here, we can still query for it and simply default to a null value
        },
        ... 5 more findings ...
    ],
    "global_details": [
        {
            "nested_detail": "Global detail 1"
        },
        {
            "nested_detail": "Global detail 2" // <- The number of "global_details" objects (2) does not match the number of individual finding objects (7)
        }

    ]
}
```

## Depois de salvar um Universal Parser

Você pode editar o Test_Type associado ao seu Universal Parser para alterar:
* Se está "active" ou não. Se não estiver, não aparecerá como opção na lista suspensa "Scan Type" na página "Add Findings"
* Se seus achados devem ser marcados como "static" ou "dynamic"
* Você pode ajustar os hash codes de deduplicação same-tool e cross-tool, bem como os hash codes de reimportação, do seu Universal Parser em "Enterprise Settings". Por padrão, apenas os hash codes de deduplicação same-tool e de reimportação são preenchidos, com os valores obrigatórios Title, Severidade e Description.

## Ciclo de vida: criar, desativar, reativar

O ciclo de vida de um Universal Parser é **somente criação (create-only)**, sem edição ou exclusão pela UI. Depois que um parser é criado, a configuração de mapeamento de campos não pode ser modificada, e o próprio parser não pode ser removido pela UI — isso é proposital, pois as configurações do Universal Parser estão vinculadas a registros de Test_Type que podem ser referenciados por Achados, Testes e histórico de importação existentes.

O que você **pode** fazer pela UI:

* **Desativar (Deactivate)** um parser para ocultá-lo da lista suspensa "Scan Type" na importação. Abra **Import → Universal Parser** na barra lateral para ver todos os seus Universal Parsers, e desative a opção "Active". (Alternativamente, você pode editar o Test_Type subjacente e desmarcar "active".) Parsers desativados deixam de aparecer como opção de Scan Type na página **Add Findings**, mas os Testes existentes que foram importados com esse parser não são afetados e continuam funcionando.
* **Reativar (Reactivate)** um parser na mesma tela, ativando novamente a opção "Active".
* **Editar os campos do Test_Type** descritos na seção acima (active/inactive, static/dynamic, hash codes de deduplicação).

### Fluxo de trabalho recomendado quando o formato de relatório de um scanner muda

Como a configuração de mapeamento de campos fica bloqueada assim que um parser é criado, o fluxo de trabalho padrão para lidar com uma mudança de formato no scanner subjacente é **avançar para um novo parser** em vez de tentar editar o antigo:

1. **Crie um novo Universal Parser** usando uma amostra do novo formato de relatório (veja a Etapa 1). Dê a ele um nome distinto — por exemplo, acrescentando `v2` ou uma data ao nome original.
2. **Alterne as novas importações** no seu pipeline de CI/CD ou fluxo de trabalho da UI para usar o scan type do novo parser.
3. **Desative o parser antigo** assim que confirmar que o novo está produzindo os achados esperados. Os Testes já importados com o parser antigo permanecem no DefectDojo e ainda podem ser triados; apenas as novas importações são direcionadas ao novo parser.

Se você precisar que uma configuração de parser seja removida permanentemente (por exemplo, porque contém nomes de campo sensíveis), entre em contato com o [Suporte DefectDojo](mailto:support@defectdojo.com).

## Uma nota sobre o mapeamento de severidade

O Universal Parser **não** possui um campo configurável de mapeamento de severidade. A severidade é mapeada automaticamente com estas regras:

* Qualquer variação de maiúsculas/minúsculas de uma severidade do DefectDojo é aceita — `CRITICAL`, `Critical`, `cRiTiCaL`, `critical` são todas mapeadas para **Crítica**. O mesmo se aplica a `High`, `Medium`, `Low` e `Info`.
* Qualquer valor que **não** corresponda a uma das cinco severidades do DefectDojo é mapeado para **Informativa**.

Esse comportamento é o mesmo para todos os parsers do DefectDojo (parsers integrados, Connectors e Universal Parsers).

Se um scanner que você está tentando ingerir usa rótulos de severidade que não correspondem aos do DefectDojo (por exemplo, "warning", "note", ou pontuações CVSS numéricas), o Universal Parser mapeará todos esses valores não correspondentes para Informativa. Se você precisar de um mapeamento diferente, a melhor solução hoje é **transformar os valores de severidade a montante (upstream)** — por exemplo, no seu pipeline de CI antes do envio — para que os valores recebidos pelo DefectDojo já sejam um dos cinco nomes de severidade do DefectDojo.
