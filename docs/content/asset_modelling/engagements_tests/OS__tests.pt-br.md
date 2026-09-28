---
title: Testes
description: Entendendo os Testes no DefectDojo OS
audience: opensource
weight: 4
---

Organizações → Ativos → Engajamentos → **TESTES** → Achados

## Visão geral

Um Teste é um contêiner para uma ou mais execuções de varredura, usadas para descobrir falhas em um Produto. Os Testes são o componente final e mais granular da hierarquia de produtos do DefectDojo, servindo como o contêiner para os Achados resultantes da execução de uma ferramenta de segurança ou de uma avaliação manual, além de adicionar o contexto em que tais Achados foram encontrados (ou seja, qual ferramenta os reportou, quando essa ferramenta foi executada pela última vez, etc.).

Exemplos de Testes incluem:
- Teste Estático de Segurança de Aplicações
- Teste Dinâmico de Segurança de Aplicações
- Análise de Composição de Software
- Varreduras de Segurança de Contêineres
- Varreduras de Infraestrutura / Rede
- Testes de Penetração Manuais
- Varreduras de Pipeline de CI/CD

### Tipos de Teste

Existem duas formas principais de criar Testes no DefectDojo:
1. **Parsers específicos de fornecedor** (por exemplo, Burp, OWASP ZAP, Acunetix, Invicti)
2. **Importação Genérica de Achados**

Cada método pode criar novos Testes ou reimportar Achados para Testes existentes, dependendo da configuração e da estratégia de deduplicação.

Embora cada método difira principalmente na forma como os dados de varredura são analisados e ingeridos, todos eles resultam, em última instância, em Achados associados a um Teste.

#### Parsers

**Parsers** são componentes que processam formatos específicos de saída de varredura (por exemplo, XML, JSON, CSV) e os mapeiam para o modelo interno de Achado do DefectDojo. Quando os resultados de uma varredura são importados, o DefectDojo usa o parser selecionado para extrair os Achados e anexá-los a um Teste recém-criado ou existente.

#### Importação Genérica de Achados

Quando não existe um parser nativo para uma determinada ferramenta, a **Importação Genérica de Achados** permite importar achados usando um esquema JSON ou CSV padronizado, independentemente da fonte original.

O DefectDojo analisa os dados fornecidos, cria um novo Teste (ou importa para um já existente) e anexa os Achados. Um Tipo de Teste correspondente também é criado com base no campo opcional `type` do relatório: quando `type` é omitido (ou é igual ao tipo de varredura) o Tipo de Teste é "Generic Findings Import"; quando `type` é fornecido, ele se torna "{type} Scan (Generic Findings Import)" (um `type` que já termina com o sufixo "(Generic Findings Import)" é usado literalmente).

|  | **Parsers Nativos** | **Importação Genérica de Achados** |
|----------|---------------|------------------------|
| **Objetivo principal** | Ingerir saídas de ferramentas suportadas | Ingerir dados não suportados/personalizados por meio de um esquema fixo |
| **Formato de entrada** | Específico da ferramenta (por exemplo, ZAP XML, SARIF) | Esquema estrito JSON/CSV |
| **Quem trata a normalização** | DefectDojo (parser integrado) | Usuário (deve estar em conformidade com o esquema) |
| **Gatilho de criação do Teste** | Upload manual ou importação via API | Upload manual ou importação via API |
| **Tipo de Teste** | Predefinido (por exemplo, "ZAP Scan") | Tipo "Generic" criado automaticamente |
| **Esforço de configuração** | Baixo | Moderado (é necessária transformação de dados) |
| **Flexibilidade** | Baixa (somente ferramentas suportadas) | Média |
| **Nível de automação** | Baixo a moderado | Baixo a moderado |
| **Caso de uso típico** | Scanners padrão (SAST, DAST, SCA) | Scripts personalizados, ferramentas não suportadas |

Independentemente do método de ingestão, todos os dados de varredura no DefectDojo são, em última instância, representados como Achados anexados a um Teste, que serve como a unidade de execução e de rastreamento do ciclo de vida.

### Dados do Teste

Os Testes armazenam uma variedade de metadados que ajudam a documentar diversos componentes de cada esforço de teste, tais como:
- Título / nome do Teste
- Tipo de Teste
- Descrição / notas do Teste
- Data de início e término
- O Ambiente em que o Teste foi executado (por exemplo, Desenvolvimento, Homologação, Pré-Produção, Produção, etc.)
- Versão / Branch / ID de Build / Hash de Commit
- Configuração de varredura de API
- Arquivos adicionais que podem ser usados para auditorias posteriores ou reimportações
- O Engajamento, o Ativo e a Organização pais
- Histórico de importação e reimportação

Cada Teste mantém um histórico de importação, que registra todas as importações e reimportações de varredura associadas ao Teste. Isso inclui metadados como data da varredura, versão, branch, hash de commit e ID de build.

Esse histórico fornece rastreabilidade em várias execuções de varredura dentro do mesmo Teste.

### Permissões

Vários Testes podem ser armazenados dentro de um único Engajamento, e os Engajamentos são armazenados dentro dos Produtos. Assim, o acesso a um Produto concede automaticamente acesso a todos os Testes (e Engajamentos) dentro desse Produto. Os Testes não possuem listas de controle de acesso independentes.

### Acessando Testes

Embora os Testes existam como um objeto independente no DefectDojo OS, eles não têm uma seção específica dedicada a eles na interface. Assim, cada Teste é acessível principalmente através do Produto e/ou Engajamento que o contém.

### Visualização do Teste

A visualização do Teste hospeda uma variedade de tabelas, incluindo o Engajamento pai, o histórico de importação e reimportação, uma lista de Achados contidos no Teste, bem como quaisquer Grupos de Achados.

Também há tabelas para Achados Potenciais, Arquivos e Notas, todas as quais podem ser adicionadas manualmente.

#### Configurações do Teste

As seguintes configurações estão disponíveis em cada visualização de Teste:
- **Editar Teste**
    - Permite a edição dos dados do Teste, como título, agendamento, ambiente e outros detalhes diversos.
- **Copiar Teste**
    - Duplica um Teste, junto com todos os metadados e Achados associados, e permite atribuí-lo a um Engajamento diferente.
- **Reenviar Varredura**
    - Inicia o processo de reimportação. Mais informações sobre Reimportação estão disponíveis mais adiante neste artigo.
- **Adicionar Notas**
    - Permite que o usuário adicione uma Nota. Uma tabela de Notas também está presente na parte inferior da página.
        - Uma Nota pode ser marcada como Privada, caso em que fica impedida de ser enviada para o Jira, Relatórios e exportações de Achados.
- **Relatório**
    - Inicia o processo de geração de um Relatório, no qual inúmeros filtros podem ser aplicados para criar um relatório apenas com os Achados filtrados.
- **Adicionar ao Calendário**
    - Baixa um arquivo .ics do Teste escolhido, que pode ser adicionado ao seu aplicativo de calendário de terceiros.
- **Ver Histórico**
    - Abre um histórico das edições feitas no Teste para fins de rastreamento, relatórios e auditoria.

## Trabalhando com Testes

### Criar Testes

Os Testes podem ser criados automaticamente quando dados de varredura são importados diretamente em um Engajamento, resultando em um novo Teste contendo os dados da varredura. Os Testes também podem ser criados em antecipação ao planejamento de futuros Engajamentos, ou para achados de segurança inseridos manualmente que exigem rastreamento e correção.

#### Fluxos de Trabalho Manuais

Existem várias maneiras de criar um Teste na versão OS:

- Selecione um Produto e clique em "Importar Resultados de Varredura" no menu Achados na barra de navegação
    - Isso criará um Engajamento ad hoc para conter o Teste

![image](images/tests_ss5.png)

- Selecione um Engajamento dentro de um Produto, clique no menu suspenso na subseção Testes e clique em "Adicionar Testes" ou "Importar Resultados de Varredura"
    - Isso criará o Teste resultante diretamente dentro do Engajamento escolhido

![image](images/tests_ss6.png)

- Durante a criação de um Engajamento

![image](images/tests_ss7.png)

Usando o terceiro método acima, você pode fazer o seguinte durante a criação de um Engajamento:

- Importar imediatamente os resultados da varredura
- Criar um shell de Teste (no qual você importará uma varredura posteriormente)
- Não fazer nenhum dos dois e simplesmente criar o Engajamento clicando em "Concluído"

Você terá a oportunidade de adicionar metadados tanto ao importar uma varredura quanto ao criar um shell de Teste. Quaisquer metadados serão refletidos na seção Histórico de Importação da Visualização do Teste.

#### Fluxos de Trabalho Automatizados

Em fluxos de trabalho automatizados, os Testes podem ser criados programaticamente como parte do processo de importação de varredura, permitindo que os pipelines enviem resultados sem exigir que um Teste seja criado manualmente com antecedência.

Ao usar a API para importar resultados de varredura, um novo Teste pode ser criado automaticamente fornecendo um engagement em vez de um test.

##### API

curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`

Diante do exposto acima, um novo Teste é criado sob o Engajamento especificado, e os resultados da varredura são anexados a esse Teste.

Se um ID de `test` for fornecido em vez disso, os resultados da varredura serão adicionados a um Teste existente, o que é comum em fluxos de trabalho de reimportação.

### Editar Testes

Os Testes podem ser editados clicando em **Editar Teste** no menu kebab ⋮ na tabela de Testes dentro da visualização do Engajamento pai, ou no menu de configurações dentro da visualização do Teste. Todos os campos subsequentes que podem ser editados também estão disponíveis quando o Teste está sendo criado.

![image](images/tests_ss24.png)

![image](images/tests_ss12.png)

#### Adicionar Achados Manualmente a um Teste

Um Achado pode ser adicionado manualmente a um Teste clicando em **Adicionar Achado ao Teste** no menu kebab ⋮ ao lado do Teste na visualização do Engajamento pai, ou nas configurações da tabela de Achados na visualização do Teste.

![image](images/tests_ss29.png)

![image](images/tests_ss30.png)

### Excluir Testes

A exclusão de um Teste pode ser realizada selecionando **Excluir Teste** no menu kebab ⋮ ao lado do Teste na visualização do Engajamento pai, ou no menu de configurações dentro da visualização do Teste. Essa ação não pode ser desfeita.

A exclusão de um Teste também excluirá quaisquer Achados contidos nesse Teste.

![image](images/tests_ss25.png)

![image](images/tests_ss26.png)

## Reimportação

A reimportação de varreduras dentro de Testes é fundamental para uma deduplicação eficaz. Quando os resultados de uma varredura são reimportados no mesmo Teste:

- Os Achados existentes podem ser atualizados
- Achados duplicados podem ser suprimidos
- Novos Achados podem ser criados se nenhuma correspondência for encontrada

Esse comportamento depende das regras de deduplicação configuradas e do tipo de varredura.

Criar um novo Teste em vez de reimportar em um já existente pode resultar na criação de Achados duplicados em vez de atualizados.

#### Reimportação vs. Importação

A Reimportação é normalmente usada quando:

- Você executa varreduras recorrentes contra o mesmo alvo
- Você rastreia como os Achados evoluem ao longo do tempo
- Você mantém uma visão contínua da postura de segurança da aplicação

Em contraste, a importação (criação de um novo Teste) é mais adequada para execuções de varredura únicas ou independentes.

### Reimportando Resultados de Varredura (Interface)

Para adicionar novos dados a um Teste existente, você pode clicar em **Reenviar Resultados de Varredura** no menu kebab ⋮ ao lado do Teste na visualização do Engajamento pai, ou clicar em **Reenviar Varredura** no menu de configurações dentro da visualização do Teste.

![image](images/tests_ss27.png)

![image](images/tests_ss10.png)

Ao preencher o formulário de Reimportar Varredura, você terá a opção de atualizar os metadados da varredura sendo reimportada, incluindo a versão, a tag de branch, o hash de commit e o ID de build.

Essas alterações são refletidas na seção Histórico de Importação da Visualização do Teste, que também incluirá os mesmos metadados das importações de varredura anteriores.

Por exemplo, na captura de tela abaixo, a tag de branch, o ID de build, o hash de commit e a versão foram todos atualizados manualmente entre a importação inicial e a reimportação subsequente.

![image](images/tests_ss28.png)

Para editar os metadados da varredura reimportada mais recentemente, siga as instruções anteriores na seção Editar Testes acima e atualize os metadados conforme desejado. Somente os metadados da importação mais recente podem ser editados.

### Reimportando Resultados de Varredura (API)

Quando os Testes são criados ou atualizados por meio de um pipeline de CI/CD, você pode incluir metadados da execução do pipeline para que os Testes sejam corretamente vinculados ao código que varreram. Isso permite que você:
- Associe os resultados da varredura a um commit ou branch específico.
- Rastreie como os Achados evoluem entre as alterações de código.
- Melhore a Deduplicação, entendendo quando duas varreduras se aplicam à mesma versão do código ou a versões diferentes.
- Ofereça suporte à auditabilidade, mostrando exatamente qual código foi varrido e quando.

A API do DefectDojo aceita esses valores durante a importação ou reimportação, para que possam ser armazenados como parte da importação da varredura e refletidos no histórico de importação do Teste. Esses metadados podem ser usados para identificar hashes de commit ou qualquer informação de repositório relevante associada a uma execução de CI/CD.

#### Campos de Metadados Suportados

A API suporta um conjunto definido de campos de metadados que podem ser incluídos durante a reimportação. Estes incluem:

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- sinalizadores `active / verified`

Esses campos representam o principal mecanismo para anexar metadados contextuais durante uma operação de reimportação.

Em pipelines automatizados, os metadados mais comumente fornecidos incluem:
- build_id (identificador do job de CI)
- commit_hash (referência de controle de versão)
- branch_tag (contexto de branch ou ambiente)
- tags (por exemplo, nightly, staging, production)

Esses campos fornecem rastreabilidade entre varreduras sem exigir intervenção manual.

Embora os metadados possam ser atualizados manualmente por meio do formulário Reimportar Varredura, a maioria dos ambientes automatizados trata isso chamando diretamente o endpoint `/api/v2/reimport-scan/`. Essa abordagem permite que o pipeline anexe automaticamente os metadados na reimportação.

##### Reimportação via API com Metadados

curl -X POST `"https://<your-instance>/api/v2/reimport-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"test=123"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"` \
  -F `"tags=nightly,api-scan"` \
  -F `"version=1.4.2"` \
  -F `"build_id=jenkins-842"` \
  -F `"branch_tag=main"` \
  -F `"commit_hash=a1b2c3d4"`

##### Metadados, Reimportação e Varreduras Agendadas

As varreduras também podem ser agendadas para serem executadas em intervalos rotineiros, como as acionadas por cron jobs. As varreduras agendadas não estão vinculadas à atividade do repositório, tornando metadados como hashes de commit ou nomes de branch irrelevantes, a menos que sejam explicitamente injetados pelo próprio script. Ainda assim, usar a reimportação pode ser útil se você preferir manter um registro contínuo da sua postura de segurança dentro de um único Teste. 
