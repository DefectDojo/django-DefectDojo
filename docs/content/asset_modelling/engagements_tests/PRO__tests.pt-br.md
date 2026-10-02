---
title: Testes
description: Entendendo os Testes no DefectDojo Pro
audience: pro
weight: 4
---

Organizações → Ativos → Engajamentos → **TESTES** → Achados

## Visão geral

Um Teste é um contêiner para uma ou mais execuções de scan, usadas para descobrir falhas em um Ativo. Os Testes são o componente final e mais granular da hierarquia de objetos do DefectDojo, servindo como o contêiner para os Achados resultantes da execução de uma ferramenta de segurança ou de uma avaliação manual, além de adicionar o contexto no qual esses Achados foram encontrados (ou seja, qual ferramenta os reportou, quando essa ferramenta foi executada pela última vez, etc.).

Exemplos de Testes incluem:
- Teste Estático de Segurança de Aplicações
- Teste Dinâmico de Segurança de Aplicações
- Análise de Composição de Software
- Varreduras de Segurança de Contêineres
- Varreduras de Infraestrutura / Rede
- Testes de Penetração Manuais
- Varreduras de Pipeline de CI/CD

### Tipos de Teste

Existem várias maneiras de criar Testes no DefectDojo, incluindo **parsers específicos de fornecedor** (por exemplo, Burp, OWASP ZAP, Acunetix, Invicti), **Generic Findings Import**, **Universal Parser** e **Connectors**.

Esses métodos podem criar novos Testes ou reimportar Achados em Testes existentes, dependendo da configuração e da estratégia de deduplicação.

Embora cada método difira principalmente na forma como os dados de scan são analisados e ingeridos, todos eles resultam, em última instância, na associação de Achados a um Teste.

#### Parsers

**Parsers** são componentes que processam formatos específicos de saída de scan (por exemplo, XML, JSON, CSV) e os mapeiam para o modelo interno de Achado do DefectDojo. Quando os resultados de um scan são importados, o DefectDojo usa o parser selecionado para extrair os Achados e anexá-los a um Teste recém-criado ou existente.

#### Generic Findings Import

Quando não existe um parser nativo para uma determinada ferramenta, o [**Generic Findings Import**](/supported_tools/parsers/generic_findings_import) permite importar achados usando um schema padronizado em JSON ou CSV, independentemente da origem original.

O DefectDojo analisa os dados fornecidos, cria um novo Teste (ou importa para um já existente) e anexa os Achados. Um Tipo de Teste correspondente também é criado com base no campo opcional `type` do relatório: quando `type` é omitido (ou é igual ao tipo de scan) o Tipo de Teste é "Generic Findings Import"; quando `type` é fornecido, ele se torna "`{type}` Scan (Generic Findings Import)" (um `type` que já termina com o sufixo "(Generic Findings Import)" é usado literalmente).

#### Universal Parser

O [**Universal Parser**](/supported_tools/parsers/universal_parser) permite que os usuários definam como dados de entrada arbitrários são mapeados para o modelo de Achado do DefectDojo. Depois de configurar o parser e enviar os dados do scan, o DefectDojo aplica as regras de mapeamento para extrair os Achados, cria um Teste (ou atualiza um já existente) e associa os Achados a esse Teste.

#### Connectors

Os [**Connectors**](/connectors/upstream/about/) podem ser usados para ingerir e organizar automaticamente dados de vulnerabilidades de ferramentas externas por meio de chamadas de API. Uma vez configurado, um Connector busca os resultados do scan, analisa os dados e cria novos Testes ou atualiza Testes existentes, dependendo de sua configuração. Os Achados são então anexados ao Teste correspondente.

#### Comparação dos Mecanismos de Criação de Teste

| | **Parsers Nativos** | **Generic Findings Import** | **Universal Parser (Pro)** | **Connectors** |
|----------|---------------|------------------------|------------------------|------------|
| **Finalidade principal** | Ingerir saídas de ferramentas suportadas | Ingerir dados não suportados/personalizados por meio de um schema fixo | Ingerir formatos arbitrários por meio de mapeamentos configuráveis | Sincronizar continuamente sistemas externos |
| **Formato de entrada** | Específico da ferramenta (por exemplo, ZAP XML, SARIF) | Schema JSON/CSV rígido | Arbitrário (JSON, XML etc.) | Respostas de API externas |
| **Quem realiza a normalização** | DefectDojo (parser integrado) | Usuário (deve seguir o schema) | DefectDojo (via configuração do parser) | Ferramenta externa + DefectDojo |
| **Gatilho de criação do Teste** | Upload manual ou importação via API | Upload manual ou importação via API | Upload manual ou importação via API | Sincronização automatizada (agendada ou orientada por evento) |
| **Tipo de Teste** | Predefinido (por exemplo, "ZAP Scan") | Tipo "Generic" criado automaticamente | Derivado da configuração do parser | Depende do connector / parser subjacente |
| **Esforço de configuração** | Baixo | Moderado (requer transformação de dados) | Alto (configuração do parser) | Moderado–Alto (configuração da integração) |
| **Flexibilidade** | Baixa (apenas ferramentas suportadas) | Média | Alta | Média–Alta |
| **Nível de automação** | Baixo–Moderado | Baixo–Moderado | Baixo–Moderado | Alto |
| **Caso de uso típico** | Scanners padrão (SAST, DAST, SCA) | Scripts personalizados, ferramentas não suportadas | Formatos complexos/personalizados em escala | Integrações de CI/CD, SCM ou plataforma |

Independentemente do método de ingestão, todos os dados de scan no DefectDojo são, em última instância, representados como Achados anexados a um Teste, que serve como a unidade de execução e de acompanhamento do ciclo de vida.

### Dados do Teste

Os Testes armazenam uma variedade de metadados que ajudam a documentar vários componentes de cada esforço de teste, como:
- Título / nome do Teste
- Tipo de Teste
- Descrição / notas do Teste
- Data de início e término
- O Ambiente em que o Teste foi executado (por exemplo, Development, Staging, Pre-Production, Production, etc.)
- Versão / Branch / Build ID / Commit Hash
- Configuração de scan de API
- Pessoal associado ao Teste
- Arquivos adicionais que podem ser usados para auditorias ou reimportações futuras
- O Engajamento, o Ativo e a Organização pai
- Histórico de importação e reimportação

Cada Teste mantém um histórico de importação, que registra todas as importações e reimportações de scan associadas ao Teste. Cada item do histórico inclui metadados como data do scan, versão, branch, commit hash e build ID.

Esse histórico proporciona rastreabilidade entre múltiplas execuções de scan dentro do mesmo Teste.

### Permissões

Vários Testes podem ser armazenados dentro de um único Engajamento, e os Engajamentos são armazenados dentro de Ativos. Assim, o acesso a um Ativo concede automaticamente acesso a todos os Testes (e Engajamentos) dentro desse Ativo. Os Testes não possuem listas de controle de acesso independentes.

## Acessando Testes

Os Testes podem ser acessados em várias seções da interface do DefectDojo.

- A barra lateral

![image](images/tests_ss13.png)

- Dentro de um Engajamento

![image](images/tests_ss14.png)

- A barra superior de um Ativo

![image](images/tests_ss15.png)

- A tabela de Metadados na visualização de um Achado

![image](images/tests_ss16.png)

## Trabalhando com Testes

### Criar Testes

Os Testes podem ser criados automaticamente quando os dados de um scan são importados diretamente em um Engajamento, resultando em um novo Teste contendo os dados do scan. Os Testes também podem ser criados antecipadamente, para planejar futuros Engajamentos, ou para achados de segurança inseridos manualmente que exijam acompanhamento e remediação.

#### Fluxos de Trabalho Manuais

Para criar um Teste, é necessário que exista um Engajamento para contê-lo, bem como um Ativo que conterá esse Engajamento. Depois disso, há várias maneiras de criar um Teste:

- Na barra lateral, em Testes, dentro da subseção **Manage**
    - Você precisará selecionar o Engajamento pré-existente ao qual atribuir o Teste ao preencher o formulário de Novo Teste.

![image](images/tests_ss1.png)

- O menu suspenso de configurações no canto superior direito da visualização de um Ativo
    - **Import Scan** criará automaticamente um Teste assim que um arquivo de scan for adicionado ao formulário de Import Scan. Você terá a opção de atribuir o Teste a um Engajamento pré-existente ou criar e nomear um novo Engajamento para conter o novo Teste.
        - Ao preencher o formulário de Import Scan, você pode adicionar metadados como a versão, a branch tag, o commit hash e o build ID. Isso será refletido na seção de Histórico de Importação da visualização do Teste.

![image](images/tests_ss2.png)

- O menu suspenso de configurações no canto superior direito da visualização de um Engajamento
    - **Import Scan** seguirá o mesmo fluxo de trabalho dos Ativos, mas colocará automaticamente o objeto Teste dentro do Engajamento no qual você clicou em Import Scan.
    - **Add Test** criará um objeto Teste, mas não exige que um scan seja enviado para o próprio Teste, o que é útil para planejar futuros Testes antecipadamente ou para achados de segurança inseridos manualmente que exijam acompanhamento e remediação.

![image](images/tests_ss3.png)

Se você selecionar Add Test e mais tarde desejar importar manualmente os resultados de um scan para um Teste, você pode fazer isso abrindo o Teste e clicando no botão Reimport Findings nas configurações do Teste ou no botão Reimport Scan na tabela de Achados.

![image](images/tests_ss21.png)

#### Fluxos de Trabalho Automatizados

Em fluxos de trabalho automatizados, os Testes podem ser criados programaticamente como parte do processo de importação de scan, permitindo que os pipelines enviem resultados sem exigir que um Teste seja criado manualmente com antecedência.

Ao usar a API ou a CLI para importar resultados de scan, um novo Teste pode ser criado automaticamente fornecendo um `engagement` em vez de um `test`.

##### API

curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`

Diante do exemplo acima, um novo Teste é criado dentro do Engajamento especificado, e os resultados do scan são anexados a esse Teste.

Se um ID de `test` for fornecido em vez disso, os resultados do scan serão adicionados a um Teste existente, o que é comum em fluxos de trabalho de reimportação.

##### CLI

Usando a CLI do DefectDojo, esse comportamento é tratado automaticamente com base nos argumentos fornecidos.

defectdojo-cli import \
  --engagement-id 45 \
  --scan-type `"ZAP Scan"` \
GOog  --file report.xml

Diante do exemplo acima, fornecer um `engagement-id` cria um novo Teste, e fornecer um `test-id` reutiliza um Teste existente e reimporta os resultados do scan nesse Teste.

Consulte [DefectDojo-CLI](/import_data/pro/specialized_import/external_tools/#defectdojo-cli) para mais detalhes sobre as flags necessárias.

### Editar Testes

Os Testes podem ser editados clicando em **Edit Test** no menu de engrenagem. Todos os campos subsequentes que podem ser editados também estão disponíveis quando o Teste está sendo criado.

### Excluir Testes

A exclusão de um Teste pode ser realizada selecionando **Delete Test** nas configurações do Teste. Essa ação não pode ser desfeita.

Excluir um Teste também excluirá todos os Achados contidos nesse Teste.

### Reimportando Resultados de Scan (UI)

Para adicionar novos dados a um Teste existente, abra o Teste ao qual deseja adicionar novos dados e clique no botão Reimport Findings nas configurações do Teste ou no botão Reimport Scan na tabela de Achados.

![image](images/tests_ss21.png)

Ao preencher o formulário de Reimport Scan, você terá a opção de atualizar os metadados do scan sendo reimportado, incluindo a versão, a branch tag, o commit hash e o build ID. Essas alterações são refletidas na seção de Histórico de Importação da visualização do Teste, que também incluirá os mesmos metadados das importações de scan anteriores.

Por exemplo, na captura de tela abaixo, a branch tag, o build ID, o commit hash e a versão foram todos atualizados manualmente entre a importação inicial e a reimportação subsequente.

![image](images/tests_ss23.png)

Para editar os metadados do scan reimportado mais recentemente, clique no ícone de engrenagem localizado no canto superior direito da visualização de um Engajamento e selecione "Edit Test". Apenas os metadados da importação mais recente podem ser editados.

### Reimportando Resultados de Scan (API/CLI)

Quando os Testes são criados ou atualizados por meio de um pipeline de CI/CD, é possível incluir metadados da execução do pipeline para que os Testes possam ser corretamente vinculados ao código que analisaram. Isso permite que você:
- Associe os resultados do scan a um commit ou branch específico.
- Acompanhe como os Achados evoluem ao longo das alterações de código.
- Melhore a Deduplicação entendendo quando dois scans se aplicam à mesma versão do código ou a versões diferentes.
- Dê suporte à auditabilidade, mostrando exatamente qual código foi analisado e quando.

A CLI e a API do DefectDojo aceitam esses valores durante a importação ou reimportação, para que possam ser armazenados como parte da importação do scan e refletidos no histórico de importação do Teste. Esses metadados podem ser usados para identificar commit hashes ou qualquer informação relevante de repositório associada a uma execução de CI/CD.

#### Campos de Metadados Suportados

A API e a CLI oferecem suporte a um conjunto definido de campos de metadados que podem ser incluídos durante a reimportação. Estes incluem:

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- flags `active / verified`

Esses campos representam o mecanismo principal para anexar metadados contextuais durante uma operação de reimportação.

Em pipelines automatizados, os metadados mais comumente fornecidos incluem:
- `build_id` (identificador do job de CI)
- `commit_hash` (referência de controle de versão)
- `branch_tag` (contexto de branch ou ambiente)
- `tags` (por exemplo, `nightly`, `staging`, `production`)

Esses campos fornecem rastreabilidade entre os scans sem exigir intervenção manual.

Embora os metadados possam ser atualizados manualmente por meio do formulário de Reimport Scan, a maioria dos ambientes automatizados fará isso chamando diretamente o endpoint `/api/v2/reimport-scan/` ou usando a CLI do DefectDojo (`defectdojo-cli reimport`) como parte do processo de build. Essa abordagem permite que o pipeline anexe automaticamente os metadados durante a reimportação.

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

##### Reimportação via CLI com Metadados

defectdojo-cli import \
  --test-id 123 \
  --scan-type "ZAP Scan" \
  --file report.xml \
  --tag nightly \
  --tag api \
  --build-id jenkins-842 \
  --branch main \
  --commit a1b2c3d4

A CLI mapeia diretamente para o mesmo endpoint da API e oferece suporte ao mesmo conjunto de campos de metadados.

Há algumas limitações a serem consideradas ao trabalhar com metadados durante a reimportação:
- A API/CLI oferece suporte apenas a parâmetros predefinidos. Metadados personalizados no formato chave-valor não podem ser adicionados durante a reimportação
- Metadados adicionais podem ser extraídos do próprio arquivo de scan, dependendo do tipo de scan e do parser.
- Os metadados fornecidos durante a reimportação não se comportam como uma atualização direta do objeto Teste, da mesma forma que as edições manuais feitas na UI.

##### Metadados, Reimportação e Scans Agendados

Os scans também podem ser agendados para serem executados em intervalos rotineiros, como os disparados por cron jobs. Scans agendados não estão vinculados à atividade do repositório, o que torna metadados como commit hashes ou nomes de branch irrelevantes, a menos que sejam explicitamente injetados pelo próprio script. Ainda assim, usar a reimportação pode ser útil se você preferir manter um registro contínuo da sua postura de segurança dentro de um único Teste.

## Reimportação e Deduplicação

Reimportar scans dentro dos Testes é fundamental para uma deduplicação eficaz. Quando os resultados de um scan são reimportados no mesmo Teste:

- Achados existentes podem ser atualizados
- Achados duplicados podem ser suprimidos
- Novos Achados podem ser criados se nenhuma correspondência for encontrada

Esse comportamento depende das regras de deduplicação configuradas e do tipo de scan.

Criar um novo Teste em vez de reimportar em um já existente pode resultar na criação de Achados duplicados em vez de sua atualização.

### Reimportação vs. Importação

A reimportação é normalmente usada quando:

- Executando scans recorrentes contra o mesmo alvo
- Acompanhando como os Achados evoluem ao longo do tempo
- Mantendo uma visão contínua da postura de segurança da aplicação

Em contraste, a importação (criação de um novo Teste) é mais adequada para execuções de scan únicas ou independentes.
