---
title: Sobre a Deduplicação
description: Fundamentos e conceitos-chave da deduplicação
weight: 1
aliases:
- /pt-br/en/working_with_findings/finding_deduplication/about_deduplication
- /pt-br/en/working_with_findings/finding_deduplication/delete_deduplicates
- /pt-br/en/working_with_findings/findings_workflows/manage_duplicate_findings
---

O DefectDojo foi projetado para ingerir relatórios em massa de ferramentas, criando um ou mais Achados com base no conteúdo do relatório. Ao usar o DefectDojo, é muito provável que você esteja ingerindo relatórios da mesma ferramenta regularmente, o que significa que Achados duplicados são altamente prováveis.

É aqui que entra a Deduplicação, um recurso inteligente que você pode configurar para gerenciar automaticamente Achados duplicados.

## Como o DefectDojo lida com duplicados

1. Primeiro, você importa o **Teste 1\.** Seu relatório contém uma vulnerabilidade que é registrada como Achado A.
2. **Mais tarde, você importa o Teste 2, que contém a mesma vulnerabilidade. Isso será registrado como Achado B, e o Achado B será marcado como um duplicado do Achado A.**
3. Mais tarde ainda, você importa o **Teste 3**, que também contém essa vulnerabilidade. Isso será registrado como Achado C, que será marcado como um duplicado do Achado A.

Ao criar e marcar Duplicados dessa forma, o DefectDojo garante que todo o trabalho relacionado à vulnerabilidade "original" seja centralizado na página do Achado original, sem criar contextos separados nem dar à sua equipe a impressão de que existem várias vulnerabilidades distintas que precisam ser tratadas.

### Qual Achado se torna o original

A Deduplicação sempre trata o Achado **criado mais cedo** em uma cadeia de duplicados como o original canônico, portanto um Achado de uma importação anterior nunca é rebaixado a duplicado de um mais novo — um original já estabelecido não muda de posição.

Dentro de um *único* relatório, a ordem em que o scanner lista seus achados não decide o vencedor. Os achados de uma mesma importação são criados em uma ordem estável, derivada do conteúdo, de modo que um relatório contendo vários achados que colidem na mesma chave de deduplicação produz **sempre o mesmo original a cada importação**. Reexecutar o scanner e reimportar os mesmos resultados não muda qual Achado sua equipe já está trabalhando.

Por padrão, esses Testes precisam estar aninhados sob o mesmo Produto para que a Deduplicação seja aplicada. Se desejar, você pode limitar ainda mais o escopo da Deduplicação a um único Engajamento.

![Deduplicação em nível de produto e engajamento](images/deduplication.png)

Os Achados duplicados são definidos como Inativos por padrão. Isso não significa que o próprio Achado duplicado esteja Inativo. Em vez disso, isso serve para que sua equipe tenha apenas um único Achado ativo para trabalhar e corrigir, com a implicação de que, quando o Achado original for Mitigado, os Duplicados também serão Mitigados.

## Deduplicação de Reimportação

Deduplicação e Reimportação são processos semelhantes, mas usam algoritmos diferentes para identificar correspondências de Achados.

* Quando você Reimporta para um Teste, o processo de Reimportação analisa os Achados recebidos, **compara os códigos de hash e descarta quaisquer correspondências**. Essas correspondências nunca serão criadas como Achados ou Achados duplicados.

No entanto, quaisquer Achados que permaneçam após a Deduplicação de Reimportação ainda estão sujeitos à Deduplicação por Mesma Ferramenta.  Portanto, se você usar um escopo mais restrito para a Deduplicação por Mesma Ferramenta, pode acabar com Duplicados dentro de um pipeline de Reimportação.

### Exemplo

Aqui está uma ferramenta com um algoritmo de Deduplicação de Reimportação diferente do algoritmo de Deduplicação por Mesma Ferramenta.

| Algoritmo de Deduplicação | Campos do Código de Hash |
| ----- | ---- |
| Reimportação | Título, CWE, Severidade, Descrição, Número da linha |
| Mesma Ferramenta | Título, CWE, Severidade, Descrição |

Digamos que você tenha um Achado no DefectDojo com um determinado número de linha.  Você reexecutou o scanner em seu ambiente e o número da linha dessa vulnerabilidade mudou.  Você reimporta para o mesmo Teste.  Veja o que acontecerá durante a reimportação e a deduplicação:

* Durante a Reimportação, o Achado não será correspondido a nenhum Achado já existente, pois o número da linha é diferente.  Portanto, um novo Achado será criado no Teste.
* Após a conclusão da Reimportação, o algoritmo de Deduplicação por Mesma Ferramenta será executado.  A Deduplicação por Mesma Ferramenta não considera o número da linha nessa configuração, portanto o novo Achado será rotulado como duplicado.

A Reimportação pode descartar completamente Achados antes que sejam registrados, portanto as configurações de Deduplicação de Reimportação devem ser ajustadas com cautela.

## Quando os duplicados são apropriados?

Os duplicados são úteis quando você lida com contextos de teste compartilhados, mas distintos. Por exemplo, se o seu Produto está enviando resultados de Teste para dois repositórios diferentes que precisam ser comparados, é útil saber quais vulnerabilidades são compartilhadas entre esses repositórios.

No entanto, se o DefectDojo estiver criando duplicados em excesso, isso também pode ser um sinal de que você precisa ajustar seus pipelines ou processos de importação.

## O que meus duplicados indicam?

* **A mesma vulnerabilidade, mas encontrada em um contexto diferente:** essa é a forma apropriada de usar Achados duplicados. Se você tem vários componentes afetados pela mesma vulnerabilidade, provavelmente vai querer saber quais componentes são afetados para entender o escopo do problema.
​
* **A mesma vulnerabilidade, encontrada no mesmo contexto**: existem opções melhores para esse caso. Se o Achado duplicado não fornece nenhum contexto novo sobre a vulnerabilidade, ou se você percebe que está frequentemente ignorando ou excluindo seus Achados duplicados, isso é um sinal de que seu processo pode ser melhorado. Por exemplo, a Reimportação permite gerenciar de forma eficaz os relatórios recebidos de um pipeline de CI/CD. Em vez de criar um objeto de Achado completamente novo para cada duplicado, a Reimportação registrará o duplicado recebido sem sequer criar o Achado duplicado.

## Visão geral

O DefectDojo Open Source é compatível com quatro algoritmos de deduplicação que podem ser selecionados por parser (tipo de teste):

- **Unique ID From Tool**: usa o identificador exclusivo fornecido pelo scanner.
- **Hash Code**: usa um conjunto configurado de campos para calcular um hash.
- **Unique ID From Tool or Hash Code**: prioriza o ID exclusivo da ferramenta; recorre ao hash quando nenhum ID exclusivo correspondente é encontrado.
- **Legacy**: algoritmo histórico com múltiplas condições; disponível apenas na versão Open Source.

**O DefectDojo Pro adiciona mais opções.** Dois algoritmos adicionais fazem a correspondência em **todos os Produtos** da instância, em vez de dentro de um único Produto ou Engajamento — **Global Component** (por nome e versão do componente) e **Global Vulnerability ID** (por CVE, GHSA, …). Ambos ficam desativados por padrão e são habilitados pelo Suporte do DefectDojo. O Pro também permite que o algoritmo Hash Code trate os IDs de vulnerabilidade e os CWEs de um Achado como **conjuntos**, correspondendo ao conjunto exato, a qualquer valor compartilhado (`_partial`) ou a um ser subconjunto do outro (`_subset`). Consulte [Ajuste fino da deduplicação (Pro)](/triage_findings/finding_deduplication/pro__deduplication_tuning/) para a lista completa, os campos de correspondência por conjunto e as regras que os regem.

### Uma alternativa à Deduplicação: Histórico de Falsos Positivos

Instâncias que deliberadamente **não** deduplicam podem usar em vez disso o [Histórico de Falsos Positivos](/triage_findings/finding_deduplication/false_positive_history/), que marca automaticamente um Achado recebido como falso positivo quando um Achado correspondente no mesmo Produto já havia sido triado dessa forma. É **mutuamente exclusivo com a Deduplicação** — o DefectDojo não permite que ambos sejam habilitados ao mesmo tempo — e ainda está marcado como experimental.

## Como os endpoints são avaliados por algoritmo

Os endpoints podem influenciar a deduplicação de diferentes formas, dependendo do algoritmo e da configuração.

### Unique ID From Tool

- A deduplicação usa `unique_id_from_tool` (ou `vuln_id_from_tool`).
- **Os endpoints são ignorados** na correspondência de duplicados.
- O hash de um achado ainda pode ser calculado para outros recursos, mas isso não afeta a deduplicação nesse algoritmo.

### Hash Code

- A deduplicação usa um hash calculado a partir dos campos especificados por `HASHCODE_FIELDS_PER_SCANNER` para o parser em questão.
- O hash também inclui campos de `HASH_CODE_FIELDS_ALWAYS` (veja a seção sobre o campo Service abaixo).
- Os endpoints podem afetar a deduplicação de duas formas:
  - Se os campos de hash do scanner incluírem `endpoints`, eles fazem parte do hash e precisam corresponder de acordo.
- Se os campos de hash do scanner não incluírem `endpoints`, a correspondência opcional baseada em endpoints pode ser habilitada por meio de `DEDUPE_ALGO_ENDPOINT_FIELDS` (configuração do OS). Quando configurada:
    - Defina como uma lista vazia `[]` para ignorar completamente os endpoints.
    - Defina como uma lista de atributos de endpoint (por exemplo, `["host", "port"]`). Se pelo menos um par de endpoints entre os dois achados corresponder em todos os atributos listados, a deduplicação pode ocorrer.

### Unique ID From Tool or Hash Code
Um achado é duplicado de outro se ambos tiverem o mesmo unique_id_from_tool OU o mesmo hash_code.

Os endpoints também precisam corresponder para que os achados sejam considerados duplicados; veja o algoritmo Hash Code acima.

### Legacy (somente Open Source)

- A deduplicação considera múltiplos atributos, incluindo endpoints.
- O comportamento é diferente para achados estáticos e dinâmicos:
  - **Achados estáticos**: o novo achado precisa conter todos os endpoints do original. Endpoints extras no novo achado são permitidos.
  - **Achados dinâmicos**: os endpoints precisam corresponder estritamente (geralmente por host e porta); endpoints diferentes impedem a deduplicação.
- Se não houver endpoints e tanto `file_path` quanto `line` estiverem vazios, a deduplicação normalmente não ocorre.

## Processamento em segundo plano

- A deduplicação é acionada na importação/reimportação e durante certas atualizações executadas em segundo plano via Celery.

### Modo de execução da deduplicação na importação/reimportação

Para importação e reimportação, você pode controlar como o pós-processamento da deduplicação é despachado e se a resposta da API aguarda por ele. Configure isso por usuário na página de perfil (**Modo de execução da deduplicação**), ou sobrescreva por requisição com o campo `deduplication_execution_mode` nos endpoints de importação/reimportação (o valor da requisição tem precedência sobre o do perfil).

- `async` (padrão): a deduplicação e o restante do pós-processamento são executados em segundo plano, e a resposta retorna imediatamente. Comportamento histórico; a resposta é produzida antes que os achados sejam deduplicados.
- `async_wait`: o pós-processamento ainda é despachado para segundo plano, mas a requisição aguarda a conclusão da deduplicação antes de responder. A notificação `scan_added` e as estatísticas na resposta então refletem o estado já deduplicado (achados que se revelaram duplicados deixam de ser contados/listados como novos). O envio ao JIRA, a avaliação (grading) do produto e outras tarefas que não sejam de deduplicação continuam assíncronas e não são aguardadas. A espera é limitada por `DD_DEDUPLICATION_ASYNC_WAIT_TIMEOUT` (padrão de `60` segundos); se nenhum worker assumir o trabalho a tempo, a requisição responde mesmo assim, em vez de ficar bloqueada.
- `sync`: a deduplicação da importação é executada de forma síncrona (inline) dentro da própria requisição web.

A resposta de importação/reimportação inclui um booleano `deduplication_complete` indicando se a deduplicação havia terminado no momento em que a resposta foi produzida (`true` para `sync` e para um `async_wait` concluído, `false` para `async`).

Isso é independente do sinalizador global de perfil `block_execution`, que força **todas** as tarefas assíncronas de um usuário (notificações, envio ao JIRA, avaliação de produto, deduplicação, ...) a serem executadas em primeiro plano. Quando nenhum modo de execução é definido, `block_execution=True` recorre a `sync`.

## O campo Service e seu impacto

- Por padrão, `HASH_CODE_FIELDS_ALWAYS = ["service"]`, o que significa que o `service` associado a um achado é incluído no hash para todos os scanners.
- Implicações práticas:
  - Dois achados que seriam idênticos, mas com valores de `service` diferentes, produzirão hashes diferentes e não serão deduplicados nos caminhos baseados em hash.
  - Durante a importação/reimportação, o campo `Service` informado na interface pode sobrescrever o serviço fornecido pelo parser. Alterá-lo pode mudar o hash e, portanto, afetar os resultados da deduplicação.
  - Se você quiser que o service não tenha impacto na deduplicação, configure `HASH_CODE_FIELDS_ALWAYS` de acordo (veja a página de ajuste fino do OS). Remover `service` da lista sempre incluída fará com que ele deixe de afetar os hashes.

## Excluir Achados Duplicados

Se você tem uma quantidade excessiva de Achados duplicados que deseja excluir, pode ativar a opção **Excluir Achados Duplicados** em **Configurações do Sistema**.

**Excluir Achados Duplicados**, combinada com o campo **Máximo de Duplicados**, permite que o DefectDojo limite a quantidade de Achados duplicados armazenados. Quando esse campo está habilitado, o DefectDojo manterá apenas um certo número de Achados duplicados.

### Quais duplicados serão excluídos?

O Achado original nunca será excluído automaticamente do DefectDojo, mas, uma vez ultrapassado o limite de Máximo de Duplicados, o DefectDojo excluirá automaticamente o Achado duplicado mais antigo.

Por exemplo, digamos que você tenha o campo Máximo de Duplicados definido como '1'.

1. Primeiro, você importa o **Teste 1\.** Seu relatório contém uma vulnerabilidade que é registrada como Achado A.
2. **Mais tarde, você importa o Teste 2, que contém a mesma vulnerabilidade. Isso será registrado como Achado B, e o Achado B será marcado como um duplicado do Achado A.**
3. Mais tarde ainda, você importa o **Teste 3**, que também contém essa vulnerabilidade. Isso será registrado como Achado C, que será marcado como um duplicado do Achado A. Nesse momento, o Achado B será excluído do DefectDojo, pois o limite máximo de duplicados foi ultrapassado.

### Aplicando essa configuração

Ao aplicar **Excluir Achados Duplicados**, um processo de exclusão será iniciado imediatamente. Essa configuração pode ser aplicada na página **Configurações do Sistema**. Consulte Habilitando a Deduplicação para mais informações.

## Solução de problemas de Deduplicação

Às vezes, a Deduplicação não funciona como esperado.  Aqui estão alguns exemplos de situações em que a Deduplicação pode não estar funcionando corretamente, junto com possíveis soluções.

| O que você vê | Causa mais provável | O que ajustar |
| --- | --- | --- |
| A Reimportação fecha um Achado antigo e cria um novo quando apenas o número da linha mudou | A correspondência da Reimportação usa campos instáveis (por exemplo, número da linha) | <strong>Deduplicação de Reimportação</strong> (prefira IDs estáveis ou campos de hash estáveis) |
| Vários Achados são criados no mesmo Teste que você acredita que deveriam ser duplicados | A correspondência de deduplicação não está configurada para essa ferramenta ou escopo | <strong>Deduplicação por Mesma Ferramenta</strong> (e considere o comportamento de “Excluir Achados Duplicados”) |
| Duplicados são criados entre ferramentas diferentes | A correspondência entre ferramentas está desabilitada ou é muito restritiva | <strong>Deduplicação entre Ferramentas (somente Pro)</strong> (correspondência baseada em hash) |
| A mesma dependência SCA importada em vários Produtos cria Achados separados em vez de duplicados | Por padrão, a deduplicação tem escopo por Produto | <strong>Deduplicação Global de Componentes (somente Pro)</strong> ([habilite para suas ferramentas SCA](/triage_findings/finding_deduplication/pro__global_component_deduplication/)), ou, no modelo de dados de Locations, <strong>Deduplicação Global de Locations (somente Pro)</strong> ([corresponda por local compartilhado](/triage_findings/finding_deduplication/pro__global_locations_deduplication/)) |
| O mesmo Achado de URL / web importado em vários Produtos cria Achados separados em vez de duplicados | Por padrão, a deduplicação tem escopo por Produto, e o Global Component corresponde apenas a componentes | <strong>Deduplicação Global de Locations (somente Pro)</strong> ([corresponda Achados DAST/URL entre Produtos](/triage_findings/finding_deduplication/pro__global_locations_deduplication/)) |
| Duplicados em excesso do mesmo Achado estão sendo criados entre Testes | A Hierarquia de Ativos não está configurada corretamente | [Considere a Reimportação para testes contínuos](/triage_findings/finding_deduplication/avoid_excess_duplicates/) |

Quando a deduplicação automática não identifica Achados que você acredita que deveriam estar relacionados, você pode vinculá-los manualmente pela página de Visualização do Achado. Consulte Achados Semelhantes para saber como descobrir Achados relacionados e marcá-los como duplicados manualmente ([Open Source](/triage_findings/finding_deduplication/os__similar_findings/) | [Pro](/triage_findings/finding_deduplication/pro__similar_findings/)).
