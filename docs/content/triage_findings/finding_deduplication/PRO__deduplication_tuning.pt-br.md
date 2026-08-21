---
title: Ajuste de Deduplicação
description: Configure como o DefectDojo identifica e gerencia achados duplicados
weight: 4
audience: pro
aliases:
- /pt-br/en/working_with_findings/finding_deduplication/tune_deduplication
---

Deduplication Tuning é um recurso do DefectDojo Pro que oferece controle refinado sobre como os achados são deduplicados, permitindo otimizar a detecção de duplicatas para o seu fluxo de trabalho específico de testes de segurança.

## Deduplication Settings

No DefectDojo Pro, você pode acessar o Deduplication Tuning em:
**Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** em instâncias que ainda usam o layout de menu anterior)

![imagem](images/deduplication_tuning.png)

A página Deduplication Settings oferece três áreas principais de configuração:
- Same Tool Deduplication
- Cross Tool Deduplication
- Reimport Deduplication

## Same Tool Deduplication

O Same Tool Deduplication vem habilitado por padrão para todos os parsers de ferramentas de segurança. Isso garante que achados de scans consecutivos usando a mesma ferramenta sejam deduplicados corretamente.

Para ajustar o Same Tool Deduplication:

1. Selecione uma **Security Tool** específica no menu suspenso
2. Escolha um **Deduplication Algorithm** entre as opções disponíveis

![imagem](images/same_tool_deduplication.png)

### Available Deduplication Algorithms

O DefectDojo Pro oferece os seguintes métodos de deduplicação para deduplicação com a mesma ferramenta:

#### Hash Code
Usa uma combinação de campos selecionados para gerar um hash único. Quando selecionado, um terceiro menu suspenso aparecerá mostrando os campos usados para calcular o hash.

##### Content Fingerprint

**Content Fingerprint** é um campo de hash selecionável (disponível nas três áreas de configuração) que fornece uma identidade *independente de localização* para achados de análise estática. Ele é derivado do trecho de código vulnerável que uma ferramenta inclui no achado — normalizado para que indentação, anotações de número de linha e diferenças de formatação não o alterem. Dois achados sobre o mesmo código vulnerável geram o mesmo hash mesmo quando o código foi movido para uma linha ou arquivo diferente.

O Content Fingerprint é calculado para ferramentas que incluem um trecho de código na descrição do achado — incluindo **Bandit**, **Gosec**, **Brakeman**, **Checkmarx One** e qualquer ferramenta cuja descrição contenha um bloco de código cercado ou um trecho SARIF.

> **Antes de selecionar Content Fingerprint como campo de hash**, popule os fingerprints dos achados existentes executando `./manage.py backfill_fingerprints`. Achados importados após a presença do recurso recebem fingerprints automaticamente, mas achados pré-existentes não têm nenhum — selecionar o campo sem fazer o backfill faz com que achados existentes e novos gerem hashes diferentes, quebrando toda correspondência até que o backfill seja executado.

O Content Fingerprint combina bem com **CWE** para ferramentas que incorporam caminhos de arquivo ou números de linha em seus títulos, casos em que outros campos de identidade mudam sempre que o código é movido. Veja [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#choosing-hash-fields-for-tracked-tools).

#### Unique ID From Tool
Aproveita o identificador interno próprio da ferramenta de segurança para os achados, garantindo deduplicação perfeita quando o scanner fornece IDs únicos confiáveis.

Esse algoritmo pode ser útil ao trabalhar com scanners SAST, ou em situações em que um achado pode "se mover" no código-fonte à medida que o desenvolvimento avança.

#### Unique ID From Tool or Hash Code
Tenta usar primeiro o ID único da ferramenta e, se nenhum ID único estiver disponível, recorre ao hash code. Essa é a opção de deduplicação mais flexível.

#### Global Component
Corresponde achados por nome e versão do componente em **todos os Produtos** da instância, em vez de dentro de um único Produto ou Engajamento. Destinado a ferramentas SCA em que a mesma dependência vulnerável aparece em muitos Produtos. Esse algoritmo vem desativado por padrão e deve ser habilitado pelo Suporte do DefectDojo. Veja [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) para detalhes.

#### Global Vulnerability ID
Corresponde achados pelos seus **IDs de vulnerabilidade** (CVE, GHSA, …) em **todos os Produtos** da instância, em vez de dentro de um único Produto ou Engajamento. Destinado a ferramentas que reportam o mesmo CVE em muitos Produtos. Desativado por padrão e habilitado pelo Suporte do DefectDojo.

> **Duas ferramentas no mesmo algoritmo de escopo de instância tornam-se candidatas mútuas de deduplicação.** Quando duas ferramentas *diferentes* são configuradas com um algoritmo de escopo de instância (Global Component, ou Global Vulnerability ID), seus achados compartilham um hash de agrupamento constante, de modo que um achado de qualquer uma das ferramentas é considerado para deduplicação em relação à outra nessa dimensão compartilhada (componente, ou ID de vulnerabilidade). Esse é o comportamento cross-tool pretendido — habilite-o apenas quando quiser que essas ferramentas façam deduplicação em conjunto.

### Set-based Hash Code Fields (Vulnerability IDs and CWEs)

Dois atributos de achado armazenam um *conjunto* de valores em vez de um único valor: IDs de vulnerabilidade (CVE, GHSA, …) e CWEs. Ao usar o algoritmo **Hash Code** (Same Tool ou Cross Tool), você pode adicionar os campos a seguir em **Hash Code Fields** para controlar como esses conjuntos são comparados:

| Campo | Os achados são duplicados quando… |
|-------|-------------------------------|
| `vulnerability_ids` | eles têm o **mesmo conjunto exato** de IDs de vulnerabilidade |
| `vulnerability_ids_partial` | eles compartilham **pelo menos um** ID de vulnerabilidade |
| `vulnerability_ids_subset` | os IDs de vulnerabilidade de um achado são um **subconjunto** dos do outro |
| `cwes` | eles têm o **mesmo conjunto exato** de CWEs |
| `cwes_partial` | eles compartilham **pelo menos um** CWE |
| `cwes_subset` | os CWEs de um achado são um **subconjunto** dos do outro |

Os campos `_partial` e `_subset` são comparados por par de achados, em vez de serem incorporados ao hash: os demais Hash Code Fields agrupam os achados candidatos, e a comparação de conjunto então restringe esse grupo. (A correspondência exata — `vulnerability_ids` e `cwes` — é incorporada diretamente ao hash.)

**Valores vazios.** Se um achado não tiver IDs de vulnerabilidade (ou CWEs) para o comparador configurado:

- Se os Hash Code Fields também incluírem um campo comum (por exemplo, `title`), esse campo carrega a identidade — o comparador de conjunto é ignorado para o par, e os achados ainda podem corresponder no restante do hash.
- Se um comparador de conjunto for o **único** campo, um achado sem valores não corresponde a nada: sem mais nada para identificá-lo, um conjunto vazio não é tratado como correspondente a todos os outros.

**Regras de configuração** (aplicadas ao salvar as configurações):

- Um campo de IDs de vulnerabilidade (`vulnerability_ids`, `vulnerability_ids_partial` ou `vulnerability_ids_subset`) pode ser usado sozinho — um CVE ou GHSA identifica uma instância específica de vulnerabilidade.
- Os campos de CWE (`cwes`, `cwes_partial`, `cwes_subset`) **não** podem ser o único critério. Um CWE é uma *classe* de fraqueza, não uma instância específica, então corresponder apenas por CWE mesclaria achados não relacionados. Combine um comparador de CWE com um campo identificador, como `title` ou `file_path`.

## Cross Tool Deduplication

O Cross Tool Deduplication vem desativado por padrão, já que a deduplicação entre diferentes ferramentas de segurança exige configuração cuidadosa devido a variações na forma como as ferramentas reportam as mesmas vulnerabilidades.

![imagem](images/cross_tool_deduplication.png)

Para habilitar o Cross Tool Deduplication:

1. Selecione uma **Security Tool** no menu suspenso
2. Altere o **Deduplication Algorithm** de "Disabled" para "Hash Code"
3. Selecione quais campos devem ser usados para gerar o hash no menu suspenso **Hash Code Fields**

O Cross Tool Deduplication oferece suporte ao algoritmo Hash Code, adequado para a maioria dos fluxos de trabalho, já que diferentes ferramentas raramente compartilham identificadores únicos compatíveis. Para ferramentas SCA que reportam as mesmas dependências, o [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) também está disponível como opção cross-tool (desativado por padrão).

Observe que o Cross Tool Deduplication também tem escopo limitado a Assets individuais.

## Reimport Deduplication

**⚠️ Os processos de reimportação podem descartar completamente achados antes que sejam registrados. Isso pode causar perda de dados se configurado incorretamente, portanto as configurações de Reimport Deduplication devem ser ajustadas com cautela.**

As configurações de Reimport Deduplication podem ser usadas para definir um algoritmo para Universal Parsers, ou para um Generic Findings Import Parser.

O Reimport Deduplication não pode ser ajustado para outras ferramentas por padrão. Usuários que desejam ajustar o algoritmo de Reimport Deduplication para outras ferramentas em sua instância devem entrar em contato com o [Suporte do DefectDojo](mailto:support@defectdojo.com) para obter assistência.

![imagem](images/reimport_deduplication.png)

Ao configurar o Reimport Deduplication:

1. Selecione a **Security Tool** (Universal ou Generic Parser)
2. Escolha o **Deduplication Algorithm** apropriado

As seguintes opções de algoritmo estão disponíveis para o Reimport Deduplication:
- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

A reimportação pode descartar completamente achados antes que sejam registrados, portanto as configurações de Reimport Deduplication devem ser ajustadas com cautela.

### Track Findings as Locations Change

Quando o algoritmo de Reimport Deduplication de uma ferramenta é **Hash Code**, um toggle adicional aparece: **Track findings as locations change**. Quando habilitado, um achado cuja localização mudou entre reimportações — um deslocamento de linha ou renomeação de arquivo, uma mudança de URL, ou um aumento de versão de dependência — é tratado como o *mesmo* achado, mesmo que a ferramenta tenha reclassificado sua severidade. Um achado é mantido no lugar e seu histórico de localização é preservado, em vez de o achado antigo ser fechado e um novo idêntico ser criado.

O toggle vem desativado por padrão e se aplica apenas ao algoritmo de reimportação Hash Code (ferramentas com um Unique ID From Tool confiável já rastreiam movimentação por meio de seus IDs estáveis). Habilitá-lo recalcula automaticamente o hash dos achados existentes da ferramenta em segundo plano, para que os dados históricos participem imediatamente.

Veja [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) para saber como funciona a correspondência, o que é preservado e orientações para habilitá-la em instâncias grandes.

## Running Deduplication Retroactively on Existing Data

Uma situação comum ao ativar o Deduplication Tuning pela primeira vez é ter um grande backlog de achados que foram importados *antes* da mudança na configuração de deduplicação. No DefectDojo Pro, não é necessário executar um comando separado para deduplicar esses dados históricos — **alterar as Deduplication Settings de uma ferramenta aciona automaticamente um recálculo de hash em segundo plano de todos os achados existentes associados a esse tipo de teste**.

Na prática, isso significa:

- Quando você altera o **Deduplication Algorithm** ou os **Hash Code Fields** de uma ferramenta, o DefectDojo enfileira um job em segundo plano para recalcular os hashes de todos os achados dessa ferramenta já presentes na instância.
- O job é executado de forma assíncrona. Em instâncias grandes (milhões de achados), isso pode levar algum tempo para ser concluído, e você não verá mudanças imediatas na tabela de achados.
- Os hashes recém-calculados se aplicam às decisões de deduplicação subsequentes em todo o backlog.

Se você fizer várias alterações de configuração em rápida sucessão, cada uma enfileira seu próprio job de recálculo. Aguarde a conclusão do job anterior antes de avaliar os resultados, especialmente ao comparar as contagens de achados antes e depois da mudança.

> **Observação para o Pro autogerenciado:** o job em segundo plano é executado no pool de workers do Celery. Se você tiver workers sobrecarregados ou com backlog, o recálculo pode levar mais tempo do que o esperado — verifique a saúde dos workers se os resultados não aparecerem dentro do prazo esperado para o tamanho da sua instância.

> **Feature flags não bloqueiam uma configuração existente.** As Deduplication Settings salvas de uma ferramenta permanecem em vigor enquanto estiverem configuradas; desativar uma feature flag relacionada **não** reverte retroativamente essa ferramenta para a deduplicação padrão. Para alterar ou interromper o comportamento de deduplicação de uma ferramenta, atualize suas Deduplication Settings diretamente (o que também aciona o recálculo em segundo plano descrito acima).

## Deduplication Best Practices

Para obter os melhores resultados com o Deduplication Tuning:

- **Comece com os padrões**: as configurações de deduplicação pré-configuradas funcionam bem para a maioria dos cenários
- **Teste as mudanças com cuidado**: depois de ajustar as configurações de deduplicação, monitore algumas importações para garantir o comportamento correto.
- **Planeje os recálculos retroativos**: alterar as configurações de deduplicação recalcula o hash de todo achado existente dessa ferramenta em segundo plano. Veja [Executando a Deduplicação Retroativamente em Dados Existentes](#running-deduplication-retroactively-on-existing-data) acima.
- **Use Hash Code para deduplicação entre ferramentas**: ao habilitar a deduplicação entre ferramentas, selecione campos que identifiquem de forma confiável o mesmo achado em diferentes ferramentas (como nome da vulnerabilidade, localização e severidade). **IMPORTANTE** Cada ferramenta habilitada para deduplicação entre ferramentas **DEVE** ter os mesmos campos selecionados.
- **Mantenha as fontes cross-tool no mesmo Asset**: o Cross Tool Deduplication tem escopo de Asset. Achados divididos entre Assets separados não serão deduplicados mesmo com campos de hash correspondentes. Veja [Cross Tool Deduplication](#cross-tool-deduplication) acima.
- **Evite deduplicação excessivamente ampla**: a deduplicação entre ferramentas com poucos campos de hash pode resultar em falsos duplicados
- **Faça o backfill antes de selecionar Content Fingerprint**: execute `./manage.py backfill_fingerprints` primeiro e só então selecione o campo — assim o recálculo acionado já terá fingerprints com que trabalhar. Veja [Content Fingerprint](#content-fingerprint) acima.
- **Habilite o rastreamento de localização entre execuções de scan**: o recálculo automático do toggle cobre todo o backlog da ferramenta; em instâncias grandes, deixe-o terminar antes da próxima reimportação agendada. Veja [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#enabling-on-existing-data-upgrades).

Ao ajustar as configurações de deduplicação para suas ferramentas específicas, você pode reduzir significativamente o ruído de duplicatas.

## Locked Findings 

Sempre que as Deduplication Settings são alteradas para uma determinada ferramenta, os hashes de deduplicação são recalculados para essa ferramenta em toda a instância do DefectDojo.
