---
title: Correlação de Causa Raiz
description: Agrupe Achados que compartilham uma causa raiz -- o mesmo componente
  vulnerável, CVE, recurso de infraestrutura ou fraqueza em uma URL -- para que uma
  única correção possa ser rastreada até cada Achado que ela resolve
weight: 1
audience: pro
---

Uma biblioteca vulnerável incorporada em quarenta serviços produz quarenta Achados. Cada um é real, cada
um é triado separadamente, e cada um é corrigido pela mesma atualização de versão. A **Correlação
de Causa Raiz** torna essa relação explícita: o DefectDojo Pro agrupa Achados que compartilham uma causa
raiz em uma lista classificada de **Causas Raiz**, para que você possa ver a correção única e tudo o que ela resolve.

A correlação é **aditiva e não destrutiva**. Cada Achado permanece independentemente visível,
mantém seu próprio status, e é triado exatamente como antes. A correlação apenas adiciona vínculos entre
Achados, os nós de cluster nos quais esses vínculos se agrupam, e as evidências que produziram cada vínculo.

> **Correlação não é deduplicação.** A [Deduplicação](/triage_findings/finding_deduplication/)
> decide que dois relatórios descrevem o *mesmo* Achado e marca um deles como duplicado. A correlação
> relaciona Achados *diferentes* que por acaso compartilham uma causa, e nunca marca nada como
> duplicado. As duas funcionam independentemente e podem ser habilitadas simultaneamente.

## Habilitando a Correlação de Causa Raiz

A Correlação de Causa Raiz está em **Beta**, é controlada por um feature flag, e vem **desativada por padrão**.
Um superusuário pode ativá-la em **Settings > Feature Flags** tanto em instâncias Cloud quanto On-Premise.
Veja [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Enquanto o flag estiver desativado, o mecanismo não realiza nenhum trabalho: nenhum cluster é construído, nenhum vínculo é
criado, e nada é disparado após uma importação.

Após ativar o flag, os Achados existentes **não** são correlacionados retroativamente até que
sejam importados novamente ou até que você execute um backfill (veja
[Preenchendo retroativamente Achados existentes](#backfilling-existing-findings)).

## O que é correlacionado

A correlação agrupa com base em quatro sinais. Três deles são **exatos** -- um vínculo só é criado quando
dois Achados genuinamente nomeiam a mesma coisa -- e um é uma heurística rotulada como tal.

| Tipo de Causa Raiz | Os Achados são agrupados quando... | Exemplo | Correspondência |
|---|---|---|---|
| **Componente** | referenciam o mesmo componente de software na mesma versão | `log4j-core 2.14.1` | Exata |
| **CVE** | referenciam o mesmo identificador de CVE | `CVE-2021-44228` | Exata |
| **Recurso** | nomeiam o mesmo objeto de infraestrutura | `aws_s3_bucket.logs` | Exata |
| **Endpoint** | reportam a mesma classe de fraqueza na mesma URL | `CWE-79 at example.com/search` | Heurística |

Um Achado se junta a **todos** os clusters aplicáveis a ele, não apenas a um. Um Achado de SCA para
`log4j-core 2.14.1` que carrega três CVEs se junta a quatro Causas Raiz: seu cluster de componente e um
cluster por CVE. É isso que permite que um Achado de imagem de contêiner que reporta apenas um CVE se correlacione
com o Achado de SCA que reporta o componente.

### Correspondência de componente

Onde o modelo de dados Locations está em uso, os componentes são indexados pela **Package URL (purl)**,
com qualificadores e subcaminhos removidos, de modo que o mesmo pacote reportado em diferentes distribuições
ou arquiteturas forme um único cluster em vez de vários. Achados que carregam apenas os campos legados
`component_name` / `component_version` são indexados por esses campos.

Achados sem um componente utilizável são ignorados em vez de agrupados: uma versão ausente, ou o
placeholder `unknown-package` que alguns formatos de SBOM emitem, do contrário colapsaria toda
linha sem componente em um único cluster sem sentido.

### Correspondência de CVE

Os identificadores de CVE são convertidos para maiúsculas e sofrem trim, de modo que `cve-2021-44228` e `CVE-2021-44228` caem
no mesmo cluster. Apenas identificadores CVE são correspondidos — GHSA, GO, RUSTSEC e outros prefixos de aviso são
reconhecidos como ids de vulnerabilidade em outras partes do DefectDojo, mas ainda não formam Causas Raiz.

### Correspondência de recurso

Ferramentas de postura de nuvem (CSPM) e infraestrutura como código (IaC) reportam um **recurso** em vez de um
pacote: um bucket S3, um namespace do Kubernetes, um bloco de recurso do Terraform. Esses Achados carregam um
nome mas nenhuma versão, então não são componentes de software e não são correspondidos como tal.

A correspondência de recurso os agrupa pelo identificador do recurso, normalizado para maiúsculas/minúsculas de modo que ferramentas que o escrevem
de forma diferente ainda concordem. É uma correspondência exata, e é o que permite que um Achado de IaC sobre
`aws_s3_bucket.logs` fique na mesma Causa Raiz que o Achado de CSPM em tempo de execução sobre o bucket
implantado.

Apenas identificadores qualificados são correspondidos -- um nome de recurso carrega um tipo ou separador de caminho
(`.`, `/`, `:`). Uma única palavra isolada é ignorada, de modo que um Achado cujo scanner simplesmente omitiu a
versão do componente não é arrastado para um cluster de recurso com o qual não tem nada a ver.

### Correspondência de endpoint

Duas ferramentas DAST escaneando a mesma aplicação frequentemente reportam a mesma fraqueza na mesma
URL. A correspondência de endpoint agrupa esses casos: a Causa Raiz é uma **classe de fraqueza em um local**, por
exemplo `CWE-79 at example.com/search`.

Este é o único sinal **heurístico**, e é rotulado como tal em todos os lugares onde aparece. Um purl ou
CVE compartilhado é uma identidade; "mesmo CWE, mesma URL" é um julgamento, e um revisor deve poder
avaliá-lo de forma diferente. O detalhe do cluster marca cada membro com seu tipo de correspondência.

O CWE é obrigatório. Uma URL isolada é um lugar, não uma causa -- agrupar todo Achado em
`/search` independentemente do que está errado produziria clusters grandes e sem sentido.

Strings de consulta, fragmentos e portas são ignorados ao comparar URLs, de modo que `/search?q=a` e
`/search?q=b` são o mesmo lugar, assim como o mesmo serviço em 443 e 8443.

> **Isso não correlaciona SAST com DAST.** Achados estáticos identificam um arquivo de origem e achados
> dinâmicos identificam uma URL; mapear entre os dois exigiria um mapa de rotas que o DefectDojo não possui.
> A correspondência de endpoint relaciona achados dinâmicos entre si.

### Quando um CVE já é coberto por um componente

Um Achado se junta à sua causa de componente *e* a cada uma de suas causas de CVE, então um Achado de SCA para
`log4j-core 2.14.1` carregando dois CVEs produz três Causas Raiz. Deixados sozinhos, todos os três competem
pelo topo da lista classificada — mas apenas um deles representa trabalho de fato. Atualizar o `log4j-core`
para uma versão corrigida resolve ambos os CVEs de uma vez; não existe uma ação separada de "corrigir o CVE-2021-44228".

Então, uma Causa Raiz de CVE é marcada como **coberta** quando *todos* os seus Achados membros ativos também são
membros ativos de uma única causa de componente ou recurso. Causas cobertas são ocultadas da
página de Causas Raiz por padrão, mantendo a lista restrita a coisas que você pode realmente resolver.

No momento em que **um** membro fica fora daquele componente, o CVE volta a valer por si só. É esse
o caso do Achado de imagem de contêiner que reporta apenas um CVE sem componente associado: nenhuma correção de componente
o alcança, então o CVE é de fato um trabalho separado. Este é exatamente o caso entre domínios que a
correlação existe para revelar, e nunca é ocultado.

Ative **Show covered CVEs** acima da tabela para vê-los. Cada um é rotulado com a causa
que o cobre, deixando claro qual correção o resolve. Causas cobertas são apenas ocultadas da
lista padrão — elas mantêm seus membros, evidências e feedback, permanecem acessíveis a partir do
painel de Causas Raiz de um Achado, e um link salvo para uma delas ainda abre normalmente.

A cobertura é reavaliada a cada execução, nas duas direções: um CVE deixa de estar coberto assim que
um Achado não coberto aparece, e volta a ser coberto assim que esse Achado é corrigido ou triado para
fora. Rejeitar um vínculo também remove esse membro do cálculo, já que você indicou que ele não
pertence ali.

Causas de componente e de recurso nunca são marcadas como cobertas, mesmo quando seus membros se sobrepõem
aos de outra. Cada uma tem sua própria versão a atualizar, então cada uma representa trabalho real.

### Quais Achados são elegíveis

Apenas Achados ativos e acionáveis são correlacionados. Um Achado é excluído enquanto está inativo,
mitigado, duplicado, falso positivo, fora do escopo, ou com risco aceito. Achados saem de
seus clusters à medida que são triados, de modo que as contagens de uma Causa Raiz sempre descrevem o trabalho pendente.

## Lendo a página de Causas Raiz

Abra **Root Causes** na seção **Manage** da barra lateral. A página lista todas as Causas Raiz
às quais você tem acesso, classificadas de modo que as maiores e mais arriscadas apareçam primeiro.

| Coluna | O que ela informa |
|---|---|
| **Root Cause** | O componente e a versão, ou o CVE |
| **Type** | Componente, CVE, Recurso ou Endpoint |
| **Fix** | A versão que corrige o problema, quando os membros do cluster concordam em uma |
| **CVEs** | Todo CVE visto entre os membros do cluster (clusters de componente) |
| **Active Findings** | Quantos Achados pendentes essa causa representa |
| **Products** | Raio de impacto — quantos Produtos são afetados |
| **Risk** | Risco agregado, somado a partir das severidades dos membros ativos |
| **Muted** | Se o cluster foi silenciado |

Causas de CVE que já são totalmente cobertas por uma causa de componente ou recurso ficam ocultas a menos que
**Show covered CVEs** esteja ativado; veja
[Quando um CVE já é coberto por um componente](#when-a-cve-is-already-covered-by-a-component).

Selecionar uma linha abre o cluster, listando cada Achado membro com sua severidade, Produto,
domínio, tipo de **correspondência**, e a **evidência** que o vincula. A evidência é registrada por vínculo, de modo que um
cluster sempre pode se explicar: um vínculo de componente registra o purl com o qual houve correspondência, um vínculo de CVE
registra o identificador, um vínculo de endpoint registra a URL e o CWE. A coluna **Match** exibe
`exact` para vínculos de componente, CVE e recurso, e `heuristic` para vínculos de endpoint, de modo que um julgamento
nunca é apresentado como uma identidade.

O risco agregado é uma soma determinística sobre as severidades dos membros ativos (Crítica 100, Alto
70, Médio 40, Baixo 10, Informativa 1). Não depende de o mecanismo de priorização estar habilitado.

**Fix** é obtido das próprias versões de correção dos membros, e só é exibido quando todo membro que
reporta uma versão reporta a mesma. Scanners divergem, e um cluster de CVE pode abranger componentes que
são corrigidos em versões diferentes, então, onde não há uma resposta única, a coluna fica
vazia em vez de escolher uma.

### O que você vê é limitado ao seu acesso

Membros, contagens e raio de impacto são filtrados de acordo com os Achados que você está autorizado a ver, e a
classificação é calculada após essa filtragem. Dois usuários com acesso diferente a Produtos, portanto,
verão contagens diferentes para a mesma Causa Raiz, e um cluster cujos membros você não pode ver
simplesmente não aparece para você.

## Onde mais a correlação aparece

### Em um Achado

A própria página de um Achado carrega um painel **Root Causes** listando todos os clusters aos quais ele pertence, divididos
entre o componente vulnerável (ou recurso) e os CVEs que compartilha. É geralmente aí que a
correlação é mais útil: você já está triando um Achado e ela informa que a correção é
compartilhada. Vínculos que você rejeitou não reaparecem ali.

### Na priorização de achados

Uma Causa Raiz que abrange muitos Produtos torna cada um de seus Achados membros mais urgente, porque a
única correção resolve todos eles. A prioridade, portanto, aumenta com o **raio de impacto da mais ampla
Causa Raiz à qual um Achado pertence**:

- Um cluster confinado a um único Produto não acrescenta nada -- não há uma história de "uma correção resolve muitos".
- Cada Produto afetado adicional acrescenta um pouco mais, até um limite, de modo que um cluster muito amplo
  não pode superar a severidade.
- Conta o cluster mais amplo, não a soma de todos eles, de modo que um Achado não é elevado apenas por
  carregar muitos ids de CVE.
- Vínculos que você **rejeitou** deixam de contar. Um cluster **silenciado** ainda conta: silenciar o oculta
  da lista classificada, não indica que os Achados não estão relacionados.

O peso é ajustável por Produto como o multiplicador **Correlation** no Prioritization Engine,
ao lado de Severity, Exploitability, Endpoints e Reachability. O termo inteiro desaparece quando o
feature flag está desativado, de modo que as pontuações permanecem inalteradas em uma instância que não usa correlação.

### Em um painel

**Top Root Causes** está disponível como um widget de painel, listando os clusters mais bem classificados com
suas contagens de achados, Produtos afetados e risco. Adicione-o a partir do seletor de widgets; ele aparece ali
apenas enquanto o recurso está habilitado. Suas contagens são limitadas ao seu acesso da mesma forma que a página
é.

## Dando feedback sobre um cluster

A correlação é um julgamento sobre seus dados, então você pode corrigi-la.

- **Confirm** um membro para registrar que o vínculo está correto.
- **Reject** um membro para registrar que não está, o que o remove da lista de
  membros ativos do cluster.
- **Mute** uma Causa Raiz inteira para que ela pare de competir por atenção na lista classificada. **Unmute**
  a restaura.

O feedback é durável. A rotatividade normal de reimportação — um Achado sendo mitigado e depois reativado
— não apaga uma confirmação ou uma rejeição, e um cluster silenciado nunca é limpo mesmo quando
temporariamente não tem membros. Apenas os vínculos que o sistema criou por conta própria são reconciliados quando
deixam de se aplicar.

## Como e quando a correlação é executada

A correlação é executada **automática e assincronamente após toda importação e reimportação**, sobre os
Achados que a importação afetou. É best-effort: uma falha dentro da correlação é registrada em log e
absorvida, e nunca faz a importação que a disparou falhar.

Por ser idempotente, executá-la novamente sobre os mesmos Achados converge para o mesmo resultado
em vez de duplicar qualquer coisa. À medida que os Achados mudam, o mecanismo também reconcilia: uma atualização de
versão de componente move o Achado para o novo cluster e remove o antigo assim que ele fica vazio.

### Preenchendo retroativamente Achados existentes

Para correlacionar Achados anteriores à habilitação do recurso, execute o comando de gerenciamento. Omita
o argumento para recalcular todo o portfólio, ou restrinja a um único Produto:

```bash
python manage.py recompute_correlations
python manage.py recompute_correlations --product-id 42
```

## O que a API expõe

As Causas Raiz podem ser lidas pela API padrão, de modo que você pode extraí-las para um relatório, abrir tickets
a partir delas, ou acompanhá-las como uma métrica sem passar pela interface.

- `GET /api/v2/root_causes/` as lista, classificadas da mesma forma que a página.
- `GET /api/v2/root_causes/{id}/` retorna uma Causa Raiz mais seus Achados membros, cada um com a
  evidência que o vincula e se a correspondência foi exata ou heurística.

Ambos são somente leitura. Confirmar, rejeitar e silenciar são feitos pela interface por enquanto; isso é
deliberadamente não publicado enquanto o recurso está em Beta, de modo que adicioná-los depois não quebre
nada que você já tenha construído em cima disso.

Filtros na listagem: `cause_type` (`exact` ou `in`), `muted`, `identity_key` (`exact` ou
`icontains`) e `display_name__icontains`.

Dois comportamentos que vale a pena conhecer antes de automatizar chamadas contra essa API:

- **As contagens são limitadas ao acesso do token**, exatamente como na interface. Dois tokens com
  acesso diferente a Produtos reportarão `active_member_count`, `product_count` e
  `risk_score` diferentes para a mesma Causa Raiz. Isso é intencional -- os números descrevem o que *aquele*
  chamador pode ver -- então não os trate como totais do portfólio inteiro.
- **Causas de CVE cobertas ficam fora da listagem**, mas sempre podem ser recuperadas pelo id. Passe
  `?include_subsumed=true` para incluí-las; um id de Causa Raiz que você armazenou anteriormente continua funcionando
  via `GET /api/v2/root_causes/{id}/` mesmo depois de se tornar coberta. Cada causa coberta
  carrega `subsumed_by_id` e `subsumed_by_name` para que você veja qual correção a resolve.

Se o feature flag estiver desativado, ambos os endpoints retornam **403**, não 404 -- o endpoint existe, ele
simplesmente não está habilitado.

## Interação com a Deduplicação Global de Componentes

A [Deduplicação Global de Componentes](/triage_findings/finding_deduplication/pro__global_component_deduplication/)
marca Achados de SCA entre Produtos como duplicados, e duplicados não são correlacionados. Com ambos os
recursos ativados, a contagem de membros de uma Causa Raiz, portanto, reflete os originais sobreviventes em vez de
cada ocorrência. Os dois também se baseiam em coisas diferentes — a Deduplicação Global de Componentes corresponde por nome e
versão do componente, enquanto a correlação usa a Package URL completa — então habilitar ambos é suportado,
mas as contagens que produzem não são diretamente comparáveis.
