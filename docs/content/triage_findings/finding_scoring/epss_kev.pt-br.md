---
title: EPSS / KEV
description: Como o DefectDojo Pro enriquece Achados com dados de EPSS e CISA KEV,
  quando a sincronização ocorre e como isso direciona a priorização
audience: pro
weight: 2
aliases:
- /pt-br/triage_findings/epss_kev/
---

O DefectDojo Pro enriquece automaticamente seus Achados com duas fontes externas de inteligência de ameaças — **EPSS** e **CISA KEV** — para que a priorização reflita a probabilidade real de exploração de uma vulnerabilidade, e não apenas sua severidade CVSS. Ambas as fontes são associadas aos Achados pelo **CVE**, são atualizadas em uma **programação diária** e alimentam diretamente a pontuação de **prioridade** calculada de cada Achado.

Os dados de enriquecimento são armazenados **uma vez por vulnerabilidade** e depois aplicados a todo Achado que a referencia. Isso significa que um CVE presente em dez mil Achados é consultado uma única vez, e você pode inspecionar seus valores de EPSS e KEV diretamente no **Vulnerability Explorer** — não apenas Achado por Achado.

No DefectDojo Cloud, o enriquecimento é totalmente gerenciado: o DefectDojo mantém os dados subjacentes de inteligência de ameaças e os entrega à sua instância. Não há nada para instalar, nenhuma URL de feed para configurar e nenhuma tarefa diária para agendar — tudo roda para você.

## As duas fontes

### EPSS — Exploit Prediction Scoring System

O [EPSS](https://www.first.org/epss/) é um modelo orientado a dados publicado pela FIRST que estima a probabilidade de um determinado CVE ser explorado ativamente nos próximos 30 dias. O DefectDojo Pro armazena dois valores de EPSS em cada Achado correspondente:

| Field | Meaning |
| --- | --- |
| **EPSS Score** | Probabilidade de exploração nos próximos 30 dias, de `0.0` a `1.0` (por exemplo, `0.94` = 94%). |
| **EPSS Percentile** | Onde esse CVE se posiciona em relação a todos os CVEs pontuados, de `0.0` a `1.0` (por exemplo, `0.99` = entre o 1% com maior probabilidade de exploração). |

Quando um único Achado carrega **múltiplos CVEs**, o DefectDojo mantém a **maior pontuação de EPSS** entre eles e a associa ao percentil daquele mesmo CVE. O percentil sempre pertence ao mesmo CVE da pontuação — os dois nunca são combinados a partir de CVEs diferentes, porque um percentil só faz sentido junto de sua própria pontuação.

### KEV — CISA Known Exploited Vulnerabilities

O [catálogo CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) é a lista oficial do governo dos EUA de vulnerabilidades confirmadamente exploradas em ambientes reais. Diferente do EPSS (uma previsão), o KEV é uma constatação de exploração real observada. O DefectDojo Pro armazena três valores de KEV em cada Achado correspondente:

| Field | Meaning |
| --- | --- |
| **Known Exploited** | `True` quando o CVE aparece no catálogo CISA KEV. |
| **Ransomware Used** | `True` quando a CISA registra que o CVE foi utilizado em campanhas de ransomware. |
| **KEV Date** | A data em que a vulnerabilidade foi adicionada ao catálogo KEV. |

Quando um Achado carrega **múltiplos CVEs**, ele é marcado como **Known Exploited** se **qualquer um** de seus CVEs estiver no catálogo, como **Ransomware Used** se algum se qualificar, e a **KEV Date** é a data de inclusão no catálogo mais antiga entre eles.

Um sinal de KEV nunca é suprimido por um EPSS mais alto de outro CVE do mesmo Achado. Se um Achado carrega um CVE com EPSS alto que *não* está listado no KEV, e outro com EPSS baixo que *está*, o Achado assume a pontuação de EPSS mais alta **e** é marcado como Known Exploited — cada campo reflete independentemente o pior caso entre os CVEs do Achado.

> **Achados sem CVE não são enriquecidos.** Ambas as fontes fazem a correspondência estritamente por identificadores de CVE (`CVE-YYYY-NNNNN`). Um Achado sem CVE — ou apenas com um identificador específico de fornecedor ou no estilo GHSA — não recebe dados de EPSS ou KEV.

## Quando a sincronização ocorre

O enriquecimento roda **uma vez por dia, automaticamente**. Cada execução acontece em duas etapas:

1. **Atualizar os dados da vulnerabilidade.** Todo CVE conhecido pelo DefectDojo é reverificado em relação aos dados mais recentes de EPSS e KEV, e o registro por vulnerabilidade é atualizado.
2. **Aplicar as mudanças aos Achados.** Apenas as vulnerabilidades cujos valores realmente *mudaram* são propagadas para os Achados que as referenciam, e apenas esses Achados são repontuados.

Como a segunda etapa é orientada pelo que mudou, um dia tranquilo é barato: se nenhuma das fontes publicou novidades, a execução termina sem reescrever seus Achados. Quando algo muda de fato — uma pontuação de EPSS se altera, ou um CVE é adicionado ao catálogo KEV — todo Achado afetado recebe essa mudança na próxima execução.

Algumas consequências que vale a pena entender:

- **Os Achados normalmente são enriquecidos já na importação.** Desde a **v3.2.0**, o enriquecimento de EPSS/KEV é aplicado no momento da importação, então um Achado com CVE recém-importado geralmente não precisa esperar o próximo ciclo diário para exibir valores. A rapidez disso depende de o DefectDojo já ter consultado aquele CVE antes — veja [O que "enriquecido no momento da importação" cobre](#what-enriched-at-import-time-covers) abaixo. A execução diária continua rodando por cima disso, mantendo esses valores atualizados conforme as pontuações de EPSS mudam e o catálogo KEV é alterado. Se um Achado que você esperava ver enriquecido não estiver, você pode [executar uma sincronização sob demanda](#running-a-sync-on-demand).
- **Os valores são mantidos atualizados, não congelados.** Um CVE que é adicionado ao catálogo KEV fará com que um Achado existente vire **Known Exploited** na próxima execução — sem necessidade de reimportação.
- **As remoções do KEV são respeitadas.** Se os CVEs de um Achado deixarem de constar no KEV, a execução limpa os valores obsoletos de **Known Exploited** / **Ransomware Used** / **KEV Date** em vez de deixá-los definidos.

### O que "enriquecido no momento da importação" cobre

Como os dados de enriquecimento são armazenados uma vez por vulnerabilidade, uma importação só consegue aplicar instantaneamente aquilo que o DefectDojo já consultou antes. Há três casos:

| At import, the CVE is… | When the Finding shows EPSS/KEV |
| --- | --- |
| **Já enriquecido** — o DefectDojo já consultou esse CVE antes, para qualquer Achado em qualquer Produto | **Imediatamente**, como parte da importação. Este é o caso comum: CVEs se repetem entre scans e entre equipes, então a maioria dos CVEs em uma importação típica já é conhecida. |
| **Novo para o DefectDojo**, e a importação traz apenas um número modesto de novos CVEs | **Pouco depois da importação**, em segundo plano. Como ainda não há nada armazenado para aplicar, a importação solicita uma consulta apenas para esses CVEs e aplica os resultados quando eles retornam. |
| **Novo para o DefectDojo**, e a importação traz um número muito grande de novos CVEs — uma primeira importação ou um backfill em massa | **Na próxima execução diária**, ou na próxima [sincronização sob demanda](#running-a-sync-on-demand). Consultar milhares de CVEs totalmente novos enquanto a importação ainda está em andamento duplicaria o trabalho da execução diária, então isso é deliberadamente deixado para essa execução. |

Em todos os casos os valores chegam sem necessidade de reimportação, e a execução diária continua sendo a rede de segurança — nada fica permanentemente pendente.

> **As sincronizações de conectores são enriquecidas da mesma forma**, com uma exceção: uma **sincronização de conector muito grande é importada em blocos (chunks)**, e sincronizações em blocos não enriquecem no momento da importação. Esses Achados recebem seus valores de EPSS/KEV na próxima execução diária, ou em uma sincronização sob demanda.

## Visualizando KEV/EPSS no Vulnerability Explorer

O **Vulnerability Explorer** lista uma linha por ID de vulnerabilidade, com as mesmas cinco colunas de KEV/EPSS que você encontra na tabela de Achados — **EPSS Score**, **EPSS Percentile**, **Known Exploited**, **Ransomware Used** e **KEV Date**:

![image](images/Pro_EPSS_KEV_Explorer_Columns.png)

Esses valores descrevem a própria vulnerabilidade, então são idênticos independentemente de quantos Achados a referenciam. EPSS Score, EPSS Percentile, Known Exploited e KEV Date são todos ordenáveis, o que torna essa a forma mais rápida de responder "quais vulnerabilidades no meu ambiente estão realmente sendo exploradas?" — ordene por **EPSS Score** decrescente, ou ordene por **Known Exploited** para trazer os CVEs listados no catálogo para o topo.

A contagem de **Total Findings** de cada linha leva à lista de Achados filtrada por aquela vulnerabilidade, permitindo ir de "esse CVE está listado no KEV" a "aqui está tudo o que ele afeta" em um único clique.

## Diferenciando "sem dados" de "não explorado"

Uma coluna de KEV/EPSS em branco e um ✗ vermelho significam coisas diferentes:

- **✗ vermelho / uma pontuação** — essa vulnerabilidade *foi* verificada. Um ✗ em Known Exploited significa que a CISA não a lista.
- **Em branco** — essa vulnerabilidade **nunca foi enriquecida**, então seu status de exploração é simplesmente desconhecido.

Aqui, o mesmo Explorer nunca foi sincronizado, então toda coluna de KEV/EPSS aparece em branco em vez de mostrar zeros ou marcas de ✗:

![image](images/Pro_EPSS_KEV_Explorer_Unenriched.png)

A mesma distinção aparece no próprio Achado. Um Achado cujos CVEs ainda não foram enriquecidos informa isso claramente, e traz um link para o Explorer, onde você pode iniciar uma sincronização:

![image](images/Pro_EPSS_KEV_Not_Enriched.png)

Assim que o enriquecimento é executado, o mesmo painel relata o que foi de fato encontrado:

![image](images/Pro_EPSS_KEV_Finding_Panel.png)

Isso importa porque "ainda não verificamos" e "verificamos e não está sendo explorado" seriam, de outra forma, indistinguíveis — e apenas um desses casos é motivo para relaxar.

## Executando uma sincronização sob demanda

Você não precisa esperar pelo ciclo diário. O botão **Sync KEV/EPSS data**, no topo do Vulnerability Explorer, inicia uma sincronização imediatamente:

![image](images/Pro_EPSS_KEV_Sync_Started.png)

Enquanto uma sincronização está em execução, o botão fica desabilitado e uma barra de progresso aparece em seu lugar, junto com uma estimativa do tempo restante assim que trabalho suficiente tiver sido concluído para projetá-la. A linha de status acima dele informa o que está acontecendo — primeiro que o DefectDojo está verificando quais vulnerabilidades mudaram, depois quantos Achados já foram atualizados até o momento. Quando a execução termina, a linha relata o resultado: quantos Achados mudaram, que tudo já estava atualizado ou — caso nenhuma fonte esteja configurada — que a sincronização não foi executada.

Apenas uma sincronização roda por vez. Clicar no botão enquanto uma já está em andamento simplesmente conecta você à execução já em curso, em vez de iniciar uma segunda, então é seguro clicar mesmo sem saber se uma sincronização já está em andamento. Uma sincronização também é segura de repetir: se nada mudou desde a última execução, ela não reescreve nada.

Essa é a forma mais rápida de trazer as mudanças de EPSS e KEV publicadas desde o último ciclo diário, e de preencher quaisquer Achados que ainda não exibam dados de enriquecimento.

## Como isso impacta a prioridade e o risco

EPSS e KEV não são apenas selos informativos — são entradas diretas para o **mecanismo de priorização** do DefectDojo Pro. A pontuação de `priority` de cada Achado combina vários componentes (severidade, exposição, contexto do ativo e outros); EPSS e KEV alimentam o componente de **pontuação externa**, que valoriza vulnerabilidades que são prováveis de ser — ou que são conhecidas por ser — exploradas.

A pontuação externa deriva do que for **mais forte** entre os seguintes sinais:

- O **EPSS** contribui proporcionalmente à sua pontuação — quanto maior a probabilidade de exploração, maior a contribuição.
- A **listagem no KEV** contribui com um peso fixo: estar **Known Exploited** *ou* ter sido usado em **ransomware** aplica um aumento significativo, e um CVE que é **tanto** Known Exploited **quanto** usado em ransomware aplica o maior aumento possível.

O maior dos dois sinais prevalece, então um Achado recebe crédito total tanto por uma alta pontuação de EPSS quanto por uma listagem no KEV, sem ser penalizado por não ter o outro. Essa pontuação externa é então combinada com a prioridade geral do Achado, junto com sua severidade e exposição. O efeito final: **um Achado listado no KEV ou com EPSS alto sobe acima de um Achado comparável que não tem nenhum dos dois**, concentrando a remediação no que é genuinamente mais provável de ser atacado.

> **EPSS e KEV são a base — [Threat Intelligence](/asset_modelling/pro_hierarchy/threat_intelligence/) a estende.** Com o Threat Intelligence Enrichment habilitado, essa mesma pontuação externa também reconhece exploits públicos armados (weaponized), templates de detecção do Nuclei, código de prova de conceito e exploração ativa confirmada, cada um atuando como um *piso (floor)* na escala de EPSS. Ele também adiciona o [Actively-Exploited Risk Floor](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor), que impede que um Achado sendo explorado em ambiente real permaneça em uma faixa de Risco baixa apenas porque sua severidade base é Baixa. Assim como EPSS e KEV, esses sinais só aumentam uma pontuação, nunca a diminuem.

Isso ocorre automaticamente — a prioridade é recalculada exatamente para os Achados atualizados por cada execução de enriquecimento, mantendo a priorização alinhada com a inteligência de ameaças mais recente.

> **Observação:** EPSS e KEV influenciam a pontuação de **prioridade**. Eles não alteram o campo de **Severidade** de um Achado. Eles podem, no entanto, afetar o prazo de **SLA**: se sua configuração de SLA tiver o **Cap by KEV due date** habilitado, o prazo de SLA de um Achado listado no KEV é antecipado para a data de remediação definida pela CISA para aquele CVE. Quando um Achado carrega vários CVEs listados no KEV, aplica-se a data mais próxima.

## Filtrando e visualizando Achados enriquecidos

Depois que os Achados são enriquecidos, os valores de EPSS e KEV ficam disponíveis em toda a interface do Pro:

- **No Achado** — EPSS score, EPSS percentile, Known Exploited, Ransomware Used e KEV Date aparecem todos no detalhe do Achado.
- **Ordenação** — as tabelas de Achados podem ser ordenadas por EPSS score / percentile para trazer primeiro os Achados com maior probabilidade de exploração.
- **Filtragem** — a lista de Achados oferece filtros de **Known Exploited** e **Ransomware Used**, permitindo montar visualizações ou relatórios com foco em vulnerabilidades com exploração real confirmada.

Um fluxo de trabalho comum é filtrar por **Known Exploited = true** e depois ordenar por prioridade, produzindo uma fila de "corrigir isso primeiro" respaldada por exploração confirmada.

## Configuração

No **DefectDojo Cloud**, o enriquecimento de EPSS e KEV já vem habilitado e é mantido para você — não há alternâncias de fonte, URLs de feed ou limites para configurar, e a sincronização diária é gerenciada pelo DefectDojo. Os pesos que traduzem EPSS e KEV em prioridade já estão embutidos no mecanismo de priorização.

Se os dados de EPSS ou KEV não estiverem aparecendo em Achados nos quais você esperava vê-los (e esses Achados de fato carregam CVEs), comece verificando a linha de status no Vulnerability Explorer — ela relata o resultado da sincronização mais recente, inclusive quando nenhuma fonte está configurada. Se isso parecer normal e os dados ainda estiverem ausentes, entre em contato com o suporte do DefectDojo, que pode confirmar se a sincronização diária está entregando dados para sua instância.

> *Instalações on-premise* configuram o enriquecimento de forma diferente — cada fonte pode ser habilitada ou desabilitada e apontada para uma URL de feed personalizada nas configurações de enriquecimento de achados do Tuner. Essa configuração não se aplica ao Cloud, onde os dados são entregues pelo DefectDojo.
