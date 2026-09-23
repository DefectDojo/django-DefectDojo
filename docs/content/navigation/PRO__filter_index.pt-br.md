---
title: Índice de Filtros
description: Referência de todos os filtros no DefectDojo
weight: 5
aliases:
- /pt-br/en/working_with_findings/organizing_engagements_tests/filter_index
---

**Nota: atualmente este artigo cobre apenas os Filtros de Achados disponíveis na interface do DefectDojo Pro, mas este artigo será expandido no futuro para abranger mais tipos de objeto, além dos filtros Open-Source.**

Aqui está uma lista de filtros que podem ser aplicados na interface do DefectDojo Pro para ordenar listas de Achados.  Os Filtros do DefectDojo podem ser usados para ajudar a navegar por listas de Objetos, construir [painéis](/metrics_reports/dashboards/custom-dashboards/) personalizados, ou criar automações por meio do [Rules Engine](/automation/rules_engine/about).

## Como os filtros de data são avaliados

Os filtros que recebem uma data — **Date Created**, **SLA Expiration Date**, **Last Status Update**, **Planned Remediation Date**, e os filtros de data do Jira listados abaixo — oferecem cinco operadores:

| Operador | Corresponde a |
| --- | --- |
| **On** | O dia indicado por completo. |
| **Before** | Tudo até o início do dia indicado. O próprio dia indicado **não** é incluído. |
| **After** | Tudo a partir do início do dia indicado — portanto o dia indicado **é** incluído. |
| **During** | Um dia inicial até um dia final, ambos **inclusivos**. |
| **Within** | Uma janela móvel que termina agora: últimos 7, 14, 30, 90 ou 180 dias, ou o último ano. |

Observe que **Before** e **After** deliberadamente não são espelhos um do outro: *Before 8 August* exclui o dia 8 de agosto, enquanto *After 8 August* o inclui.

### Limites de dia e seu fuso horário

**On**, **Before**, **After** e **During** resolvem seus limites de dia no **seu próprio fuso horário**, detectado a partir do seu navegador. Um intervalo de datas, portanto, cobre de meia-noite a meia-noite conforme *você* o experimenta, e não em UTC ou no fuso horário do servidor. Duas pessoas em fusos horários diferentes podem ver resultados ligeiramente diferentes no mesmo filtro para Achados próximos a um limite de dia.

**Within** não é afetado — é uma janela móvel medida a partir do momento atual, então não tem limite de dia a resolver.

> **Onde isso não se aplica.** Somente as requisições feitas pela interface Pro carregam seu fuso horário. Qualquer coisa que roda sem um navegador — a API REST `/api/v2`, os relatórios agendados e o Rules Engine — usa o fuso horário configurado no servidor (`DD_TIME_ZONE`, `UTC` a menos que seu administrador o tenha alterado). Se o fuso horário do seu navegador for diferente do servidor, um relatório agendado e um filtro em tela usando a mesma data podem retornar linhas ligeiramente diferentes. As exportações iniciadas a partir de uma tabela filtrada na interface não são afetadas — elas usam o seu fuso horário, correspondendo ao que você estava vendo.

## Como os filtros numéricos são avaliados

Os filtros numéricos — incluindo **Age** e **SLA** — oferecem um operador de correspondência junto com o valor: **Equals**, **Not Equals**, **Greater Than**, **Greater Than or Equal To**, **Less Than**, **Less Than or Equal To**, **In List** e **Not In List**. Inserir um valor sem escolher um operador corresponde a **Equals**.

## Filtros de SLA

Três filtros cobrem o SLA, e eles respondem a perguntas diferentes:

| Filtro | Tipo | O que corresponde |
| --- | --- | --- |
| **SLA Expiration Date** | Data, com os operadores acima | A data em que o SLA do Achado se esgota. |
| **SLA** | Número, com operadores | **Dias restantes** no prazo do SLA. Valores negativos estão atrasados, então `Less Than 0` encontra tudo que já está fora do prazo, e `Less Than 7` encontra o que vence dentro da semana. |
| **Mitigated Within SLA** | Verdadeiro / Falso | Se um Achado que **foi mitigado** foi mitigado antes do vencimento do seu SLA. |

**Mitigated Within SLA é mais restrito do que parece, e isso costuma pegar as pessoas de surpresa.** Ambos os valores só correspondem a Achados que **já foram mitigados** e que **não são de severidade Info**:

* **True** — mitigado na data de vencimento do SLA ou antes dela.
* **False** — mitigado após a data de vencimento do SLA.

Um Achado **aberto** que já está atrasado não corresponde a **nenhum** dos dois valores, porque ainda não foi mitigado. Para encontrar esses casos, use **SLA** `Less Than 0`. Achados de severidade Info são excluídos de ambos os lados.

> Se a configuração de SLA de um Achado tiver **Cap SLA by CISA KEV Due Date** habilitado, tanto **SLA** quanto **SLA Expiration Date** refletem o prazo reduzido e limitado pelo KEV, em vez da janela simples baseada em severidade. Não há um indicador separado para isso nos filtros — veja [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/).

## Achados
Estes campos são específicos dos Achados do DefectDojo e são usados para organizar um Achado.  Cada um desses filtros é uma coluna separada na tabela All Findings.

Os Achados no DefectDojo podem ser filtrados por:

### Metadados do DefectDojo
Estes Filtros estão diretamente relacionados à funcionalidade principal do DefectDojo.

##### Não podem ser modificados
Estes Filtros são atribuídos no momento da criação do problema e não podem ser modificados diretamente por meio de Edit Finding.

* Finding Severity (qualquer um entre Info, Low, Medium, High, Critical)
* Product
* Product Type
* Engagement
* Engagement Version
* Test
* Test Type
* Test Version
* Date Created
* Age (idade do Achado em dias)
* SLA (dias restantes no prazo do SLA — negativo significa atrasado; veja [Filtros de SLA](#sla-filters))
* SLA Expiration Date (veja [Filtros de SLA](#sla-filters))
* Mitigated Within SLA (Verdadeiro ou Falso — note que isso só corresponde a Achados que já foram Mitigados; veja [Filtros de SLA](#sla-filters))
* Reporter (usuário ou serviço que criou o Achado)
* Found by (refere-se à Ferramenta)

##### Podem ser modificados
Estes campos são definidos quando um problema é criado, mas podem ser modificados conforme o problema evolui.

* [Status](/triage_findings/findings_workflows/finding_status_definitions/)
* Last Status Update (Timestamp)
* Mitigated (Verdadeiro ou Falso)

##### Funções de Modelo Adicionais
Estas funções do DefectDojo podem ser usadas para organizar ainda mais seus Achados ou acompanhar a remediação.

* Finding Tags
* Reviewers (usuário atribuído)
* Has Notes (Verdadeiro/Falso)
* Group (refere-se ao [Finding Group](/triage_findings/findings_workflows/editing_findings/#finding-group-actions), se houver um)
* Risk Acceptance (selecione uma ou mais Risk Acceptances existentes na lista)

### Metadados Específicos da Ferramenta
Estes campos não têm impacto direto na funcionalidade do DefectDojo, mas fornecem informações adicionais para ajudar a explicar e mitigar problemas.  Eles podem ser definidos quando um Achado é criado inicialmente (usando informações de um relatório recebido), ou podem ser alterados por um usuário.

* CWE Value
* Vulnerability ID (geralmente um CVE)
* EPSS Score
* EPSS Percentile
* Service
* Planned Remediation Date
* Planned Remediation Version
* Has Component (Verdadeiro/Falso)
* Component Name
* Component Version
* File Path
* Effort for Fixing

### Metadados do Jira
Se estiver usando a integração com o Jira, estes filtros acompanham atualizações em Issues do Jira vinculadas.

* Jira Issue (pode filtrar se o Achado tem uma ou não)
* Jira Age (idade da Issue do Jira)
* Jira Change (última vez que mudanças foram enviadas ao Jira)
