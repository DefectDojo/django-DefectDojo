---
title: Construindo Regras
description: O editor de grafos, gatilhos, escopo, condições e modelos de mensagem
weight: 2
audience: pro
aliases:
- /pt-br/automation/rules_engine_v2/building_rules/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: O Rules Engine 2.0 é um recurso exclusivo do DefectDojo Pro.</span>

Uma regra é construída em uma tela (canvas). Você arrasta nós de uma paleta, os conecta entre si e configura cada um em um painel lateral. Esta página aborda as partes desse processo que são iguais independentemente dos nós usados. Os próprios nós estão descritos em [Node Reference](../node_reference/).

## O editor

Abra **Rules Engine 2.0 > All Rules** e escolha **New Rule**, ou abra uma regra existente para editá-la.

A paleta é agrupada em quatro categorias, que também é a ordem em que os itens fluem por um grafo típico:

| Categoria | O que os nós fazem |
|----------|-------------------|
| **Triggers** | Decidem quando a regra é ativada e quais Achados entram nela. Exatamente um por grafo. |
| **Logic** | Roteiam, limitam e removem duplicidades dos itens que fluem por ela. |
| **Findings** | Alteram os Achados. |
| **Egress** | Enviam algo para fora: um chamado, uma mensagem, um relatório. |

A paleta é gerada a partir do próprio mecanismo, portanto o que você vê no editor é sempre exatamente o que o mecanismo consegue executar.

### Regras do grafo

Um grafo é verificado quando você o salva, e novamente antes de cada execução. Ele deve satisfazer todas as condições a seguir:

* Tem pelo menos um nó.
* Tem **exatamente um** nó de gatilho.
* Cada nó tem um id único e não vazio de até 100 caracteres.
* Cada nó é de um tipo conhecido pelo mecanismo.
* Cada aresta conecta dois nós que existem.
* Não contém ciclos.

Um nó sem nada conectado a ele é válido. Ele é executado com uma lista de entrada vazia, o que geralmente significa que não faz nada.

Um nó com várias arestas de entrada recebe todas as saídas delas concatenadas.

### Pré-visualizando antes de salvar

O **Preview** executa a seco (dry-run) o grafo que você tem atualmente na tela e mostra o rastreamento por nó que ele produziria: quantos itens entraram em cada nó, quantos saíram por cada saída, e o que cada nó teria alterado.

O Preview executa o mecanismo real, não uma simulação dele, e depois desfaz tudo. Nada é gravado, nenhuma execução é registrada, e a saída (egress) é forçada a simular o que quer que o modo da regra determine. É a forma mais rápida de verificar se suas condições correspondem ao que você esperava.

O Preview é a única execução que limita quantos Achados ele examina, para permanecer rápido. Quando trunca, ele informa isso no rastreamento. Uma execução real não tem esse limite.

## Gatilhos e escopo

Todo grafo começa com um dos três gatilhos.

* **On Finding Event** ativa a regra quando Achados são criados, atualizados, fechados ou reabertos. Escolha qual desses eventos na configuração **Event** do nó, ou `any` para os quatro.
* **On a Schedule** varre os Achados em uma programação recorrente.
* **Manual Run** varre os Achados quando você pressiona **Run** na regra.

### Escopo

Os três gatilhos aceitam um **Scope**, e o escopo é a forma de restringir o que a regra considera. É o mesmo vocabulário de filtros usado pelo Rules Engine original, cerca de sessenta filtros que abrangem os Achados e os objetos ao seu redor, portanto um filtro que você já sabe escrever lá significa a mesma coisa aqui.

Duas coisas sobre o escopo valem a pena entender:

* **O escopo é aplicado por cima da autorização, nunca no lugar dela.** A regra é executada como seu proprietário, portanto o escopo restringe um conjunto de Achados já autorizado. Deixar o escopo vazio não significa "todo Achado na instância", significa "todo Achado que o proprietário da regra consegue ver".
* **Um escopo inválido faz a execução falhar, em vez de ampliá-la.** Se uma chave de filtro não existir, ou um valor for algo que o filtro descartaria silenciosamente, a execução termina com erro. Uma regra que não faz nada é recuperável. Uma regra que silenciosamente edita todo Achado na instância não é.

Para um gatilho de evento, o escopo funciona como um segundo portão: os Achados indicados no evento são comparados a ele, e somente os que passam entram no grafo.

### Agendamento

Uma regra cujo gatilho é **On a Schedule** é agendada a partir da própria regra. Definir a programação exige Rule Edit, a mesma permissão usada para editar a regra, porque uma regra disparada por agendamento não faz absolutamente nada até ter uma programação definida.

As programações se limitam a marcas de quinze em quinze minutos. O campo de minutos de uma expressão cron deve ser `0`, `15`, `30` ou `45`.

Exemplos válidos:

```
0 * * * *     every hour, on the hour
15 9 * * *    every day at 09:15
0 15 * * 1    every Monday at 15:00
30 2 * * *    every day at 02:30
```

## Referindo-se aos dados do Achado

Dois lugares em uma regra leem valores do item que passa por ela: **condições** e **modelos**. Ambos usam os mesmos caminhos com pontos (dot paths).

```
finding.severity
finding.title
finding.vulnerability_ids.0
product.name
product_type.name
test.scan_type
ctx.rule_name
```

Um caminho que não resolve produz nenhum valor, em vez de um erro.

### Campos disponíveis

Cada item carrega um conjunto fixo de campos do Achado. Esta lista é um contrato, portanto só muda de forma deliberada.

| Grupo | Campos |
|-------|--------|
| Identidade | `id`, `title`, `hash_code`, `unique_id_from_tool` |
| Severidade e pontuação | `severity`, `numerical_severity`, `cvssv3`, `cvssv3_score`, `epss_score`, `epss_percentile`, `priority`, `risk`, `risk_score` |
| Texto | `description`, `mitigation`, `impact` |
| Status | `active`, `verified`, `false_p`, `duplicate`, `is_mitigated`, `out_of_scope`, `risk_accepted`, `under_review` |
| Datas | `date`, `mitigated`, `last_status_update`, `sla_expiration_date` |
| Localização | `file_path`, `line`, `component_name`, `component_version`, `service` |
| Classificação | `cwe`, `vulnerability_ids`, `tags` |

Além de `finding`, cada item carrega `test` (`id`, `title`, `scan_type`), `engagement` (`id`, `name`), `product` (`id`, `name`), `product_type` (`id`, `name`), e `ctx`.

As datas são strings ISO-8601. Isso é proposital: significa que `gt` e `lt` as ordenam corretamente como texto, portanto `2026-07-28` é corretamente maior que `2026-01-01`.

`priority`, `risk` e `risk_score` vêm da priorização do Pro. Um Achado que ainda não foi pontuado não carrega valor para eles.

### Condições

Um nó **If / Filter** contém uma lista de linhas de condição. Cada linha é um caminho, um operador e um valor. **Match** decide se todas as linhas precisam ser verdadeiras (`all`) ou apenas uma delas (`any`).

| Operador | Significado |
|----------|---------|
| `eq` | igual a |
| `neq` | diferente de |
| `contains` | contém |
| `not_contains` | não contém |
| `in` | é um de |
| `not_in` | não é um de |
| `gt` | é maior que |
| `gte` | é maior ou igual a |
| `lt` | é menor que |
| `lte` | é menor ou igual a |
| `startswith` | começa com |
| `endswith` | termina com |
| `exists` | está definido |
| `not_exists` | não está definido |

As comparações são **flexíveis (loose)**. Primeiro tenta-se um número, e se isso falhar os valores são comparados como texto, sem espaços nas bordas e sem diferenciar maiúsculas de minúsculas. Assim, uma condição escrita como `finding.severity eq high` corresponde a um Achado cuja severidade é `High`, que é quase sempre o que o autor pretendia.

#### Transformações

Uma linha de condição pode pós-processar o valor lido antes de compará-lo.

| Transformação | Efeito |
|-----------|--------|
| `int` | número inteiro |
| `float` | número decimal |
| `str` | texto |
| `first` | primeiro item de uma lista |
| `list` | como lista |
| `join` | unido com vírgulas |
| `upper` | MAIÚSCULAS |
| `lower` | minúsculas |
| `strip` | sem espaços nas bordas |
| `cwe_int` | número do CWE |
| `severity` | severidade normalizada, de modo que valores como `critical`, `error` e `warning` vindos de diferentes scanners são mapeados para os cinco níveis do DefectDojo |
| `numerical_severity` | código de severidade ordenável, para comparações de ordenação |

### Modelos (Templates)

Qualquer configuração identificada como mensagem, nota, título ou valor aceita placeholders `{{ path }}`, resolvidos por item:

```
{{finding.severity}}: {{finding.title}} ({{product.name}})
```

Um caminho sem valor é renderizado como uma string vazia. Uma lista é renderizada unida por vírgulas.

Os modelos também enxergam um bloco `ctx` que carrega detalhes sobre a própria execução. As chaves disponíveis dependem do nó, mas as mais comuns são:

| Placeholder | Significado |
|-------------|---------|
| `{{ctx.rule_name}}` | O nome da regra |
| `{{ctx.count}}` | Quantos Achados a mensagem cobre |
| `{{ctx.trigger}}` | O evento que iniciou a execução |
| `{{ctx.findings_html}}` | A lista de Achados renderizada, no nó de e-mail |
| `{{ctx.report_url}}` | O link de download, no nó de relatório |
| `{{ctx.template_name}}` | O nome do modelo de relatório, no nó de relatório |

Os modelos fazem substituição simples. Não há avaliação de expressões, execução de código, nem acesso a atributos de objetos em nenhum lugar da configuração de uma regra.

## Testando uma regra com segurança

A ordem recomendada para uma regra que envia algo:

1. Construa o grafo e use o **Preview** até que a contagem de itens pareça correta.
2. Salve-a. Novas regras são criadas desativadas.
3. Deixe o modo em **Simulate** e ative a regra.
4. Deixe-a executar, depois leia **Deliveries** e verifique se as cargas (payloads) registradas são as que você pretendia.
5. Mude o modo para **Live**.

Simulate não é uma execução parcial. Toda edição de Achado no grafo acontece de verdade no modo de simulação. Somente os envios de saída são retidos.
