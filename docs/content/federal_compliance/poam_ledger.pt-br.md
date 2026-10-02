---
title: O Registro de POA&M
description: Como os itens de POA&M são criados a partir dos achados, e as convenções
  que o registro segue
weight: 2
audience: pro
---

Os itens de POA&M são criados e atualizados automaticamente a partir dos achados. A sincronização roda logo após importações e mudanças em achados, e uma varredura noturna captura qualquer coisa que tenha escapado. Você também pode adicionar itens manualmente, para fraquezas que nenhum scanner reporta.

![O registro de POA&M](images/02-poam-items.png)

## Convenções do registro

O registro segue as convenções do FedRAMP:

* **Numeração estável.** Todo item mantém um número de sequência dentro do seu sistema, e os números nunca são reutilizados.
* **Achados agrupados são consolidados.** O mesmo CVE em vários hosts vira um único item, com cada asset afetado listado nele.
* **Achados de configuração podem se consolidar sob CM-6**, em vez de inundar o registro com um item por regra de benchmark. Na captura de tela acima, `V-4` é esse item consolidado.
* **Itens fechados nunca reabrem.** Se a mesma fraqueza retornar, o registro abre um novo item que referencia o antigo, então seu histórico de remediação permanece intacto.

## Editando um item

O lápis em qualquer linha abre o item para edição.

![Editando um item de POA&M](images/03-poam-item-detail.png)

A partir daqui você define o ponto de contato, os recursos necessários e o plano de remediação, e registra qualquer desvio.

### Desvios

Os desvios são rastreados como três estados separados em cada item:

| Desvio | Valores |
| --- | --- |
| Falso positivo | Não, Pendente ou Sim |
| Ajuste de Risco | Não, Pendente ou Sim |
| Requisito Operacional | Não, Pendente ou Sim |

Cada um carrega uma **Deviation Rationale** compartilhada. Um ajuste de risco também registra o **Adjusted Risk Rating** ao lado do original, e ambos aparecem nos entregáveis gerados.

### Dependências de fornecedor

Os itens podem carregar um sinalizador **Vendor Dependency** e o nome **Vendor Product**, para fraquezas que você não pode remediar diretamente. A data do seu último contato com o fornecedor é rastreada junto com o item.

## Rastreamento de KEV

Itens vinculados a uma Vulnerabilidade Conhecida Explorada (KEV) da CISA carregam a data de vencimento do KEV. Essa data também limita o prazo de remediação — veja [Prazos de Remediação](../remediation_slas).

## Marcos

Os marcos carregam uma descrição com datas programadas e concluídas, e aparecem tanto na saída Excel quanto na OSCAL. Eles são gerenciados através da API de compliance, e não no formulário do item.

## Adicionando um item manualmente

Adicione um item para uma fraqueza que nenhum scanner reporta. Itens criados manualmente se comportam como os sincronizados: eles recebem o próximo número de sequência, aceitam desvios e marcos, e aparecem no próximo snapshot.

## Auditabilidade

Itens de POA&M, marcos e desvios ficam todos sob o histórico de auditoria. Cada mudança registra quem, o quê e quando.
