---
title: Entregas
description: O registro de tudo que as regras enviam para fora, e como funcionam as
  tentativas e a reprodução
weight: 5
audience: pro
aliases:
- /pt-br/automation/rules_engine_v2/deliveries/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: o Rules Engine 2.0 é um recurso exclusivo do DefectDojo Pro.</span>

Cada efeito colateral de saída produzido por uma regra é uma linha no registro de entregas. **Rules Engine 2.0 > Entregas** as lista.

A linha é gravada **antes** de qualquer chamada de rede acontecer, e contém exatamente o que seria, ou foi, enviado. É isso que torna a saída auditável, em vez de uma linha de log que você espera que alguém tenha guardado, e é por isso que **Simulate** não é um caminho de código separado: um envio simulado é a mesma linha com a etapa de despacho pulada.

## O que uma entrega registra

| Field | Meaning |
|-------|---------|
| **Run** e **Node** | Qual execução e qual nó de saída a produziu. |
| **Finding** | O Achado a que ela se refere, em um envio por Achado. Envios em lote registram o grupo em vez disso. |
| **Channel** | Que tipo de envio é. |
| **Target** | O destino resolvido: uma chave de projeto do JIRA, um canal, uma URL, um endereço. |
| **Title** | Uma descrição de uma linha do envio. |
| **Payload** | Exatamente o que seria, ou foi, enviado. |
| **Mode** | `simulate` ou `live`. |
| **Status** | Até onde a entrega chegou. |
| **Attempts** | Quantos envios já foram tentados, em relação ao máximo permitido. |
| **Last error** | Por que a última tentativa falhou, ou por que a entrega foi ignorada. |
| **Response** | O que o destino respondeu. |
| **External reference** e **URL** | A chave do chamado, o id da mensagem ou o caminho do arquivo que o destino retornou, e um link para ele quando existir. |

## Canais

| Canal | Produzido por |
|---------|-------------|
| **JIRA** | Criar uma Issue do JIRA |
| **Downstream connector** | Criar um Ticket Downstream |
| **Slack** | Enviar uma Mensagem no Slack, e anúncios de relatórios enviados ao Slack |
| **Microsoft Teams** | Enviar uma Mensagem no Microsoft Teams |
| **Email** | Enviar um E-mail, e anúncios de relatórios enviados por e-mail |
| **Webhook** | Chamar um Webhook |
| **Report** | Gerar um Relatório |
| **In-app alert** | Emitir um Alerta no Aplicativo |

## Status

| Status | Significado |
|--------|---------|
| `simulated` | A regra estava no modo Simulate. Nada foi enviado, e nada nunca será. |
| `skipped` | Algo já cobriu esse envio, ou o controle o recusou. O motivo está no campo de último erro. |
| `pending` | Registrada no modo Live, aguardando sua tarefa de entrega. |
| `dispatched` | Repassada ao serviço de integração, aguardando confirmação. |
| `sent` | Entrega confirmada. |
| `failed` | Rejeitada permanentemente, por exemplo um 4xx ou um erro do fornecedor. Pode ser reproduzida. |
| `dead` | Tentativas esgotadas, ou nenhuma confirmação jamais chegou. Pode ser reproduzida. |

Vale a pena examinar melhor o `skipped`. Entradas ignoradas são registradas em vez de silenciosas, porque "a regra não fez nada" e "a regra não fez nada porque este Achado já tinha um chamado" são respostas diferentes, e apenas uma delas é um problema.

Há três motivos comuns para uma entrada ser ignorada, e o campo de último erro sempre diz qual:

* **Idempotência.** Algo já cobriu esse envio.
* **O canal está desligado.** Uma regra com um nó do Slack em uma instância onde o Slack está desabilitado registra uma entrada ignorada explicando isso, em vez de falhar. Uma regra salva enquanto um canal estava ativo não deveria passar a apresentar erros quando alguém o desativa. Veja [disponibilidade do nó](../node_reference/#when-a-channel-is-unavailable).
* **O limite de envio por Achado foi atingido.** Um nó que envia uma mensagem por Achado para por padrão após 1.000 em uma única execução, e registra quantos Achados ficaram de fora do envio.

### Fidelidade do payload

O registro é honesto sobre o quão próximo o payload registrado está do corpo real transmitido, porque isso varia conforme o canal.

| Fidelity | Significado |
|----------|---------|
| `exact` | Equivalente byte a byte ao que foi enviado. |
| `rendered` | Renderizado pelos helpers reais, mas o controle no momento do envio ainda pode reduzi-lo. |
| `dojo request` | A requisição exata entregue ao serviço de integração. O payload específico do fornecedor é composto downstream. |
| `summary` | Uma descrição do envio em vez de uma reprodução dele. Um relatório gerado é o exemplo: o arquivo é construído a partir de dados ao vivo no momento do envio, então uma cópia armazenada dele estaria errada no instante em que qualquer coisa mudasse. |

## A proteção contra envio duplicado

Apenas uma entrega **ativa** pode existir por chave de idempotência, imposto no banco de dados em vez de por convenção. Ativa significa `pending`, `dispatched` ou `sent`.

Um segundo envio que colidiria com um ativo se torna uma linha `skipped` com seu motivo registrado. Nunca é um no-op silencioso, e nunca é um chamado duplicado.

Como as linhas `simulated`, `skipped`, `failed` e `dead` não mantêm nenhuma reserva, uma entrega com falha pode ser reproduzida no lugar sem que uma segunda linha dispute a mesma chave.

## Tentativas

Uma entrega ao vivo é repetida automaticamente. Cada linha carrega sua própria contagem de tentativas e seu próprio limite, seis tentativas por padrão, de modo que um destino com falha não consegue arrastar seus vizinhos junto. As repetições aguardam um intervalo crescente entre as tentativas.

Quando a última tentativa é consumida, a linha é marcada como `dead` em vez de ficar parada em `pending`. O esgotamento é visível, não silencioso.

Se um worker for encerrado no meio de um envio, a mensagem é reentregue. A linha é bloqueada e seu status é reverificado antes que qualquer coisa seja enviada novamente, de modo que uma reentrega não pode se tornar um envio duplicado.

Entregas repassadas ao serviço de integração passam para `dispatched` e aguardam um callback de confirmação. Se nenhum callback chegar em até seis horas, a linha é marcada como `dead` para que possa ser reproduzida. Essa janela é deliberadamente generosa: uma fila downstream congestionada por uma hora é normal, e marcar uma linha como morta cedo demais transformaria uma reprodução em um chamado duplicado.

## Reproduzindo uma entrega

Uma entrega `failed` ou `dead` pode ser reenviada a partir da página Entregas. O registro anota quando ela foi reproduzida e por quem.

Reproduzir exige **Rule Edit**.

Reproduzir reenvia o payload registrado. Para um relatório, isso regenera o relatório a partir dos dados atuais, porque o payload é uma descrição do que gerar, e não o arquivo em si.

## Simulate

No modo Simulate, cada nó de saída grava sua linha de entrega com status `simulated`, payload completo e destino resolvido, e então para. Nenhum despacho é registrado, então nada pode ser enviado depois, não importa como a execução termine. O Preview se comporta da mesma forma, e nem sequer insere as linhas.

Essa é a forma indicada de revisar uma regra antes de colocá-la em produção: ative-a em Simulate, deixe-a rodar contra Achados reais, e depois leia os payloads que ela registrou.

Lembre-se de que o Simulate contém **apenas** os envios de saída. Nós de Achados continuam alterando Achados.

## Retenção

As entregas são mantidas por **180 dias** por padrão, após os quais um job de retenção as remove.

Esta é a tabela que mais cresce no recurso, porque um nó que envia uma mensagem por Achado grava uma linha por Achado, tanto no modo Simulate quanto no Live. O padrão é uma janela real em vez de "guardar tudo", então o crescimento não vira seu problema silenciosamente.

Você é avisado sobre isso em vez de ser deixado para descobrir sozinho. O detalhe de uma entrega mostra a janela de retenção e a data em que aquela linha será excluída, e a data é recalculada a cada leitura, de modo que alterar a janela tem efeito imediato.

Defina a janela mais longa se precisar de uma trilha de auditoria de saída mais longa, ou `0` para manter tudo. Veja [Configuração](../configuration/#retention).
