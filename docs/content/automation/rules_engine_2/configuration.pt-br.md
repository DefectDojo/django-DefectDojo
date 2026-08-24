---
title: Configuração
description: Configurações em nível de implantação para o Rules Engine 2.0
weight: 7
audience: pro
aliases:
- /pt-br/automation/rules_engine_v2/configuration/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: O Rules Engine 2.0 é um recurso exclusivo do DefectDojo Pro.</span>

O Rules Engine 2.0 funciona pronto para uso. As configurações desta página são para implantações que precisam ajustar throughput, retenção ou a política de rede de saída. Todas elas são aplicadas da mesma forma que qualquer outra configuração do DefectDojo (veja [Configuration](/get_started/open_source/configuration/)).

O Rules Engine 2.0 é configurado separadamente do Rules Engine original. Os dois mecanismos não compartilham nenhum ajuste, portanto uma configuração `DD_RULES_ENGINE_*` não afeta o Rules Engine 2.0, e uma configuração `DD_RULES_V2_*` não afeta o mecanismo original.

```python
DD_RULES_V2_EVENT_BATCH=(int, 500),
DD_RULES_V2_CHUNK_SIZE=(int, 1000),
DD_RULES_V2_STALLED_AFTER_MINUTES=(int, 30),
DD_RULES_V2_RUN_TIME_LIMIT_MINUTES=(int, 360),
DD_RULES_V2_ALLOW_PRIVATE_EGRESS=(bool, False),
DD_RULES_V2_DELIVERY_RETENTION_DAYS=(int, 180),
DD_RULES_V2_RUN_RETENTION_DAYS=(int, 180),
DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS=(int, 8000),
DD_RULES_V2_MAX_PER_ITEM_SENDS=(int, 1000),
```

## Throughput

### Achados por evento (`DD_RULES_V2_EVENT_BATCH`)

**Padrão: 500.**

Quantos ids de Achado um único evento carrega. Os eventos atravessam uma fronteira assíncrona, portanto são mantidos pequenos o suficiente para continuar sendo uma mensagem barata. Uma gravação maior se espalha em vários eventos, cada um dos quais se torna sua própria execução.

Aumentar esse valor produz execuções mais raras e maiores. Diminuí-lo produz execuções mais frequentes e menores.

### Achados por bloco (`DD_RULES_V2_CHUNK_SIZE`)

**Padrão: 1000.**

Quantos Achados uma execução mantém na memória de uma vez. Uma execução é processada em blocos (chunks), portanto isso é um ajuste de memória e **não** um limite para o que uma regra processa: uma regra sempre processa tudo o que seu escopo corresponde.

Um envelope tem aproximadamente 2,7 KB por Achado, portanto o padrão ocupa alguns megabytes de cada vez. Aumentá-lo troca memória por menos idas e voltas. Diminuí-lo faz o oposto.

### Limite de texto do envelope (`DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS`)

**Padrão: 8000. Defina como 0 para desativar.**

Quantos caracteres de `description`, `mitigation` e `impact` um item carrega.

Esses três campos correspondem à maior parte do tamanho de um envelope. O limite existe para o caso incomum de um Achado com uma descrição muito grande, em que um bloco cheio deles seria muito maior do que o tamanho do bloco sugere. Ele é generoso o suficiente para que uma instância comum nunca perceba isso.

Observe que isso afeta o que condições e modelos conseguem ver. Uma condição que compara com o final de uma descrição muito longa não verá texto além do limite.

## Ciclo de vida da execução

### Janela de estagnação (`DD_RULES_V2_STALLED_AFTER_MINUTES`)

**Padrão: 30.**

Por quanto tempo uma execução pode ficar sem uma pulsação (heartbeat) antes de ser tratada como abandonada, marcada como com erro, e ter seu bloqueio por regra liberado.

Uma execução registra uma pulsação após cada bloco, portanto isso é medido a partir da última pulsação, e não do início. Uma varredura longa que ainda está progredindo nunca é confundida com um worker travado, o que é o que permite manter a janela curta.

### Limite de tempo de execução (`DD_RULES_V2_RUN_TIME_LIMIT_MINUTES`)

**Padrão: 360, que são seis horas.**

O tempo máximo que uma única execução pode levar antes de o worker encerrá-la.

Isso é uma proteção contra uma regra que nunca terminaria enquanto ocupa um slot de worker e o bloqueio de execução da sua regra. É deliberadamente generoso, porque uma varredura em blocos sobre um escopo muito grande é exatamente o tipo de carga de trabalho para o qual este mecanismo foi construído.

## Retenção

Duas tarefas limitam as três tabelas que este recurso faz crescer. Ambas usam **180 dias** por padrão, e ambas aceitam `0` para desativar completamente a limpeza (pruning).

A retenção é exposta no produto, em vez de ficar implícita: a API fornece tanto a janela quanto a data em que um determinado registro será excluído, e as páginas que mostram uma execução ou uma entrega informam isso em uma frase. A data é calculada no momento da leitura, portanto alterar a janela tem efeito imediato, em vez de se aplicar apenas a novos registros.

### `DD_RULES_V2_DELIVERY_RETENTION_DAYS`

**Padrão: 180.**

Por quantos dias uma entrega concluída é mantida.

Esta é a tabela que mais cresce no recurso. Um nó de saída por Achado grava até o equivalente a um bloco de linhas por execução, inclusive no modo Simulate. Aumente-a se precisar de uma trilha de auditoria de saída mais longa, e diminua-a se o volume for um problema.

### `DD_RULES_V2_RUN_RETENTION_DAYS`

**Padrão: 180.**

Por quantos dias uma execução concluída é mantida, junto com suas linhas por nó e sua proveniência de Achados.

O lado das execuções cresce mais rápido do que o das entregas, porque a proveniência é uma linha por Achado por nó de mutação por execução. Uma regra que roda de hora em hora sobre um escopo grande gera muito disso.

Uma execução que ainda contém entregas é mantida até que essas sejam removidas, portanto definir uma janela de execução mais curta do que a janela de entrega não deixa nada órfão.

## Validação de destino de saída

Duas configurações de nó recebem um destino como texto livre, em vez de a partir de um objeto configurado: a **URL** em Call a Webhook, e o **To** em Send an Email. Ambas são validadas quando a regra é salva.

Para URLs de webhook:

* Somente `http` e `https` são aceitos. Outros esquemas são rejeitados de imediato.
* A URL precisa ter um host.
* Por padrão, um host que resolve para um endereço loopback, link-local, privado, reservado ou multicast é rejeitado.

Para endereços de e-mail, um endereço vazio é rejeitado, assim como um que contenha uma quebra de linha, o que caracteriza injeção de cabeçalho.

O motivo dessa verificação de rede é que o worker que envia a requisição geralmente fica dentro do seu cluster e consegue alcançar uma parte muito maior da rede interna do que a pessoa que escreve a regra consegue. Sem essa verificação, uma URL em texto livre é um primitivo de falsificação de requisição: aponte-a para um serviço de metadados ou uma porta administrativa interna, e a resposta volta através do registro de entregas.

Isso é defesa em profundidade, e não o único controle. Rule Edit já está próxima de ser uma permissão administrativa de qualquer forma. Vale a pena tê-la para que o raio de alcance de uma função concedida em excesso não seja "ler qualquer endpoint HTTP interno", e para que um erro de digitação falhe no momento de salvar, com uma mensagem clara, em vez de no momento do envio, com um erro de conexão.

### Permitindo endereços privados (`DD_RULES_V2_ALLOW_PRIVATE_EGRESS`)

**Padrão: desativado.**

Desativa a verificação de endereço de rede, de modo que os webhooks possam enviar para endereços loopback, link-local e privados. A validação de esquema e formato continua se aplicando.

Ative isso se você realmente usa webhook para algo em um endereço privado, o que geralmente é o caso de um chat ou receptor de webhook auto-hospedado.

## Limite de envios por Achado

### `DD_RULES_V2_MAX_PER_ITEM_SENDS`

**Padrão: 1000. Defina como 0 para remover o limite.**

O número máximo de envios por Achado que um único nó de saída registrará em uma execução.

Um nó com **One Message per Finding** ativado produz uma linha de entrega e uma tarefa enfileirada por Achado. Como uma execução não tem limite de itens, uma regra com um escopo muito amplo e envio por Achado ativado significaria, de outra forma, um número ilimitado de ambos.

Após esse limite, o nó registra uma **omissão visível (visible skip)** informando quantos Achados não tiveram envio realizado. Isso não faz a execução falhar, nem para silenciosamente.

## Configurações relacionadas

Alguns nós do Rules Engine 2.0 usam a configuração de integração de todo o sistema, em vez da própria:

* **Send a Slack Message** usa o token do Slack do sistema, e recorre ao canal do Slack do sistema quando o nó não indica nenhum.
* **Send a Microsoft Teams Message** usa o webhook do Microsoft Teams das configurações do sistema.
* **Create a JIRA Issue** usa a configuração do JIRA do produto para o resumo, a descrição e a prioridade.
* **Raise an In-App Alert** respeita a própria configuração de notificação **Rules Engine Match** de cada destinatário.
