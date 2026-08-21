---
title: Execuções
description: Como uma regra é executada, o que uma execução registra e como o encadeamento
  é limitado
weight: 4
audience: pro
aliases:
- /pt-br/automation/rules_engine_v2/runs/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Observação: o Rules Engine 2.0 é um recurso exclusivo do DefectDojo Pro.</span>

Um **run** (execução) é a execução de uma regra. Toda execução é registrada, tenha sido bem-sucedida ou não, e cada nó dentro dela deixa um rastro. **Rules Engine 2.0 > Runs** lista essas execuções.

## O que uma execução registra

| Campo | Significado |
|-------|---------|
| **Rule** | A regra que foi executada. |
| **Trigger** | O evento que iniciou a execução, por exemplo `finding.created`, `schedule` ou `manual`. |
| **Triggered by** | A pessoa que a disparou, quando uma pessoa esteve envolvida: quem clicou em Run, ou quem salvou o Finding que a disparou. Fica vazio para um agendamento, e para uma alteração em que ninguém esteve presente, como uma importação ou uma chamada de API sem usuário. Isso é diferente do proprietário da regra, que é quem a execução realmente executa **como**. |
| **Status** | `Running`, `Success` ou `Error`. |
| **Started** e **Finished** | Quando foi executada. Finished fica vazio apenas enquanto ela ainda está em execução. |
| **Error** | O erro que a encerrou, caso tenha falhado. |
| **Stats** | Totais por nó, eventos em cascata e trabalho adiado. |
| **Depth** | Quantos saltos de cascata esta execução está distante do evento que a originou. |
| **Source run** | A execução cujo evento emitido disparou esta, no caso de uma execução em cascata. |

### O rastro dos nós

Dentro de uma execução, cada nó registra sua própria linha:

| Campo | Significado |
|-------|---------|
| **Order** | Onde o nó se posicionou na ordem de execução. |
| **Node** | Seu id, seu tipo e seu rótulo, se você tiver definido um. |
| **Status** | Se o nó foi concluído ou gerou um erro. |
| **Items in** | Quantos itens entraram. |
| **Items out** | Quantos saíram, detalhados por handle de saída, de modo que um nó If / Filter mostra suas contagens de verdadeiro e falso separadamente. |
| **Summary** | Quaisquer contadores que o nó tenha reportado, por exemplo quantos Findings ele alterou. |
| **Error** | O erro gerado, caso tenha falhado. |

O rastro é o que você lê quando uma regra não fez o que você esperava. Um nó If / Filter reportando 400 itens de entrada e 0 no ramo verdadeiro informa que as condições estão erradas, sem que você precise adivinhar.

## Modelo de execução

Os nós são executados em ordem topológica: um nó é executado assim que tudo que o alimenta já foi executado. Um nó com várias arestas de entrada recebe todas as saídas delas concatenadas. Um nó sem nada o alimentando ainda é executado, com uma lista de entrada vazia.

### Uma execução com falha não altera nada

Uma execução é atômica. Se qualquer nó gerar um erro, toda alteração de Finding feita pela execução é revertida.

O rastro não é revertido junto. As linhas dos nós e o status `Error` são gravados depois, de modo que uma execução com falha mostra exatamente qual nó quebrou, sem deixar nenhuma edição parcialmente aplicada para trás. Esta é a garantia mais importante a se ter em mente ao ler a página Runs: uma execução com erro é uma execução que não fez nada.

A saída (egress) segue a mesma regra. As entregas são registradas dentro da transação da execução e só são despachadas depois que ela é confirmada (commit), de modo que uma execução revertida não envia nada.

### Uma execução por regra por vez

Uma regra só pode ter uma execução em andamento. Um segundo disparo para a mesma regra enquanto ela ainda está em execução não entra em disputa com ela. Ele aguarda e tenta novamente.

Regras diferentes são executadas totalmente em paralelo, de modo que uma regra lenta nunca atrasa suas irmãs.

Se uma execução for de alguma forma abandonada, por exemplo porque o worker que a executava foi encerrado, seu lock é liberado após uma janela de inatividade (30 minutos por padrão), de modo que a regra não fique travada para sempre. Uma execução próxima dessa janela se interrompe primeiro, revertendo tudo de forma limpa, de modo que uma execução apenas lenta nunca acaba sendo executada junto com sua própria substituta.

## Encadeamento (cascata)

Uma regra que altera um Finding produz exatamente o tipo de evento que outra regra pode usar como gatilho. O Rules Engine 2.0 permite isso, de modo que cadeias `A -> B -> C` funcionam, e as limita de duas formas independentes:

* **Depth (profundidade).** Um evento pode percorrer no máximo **3** saltos de cascata a partir da alteração que o originou.
* **Pertencimento à cadeia.** Todo evento carrega a lista de regras já percorridas em sua cadeia, e uma regra nunca é executada duas vezes na mesma cadeia. Assim, uma regra não pode disparar a si mesma novamente, e duas regras não podem ficar em ping-pong.

Os campos **Depth** e **Source run** de uma execução permitem rastrear uma cadeia até a alteração que a iniciou. **Triggered by** é propagado por toda a cadeia, de modo que uma cascata disparada por uma pessoa permanece atribuída a ela em cada salto.

Alterações feitas *por* uma regra em execução são atribuídas à própria cascata dessa regra, em vez de parecerem nova atividade do usuário, de modo que uma regra que delega trabalho internamente não infla a cadeia.

## Escala e limites

**Uma execução não tem limite superior de itens.** Uma regra processa tudo o que seu escopo corresponde, por maior que seja. Uma regra que parasse silenciosamente nos primeiros N Findings seria uma regra na qual você não poderia confiar.

Em vez disso, uma execução é processada em **blocos (chunks)**, 1.000 Findings por vez por padrão. Apenas o bloco fica em memória, de modo que uma varredura sobre um escopo muito grande é limitada em memória, não em cobertura. A única exceção é o **Preview**, que tem um limite, e informa isso em seu rastro quando trunca.

Outros dois números moldam como o trabalho é dividido:

* **Findings per event**, 500 por padrão. Uma alteração em massa é dividida em vários eventos, cada um se tornando sua própria execução. O efeito prático para uma importação grande é um número administrável de execuções, em vez de uma execução por Finding.
* **Per-Finding send ceiling**, 1.000 por padrão. Um nó de saída configurado para enviar uma mensagem por Finding para de enviar ao atingir esse número em uma única execução, e registra uma omissão visível informando sobre quantos não enviou. Isso limita as linhas de entrega e as tarefas enfileiradas, algo que uma execução em blocos não limita mais por si só.

Todos os três são configurações de implantação, documentadas em [Configuração](../configuration/).

### Quanto tempo uma execução pode levar

Uma execução registra um **heartbeat (pulsação)** após cada bloco. A detecção de travamento lê essa pulsação em vez do horário de início, de modo que uma varredura longa que ainda está progredindo nunca é confundida com um worker travado.

Duas janelas se aplicam, ambas configuráveis:

* Uma execução que fica 30 minutos sem pulsação é tratada como abandonada, marcada como erro, e seu lock é liberado.
* Uma execução é encerrada à força após seis horas, como proteção contra uma execução que nunca terminaria.

## Retenção

As execuções são mantidas por **180 dias** por padrão, junto com suas linhas por nó e sua proveniência de Finding. As entregas são mantidas por 180 dias separadamente.

O produto informa isso em vez de deixar implícito: o detalhe de uma execução mostra a janela de retenção e a data em que aquela execução será excluída. Uma execução que ainda contém entregas é mantida até que essas sejam removidas.

Ambas as janelas são configuráveis, e qualquer uma delas pode ser definida para manter os registros indefinidamente. Veja [Configuração](../configuration/#retention).

## Executando uma regra manualmente

Uma regra cujo gatilho é **Manual Run** é executada com a ação **Run** na lista de regras. Regras com outros gatilhos são executadas quando seu gatilho dispara.

**Preview**, no editor, é a outra forma de executar um grafo. Ele executa o mecanismo real e depois reverte tudo, não registra nenhuma execução, e força a saída (egress) a simular. Use o preview enquanto constrói, e as execuções para ver o que realmente aconteceu.

## Proveniência em um Achado

As execuções respondem "o que esta regra fez?". A proveniência responde à pergunta oposta: "por que este Finding mudou?".

Toda alteração feita por uma regra é registrada no Finding junto com a regra, a execução e o nó responsáveis, e aparece como uma linha do tempo no próprio Finding. As ações registradas são:

| Ação | Significado |
|--------|---------|
| `created`, `updated`, `closed`, `reopened` | O ciclo de vida do Finding mudou. |
| `duplicate`, `status_change` | Seus sinalizadores de duplicidade ou status mudaram. |
| `notified` | Uma notificação foi enviada sobre ele. |
| `delivered` | Uma entrega de saída o cobriu. |

Edições de campo registram o que mudou, incluindo o valor anterior e o valor posterior de cada campo. Valores muito longos são truncados no registro, de modo que a linha do tempo permanece um registro da alteração, e não uma segunda cópia do Finding.

Notificações e entregas também são registradas aqui. Isso é proposital: uma regra que enviou uma mensagem, mas não alterou nenhum campo, de outra forma não deixaria nenhum rastro no Finding.

A proveniência sobrevive à regra. Excluir uma regra ou uma execução mantém as entradas da linha do tempo e simplesmente as desvincula, de modo que o histórico não desaparece quando alguém faz uma limpeza.

## Excluindo regras com histórico

Uma regra que produziu entregas não pode ser excluída enquanto elas existirem. Exclua as entregas primeiro, ou mantenha a regra e a desative. Isso é intencional: as entregas guardam o registro do que foi realmente enviado para sistemas externos, e uma exclusão em cascata levaria consigo envios em andamento.
