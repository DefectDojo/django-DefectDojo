---
title: Migrando do Rules Engine
description: Migre regras existentes do Rules Engine para grafos do Rules Engine 2.0
weight: 6
audience: pro
aliases:
- /pt-br/automation/rules_engine_v2/converting_from_rules_engine/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: O Rules Engine 2.0 é um recurso exclusivo do DefectDojo Pro.</span>

Os dois mecanismos funcionam lado a lado. Ativar o Rules Engine 2.0 não muda nada em suas regras existentes do [Rules Engine](/automation/rules_engine/about/), e não há um prazo até o qual você precise migrá-las.

Quando você quiser migrá-las, existe um conversor. Ele traduz uma regra do Rules Engine (um filtro mais uma lista ordenada de ações) em um grafo equivalente do Rules Engine 2.0.

## O que o conversor garante

**Uma regra é convertida por completo ou não é convertida de forma alguma.** Toda conversão relata dois tipos de resultado:

* **Problems** significam que a regra não foi escrita. Nada parcial é salvo.
* **Warnings** significam que a regra foi convertida, mas algo nela mudou e você deveria dar uma olhada.

Nada é aproximado silenciosamente. Todo o valor do conversor está em você poder confiar em uma regra que converteu sem ressalvas, e verificar manualmente uma que não converteu.

**Regras convertidas são sempre criadas desativadas.** Os dois mecanismos estão em execução, e duas regras fazendo a mesma coisa com os mesmos Achados é o único resultado que um conversor nunca deve produzir por conta própria. Revise cada regra convertida e ative-a deliberadamente.

**Uma regra converte uma única vez.** Cada regra convertida lembra de qual regra ela veio, portanto executar o conversor duas vezes ignora o que já foi feito, em vez de criar duplicatas. Use a opção de sobrescrever para substituir deliberadamente um grafo convertido anteriormente.

## Executando o conversor

### Pela interface (UI)

A lista de regras oferece uma ação de conversão, que informa, por regra, o que foi convertido, o que foi ignorado e o que falhou.

### Pela linha de comando

```bash
python manage.py convert_rules_to_v2
```

| Opção | Efeito |
|--------|--------|
| `--dry-run` | Imprime o grafo que cada regra produziria e não grava nada. |
| `--rule-ids 1,2,3` | Converte somente essas regras. Converte todas as regras quando omitido. |
| `--overwrite` | Substitui o grafo de uma regra já convertida e incrementa sua versão, em vez de ignorá-la. |
| `--activate-schedules` | Também copia cada programação para a sua regra convertida. Desativado por padrão. |
| `--drop-invalid-filters` | Descarta os filtros de escopo que o conjunto de filtros não reconhece mais e emite um aviso, em vez de falhar a regra. |
| `--json` | Imprime o relatório em JSON em vez de texto. |

O comando termina com código diferente de zero somente quando uma regra falha ao converter. Itens ignorados são relatados, mas não são falhas.

Comece com `--dry-run` no conjunto completo para ver no que você está se metendo, depois converta de verdade.

## O que a conversão produz

| Conceito do Rules Engine | Torna-se |
|----------------------|---------|
| O filtro da regra | O **Scope** no nó de gatilho. |
| Uma regra com uma programação | Um gatilho **On a Schedule**. |
| Uma regra sem programação | Um gatilho **Manual Run**. |
| Cada ação, em ordem | Um nó, encadeado na mesma ordem. |
| Uma ação protegida por uma condição | Um nó **If / Filter** na frente desse nó. |

O vocabulário de filtros é compartilhado entre os dois mecanismos, portanto um escopo é convertido sem tradução. Isso é proposital: é o mesmo conjunto de filtros, com uma única implementação.

Os grafos convertidos são validados da mesma forma que um grafo construído manualmente, incluindo a configuração por nó e os valores permitidos de cada menu suspenso. Uma regra que contém um valor de severidade ou de risco que o produto já deixou de usar é detectada na conversão, e não em tempo de execução.

## O que não é migrado

Quatro coisas para planejar. O conversor relata essas informações como notas em cada execução.

* **O histórico de execuções permanece onde está.** O histórico de execuções existente, junto com seus registros afetados e ignorados, permanece na interface do Rules Engine. Eles não são copiados.
* **As programações não são ativadas por padrão.** Uma regra disparada por agendamento é convertida, mas sua programação não é copiada a menos que você passe `--activate-schedules`. Isso mantém a propriedade exclusiva das programações ativas com o mecanismo original enquanto os dois estão em execução, de modo que uma regra convertida não pode começar a disparar sem você perceber. Quando você copia uma programação, a cópia recebe um nome distinto para não colidir com a original.
* **O modelo de concorrência é diferente.** O Rules Engine tem um único bloqueio de execução para toda a instância. O Rules Engine 2.0 serializa por regra, portanto regras distintas são executadas simultaneamente. Um conjunto de regras que costumava se revezar agora vai se sobrepor.
* **Uma ação não tem equivalente.** Uma ação de "definir falso positivo como falso" não pode ser expressa como um nó do Rules Engine 2.0 e precisa ser convertida manualmente.

Uma regra cujo proprietário não está definido é convertida, com um aviso. Lembre-se de que uma regra sem proprietário não vê nenhum Achado, portanto atribua um antes de ativá-la.

## Uma ordem sugerida

1. Ative o Rules Engine 2.0 e deixe suas regras existentes em execução.
2. Execute o conversor com `--dry-run` e leia o relatório.
3. Converta. Tudo é criado desativado.
4. Abra cada regra convertida, verifique o grafo e deixe o modo em **Simulate**.
5. Ative a regra convertida e deixe-a rodar ao lado da original por um tempo. Simulate significa que ela altera Achados, mas não envia nada, portanto compare suas execuções com o que a original fez.
6. Quando estiver satisfeito, desative a regra original e mude a convertida para **Live**.
7. Copie a programação por último, quando nada mais estiver executando a regra antiga.

O passo 5 é o que mais vale a pena não pular. Os dois mecanismos editando os mesmos Achados é algo tranquilo de observar, mas você quer ser quem decide quando os envios começam.
