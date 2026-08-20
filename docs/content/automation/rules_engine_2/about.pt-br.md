---
title: Sobre o Rules Engine 2.0
description: O que é o Rules Engine 2.0, como ativá-lo e os conceitos em que se baseia
weight: 1
audience: pro
aliases:
- /pt-br/automation/rules_engine_v2/about/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: O Rules Engine 2.0 é um recurso exclusivo do DefectDojo Pro.</span>

Rules Engine 2.0 é um construtor visual de automação. Em vez de um filtro mais uma lista simples de ações, uma regra é um **grafo**: um nó de gatilho que decide quando a regra é ativada, e qualquer número de nós de lógica, de Achado e de saída (egress) conectados entre si para dizer o que acontece a seguir.

O Rules Engine 2.0 só pode ser acessado pela [Pro UI](/get_started/about/ui_pro_vs_os/).

## O que ele adiciona em relação ao Rules Engine

O [Rules Engine](/automation/rules_engine/about/) original aplica uma lista ordenada de ações a cada Achado que corresponde a um filtro. O Rules Engine 2.0 mantém essa capacidade e adiciona quatro coisas:

* **Ramificação (branching).** Um nó **If / Filter** encaminha os itens por um ramo verdadeiro e um ramo falso, de modo que uma única regra possa tratar Achados Críticos de forma diferente do restante sem precisar ser dividida em duas regras.
* **Saída (egress).** Uma regra pode sair do DefectDojo: abrir um chamado no JIRA ou em um sistema de tickets externo, publicar no Slack ou no Microsoft Teams, enviar um e-mail, chamar um webhook, disparar um alerta no aplicativo ou gerar um relatório.
* **Rastreabilidade.** Cada execução é registrada nó a nó como uma [Execução](../runs/), e cada envio de saída é registrado como uma [Entrega](../deliveries/) que informa exatamente o que foi enviado, para onde foi e como terminou.
* **Um modo de simulação.** Uma regra pode registrar exatamente o que enviaria sem enviar nada de fato, o que permite testá-la com segurança antes de deixá-la tocar o mundo externo.

Os dois mecanismos funcionam lado a lado. Ativar o Rules Engine 2.0 não desativa nem converte suas regras existentes, e há um [conversor](../converting_from_rules_engine/) para quando você quiser migrá-las.

## Ativando o Rules Engine 2.0

O Rules Engine 2.0 está em Beta e vem desativado por padrão. Um superusuário o ativa em **Settings > Feature Flags**, tanto em instâncias Cloud quanto On-Premise. Veja [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Assim que a flag é ativada, uma seção **Rules Engine 2.0** aparece na barra lateral com três páginas:

| Página | Para que serve |
|------|----------------|
| **All Rules** | A lista de regras. Crie, edite, ative, execute e exclua regras a partir daqui. |
| **Runs** | Cada execução, com seu rastreamento por nó. |
| **Deliveries** | O registro de tudo o que as regras enviaram para fora. |

### Permissões

O acesso é regido por duas permissões globais de função, compartilhadas com o Rules Engine original:

* **Rule View** é necessária para ver a seção na barra lateral e tudo o que está nela.
* **Rule Edit** é necessária para criar, alterar, executar, excluir, converter, assumir a propriedade e reproduzir.

Rule Edit está próxima de ser uma permissão administrativa. Um autor de regra pode alcançar qualquer Achado que o proprietário da regra consiga ver, e pode direcionar a saída para sistemas externos, portanto conceda-a com cautela.

## Os conceitos

### Regras e grafos

Uma regra é um nome, uma descrição, um proprietário, um modo, uma chave de ativação e um grafo. O grafo é um conjunto de **nós** e as **arestas** entre eles. Ele deve conter exatamente um nó de gatilho e não pode conter um ciclo. Tudo o mais fica a seu critério, inclusive deixar um nó desconectado, o que simplesmente significa que ele é executado sem nada para processar.

Novas regras são sempre criadas **desativadas**, portanto ativar uma é um ato deliberado.

### Itens

O que trafega pelas arestas de um grafo é um **item**: um snapshot em JSON de um Achado mais o contexto ao seu redor.

```json
{
  "finding":      { "id": 1234, "title": "...", "severity": "High", "...": "..." },
  "test":         { "id": 12, "title": "...", "scan_type": "..." },
  "engagement":   { "id": 5,  "name": "..." },
  "product":      { "id": 3,  "name": "..." },
  "product_type": { "id": 1,  "name": "..." },
  "ctx":          { "trigger": "finding.created", "depth": 0, "source": "app" }
}
```

As condições e os modelos de mensagem são escritos com base nos caminhos dessa estrutura, por exemplo `finding.severity` ou `product.name`. A lista completa de campos está em [Building Rules](../building_rules/).

### Proprietário

Toda regra é executada **como o seu proprietário**. Ela vê exatamente os Achados que esse usuário consegue ver, através da mesma autorização usada em todo o restante do produto. Duas consequências valem a pena conhecer:

* Restringir o acesso do proprietário de uma regra restringe a regra.
* Uma regra cujo proprietário teve a conta excluída fica sem proprietário, portanto não corresponde a nada e não faz nada. Atribua um novo proprietário, ou use **Take Ownership** na lista de regras, para trazê-la de volta.

### Modo: Simulate ou Live

O modo é definido por regra, não por nó.

* **Simulate** (o padrão) executa o grafo inteiro de verdade, incluindo toda edição de Achado, mas os nós de saída registram o que *teriam* enviado e param por aí. Nada sai do DefectDojo.
* **Live** realiza os envios de fato.

Os envios simulados ainda aparecem no registro de Deliveries, marcados como `simulated`, com sua carga (payload) completa. Essa é a forma pretendida de revisar uma regra antes de liberá-la.

O modo se aplica deliberadamente à regra inteira. Um grafo em que alguns envios são reais e outros não é mais difícil de entender do que duas regras separadas.

### Execuções (Runs)

Uma execução de uma regra é uma [Execução](../runs/). Uma execução registra o evento que a disparou, seu status, seu rastreamento por nó e qualquer erro. Uma regra só pode ter uma execução em andamento por vez, portanto uma regra ocupada entra em fila em vez de competir consigo mesma.

### Entregas (Deliveries)

Todo efeito colateral de saída é uma linha no registro de [Entregas](../deliveries/), gravada **antes** de qualquer chamada de rede acontecer. A linha contém a carga (payload), o destino resolvido, o status, o número de tentativas e o que quer que o destino tenha respondido. As omissões (skips) também são registradas, de modo que "a regra não fez nada" e "a regra não fez nada porque o Achado já tinha um chamado aberto" são situações distinguíveis.

### Proveniência

Toda alteração que uma regra faz em um Achado é atribuída de volta à regra, à execução e ao nó que a realizou. Essa linha do tempo fica visível no próprio Achado, de modo que você pode responder "por que esse Achado mudou?" sem precisar ler as definições das regras.

### Escala

Uma regra processa tudo o que seu escopo corresponde. Não há limite para quantos Achados uma execução processa: ela os percorre em blocos (chunks) para que o consumo de memória permaneça limitado, e não a cobertura. Somente o Preview impõe limites, e ele avisa quando o faz.

### Retenção

Execuções e entregas são mantidas por 180 dias por padrão, e depois são removidas. O produto mostra a janela e a data em que um determinado registro será excluído, em vez de deixar isso implícito, e ambas as janelas são configuráveis. Veja [Configuration](../configuration/#retention).

## Para onde ir a seguir

* [Building Rules](../building_rules/) aborda o editor, gatilhos, escopo, condições e modelos.
* [Node Reference](../node_reference/) documenta todos os 25 nós.
* [Runs](../runs/) aborda execução, rastreamentos, encadeamento (cascading) e limites.
* [Deliveries](../deliveries/) aborda canais, status, novas tentativas e reprodução (replay).
* [Converting from Rules Engine](../converting_from_rules_engine/) aborda a migração de regras existentes.
* [Configuration](../configuration/) aborda as configurações em nível de implantação.
