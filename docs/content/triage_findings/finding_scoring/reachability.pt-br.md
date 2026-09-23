---
title: Reachability
description: Como o DefectDojo Pro registra se o código vulnerável de um Achado é
  de fato alcançável, e como esse veredito ajusta a prioridade
audience: pro
weight: 3
---

Um CVE Crítico em um código que sua aplicação nunca chama não representa o mesmo
risco que o mesmo CVE em um caminho de requisição ativo. O **Reachability** captura
essa diferença: o DefectDojo Pro registra se o código vulnerável de cada Achado
pode de fato ser alcançado, mostra de onde veio essa conclusão, e a incorpora na
**prioridade** calculada do Achado.

O Reachability é um recurso em **beta** e vem **desativado por padrão**. Um
superusuário o habilita em **Settings > Feature Flags**. Enquanto estiver
desativado, nenhum veredito é registrado, a prioridade não é afetada, e nenhuma
interface de Reachability aparece.

## Vereditos

Todo veredito é normalizado para os mesmos cinco valores, qualquer que seja sua origem:

| Verdict | Meaning |
|---|---|
| **Reachable (runtime)** | O código vulnerável foi observado em execução. |
| **Reachable (static)** | Existe um caminho de chamada até o código vulnerável a partir de um ponto de entrada da aplicação. |
| **Potentially reachable** | Evidência parcial — por exemplo, o pacote vulnerável é utilizado, mas a função específica não pôde ser confirmada. |
| **Unreachable** | A análise não encontrou nenhum caminho até o código vulnerável. |
| **Unknown** | Nenhuma análise de reachability ainda cobre este Achado. |

Essa normalização importa porque as ferramentas divergem na terminologia: o
"nenhum caminho encontrado" de um scanner e o "não utilizado" de outro
significam coisas diferentes, e o DefectDojo registra ambos como vereditos
comparáveis, em vez de reduzi-los a um simples sim/não.

## As regras que o Reachability segue

Esses comportamentos são intencionais e não mudam de uma ferramenta para outra:

- **Unknown nunca conta contra um Achado.** A maioria das instâncias começa
  com pouca ou nenhuma cobertura de reachability. Um Achado que nada analisou
  é pontuado exatamente como seria com o recurso desativado.
- **Unreachable reduz a prioridade. Nunca fecha um Achado.** Um veredito
  "unreachable" reduz a pontuação para que problemas genuinamente ativos
  apareçam acima dele na ordenação, mas o Achado permanece aberto e visível.
  A análise de reachability não é perfeita, e um "unreachable" incorreto que
  escondesse silenciosamente um Crítico ativo seria a pior falha possível.
- **Todo veredito mostra sua origem.** Nenhum veredito aparece sem a
  ferramenta que o produziu, sua confiança e, quando conhecido, o commit que
  foi analisado.
- **Os vereditos seguem a deduplicação.** Quando vários scanners relatam a
  mesma vulnerabilidade e apenas um deles relata reachability, o veredito se
  aplica a todo o cluster de duplicatas, então você não perde o sinal ao
  importar outra ferramenta.

## De onde vêm os vereditos

Você não precisa adotar um novo scanner para obter valor aqui — o DefectDojo
lê o reachability que ferramentas que você já pode estar usando estão
produzindo:

- **Scanners que relatam isso na saída.** Vários parsers suportados carregam
  reachability, seja como dado estruturado ou no texto do relatório. Nenhuma
  configuração é necessária além de importar o relatório normalmente.
- **Conectores.** Um conector que suporta reachability envia vereditos para
  os produtos que sincroniza, atualizados em sua programação normal.

A cobertura normalmente é parcial, e isso é esperado. Ferramentas que não
relatam reachability simplesmente deixam seus Achados como **Unknown**.

## Como o Reachability altera a prioridade

O Reachability é mais uma entrada para a pontuação de prioridade descrita em
[Scoring & Prioritization](../). Vereditos Reachable aumentam a prioridade de
um Achado, Unreachable a reduz proporcionalmente à confiança da fonte, e
Unknown a deixa inalterada.

A intensidade desse ajuste é configurável por mecanismo de priorização, como
qualquer outro fator: defina o escalar de reachability como `0` para
registrar vereditos sem deixar que eles movam as pontuações, ou aumente-o
para dar mais peso ao reachability. Você pode pré-visualizar o efeito com o
simulador de priorização antes de aplicá-lo.

Como habilitar o Reachability desloca as pontuações, revise os limiares de
risco do seu mecanismo depois de ativá-lo, para que os Achados caiam nas
faixas esperadas.

### Regras de risco do Reachability

Esse ajuste é proporcional à severidade de um Achado, o que significa que ele
não consegue expressar duas coisas que você pode querer. Um Achado de
severidade Baixa cujo código é confirmadamente reachable ainda recebe apenas
um pequeno acréscimo e permanece em uma faixa baixa; um Crítico relatado como
unreachable ainda pode permanecer no topo da fila. Duas regras opcionais no
mecanismo de priorização definem uma faixa diretamente, em vez disso:

- **Reachable risk floor** — a faixa de Risco mínima para Achados cujo código
  vulnerável é confirmadamente reachable. Ela só eleva uma faixa, nunca a
  reduz.
- **Unreachable risk ceiling** — a faixa de Risco máxima para Achados
  relatados como unreachable. Ela só reduz uma faixa, nunca a eleva, e nunca
  fecha ou oculta um Achado; apenas limita onde ele é ordenado.

Ambas ficam vazias por padrão, então nada muda até que você as defina. O teto
também tem uma **confiança mínima**: ele só se aplica quando o veredito
unreachable tem, no mínimo, esse nível de confiança, porque limitar uma faixa
com base em um veredito de baixa confiança é exatamente como um Crítico
ativo acaba sendo enterrado.

Um Achado cujo CVE é relatado como ativamente explorado em ambiente real
nunca é limitado pelo teto — evidência de exploração tem precedência sobre
uma alegação de ausência de caminho.

## O que você vê

**No Achado** — um selo de reachability, e um painel **Reachability Sources**
listando cada fonte que relatou sobre ele, o veredito e a confiança de cada
fonte, e qual delas se aplica atualmente. Quando uma ferramenta fornece um
caminho de chamada, a evidência de suporte é exibida junto.

**Na lista de Achados** — uma coluna e um filtro de Reachability, permitindo
montar visualizações como "Crítico e reachable" e salvá-las.

**Em um ativo** — um painel **Reachability Coverage** mostrando a
distribuição de vereditos para aquele ativo, quantos de seus Achados carregam
algum veredito e quantos Críticos o reachability rebaixou ou confirmou. Cada
número leva aos Achados correspondentes. A parcela ainda em Unknown é exibida
junto com o restante: ela indica sobre quanto do ativo o reachability
consegue, no momento, se pronunciar.
