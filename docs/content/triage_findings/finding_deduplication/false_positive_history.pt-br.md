---
title: Histórico de Falsos Positivos
description: Marca automaticamente novos Achados como falso positivo quando um Achado
  correspondente já foi triado dessa forma
weight: 7
---

**O Histórico de Falsos Positivos** evita que sua equipe precise triar o mesmo falso positivo repetidamente. Quando habilitado e um Achado é importado, o DefectDojo procura Achados existentes no mesmo Produto que correspondam a ele e, se algum deles já estiver marcado como **Falso positivo**, o Achado recebido também é marcado como Falso positivo.

> **Esse recurso é marcado como EXPERIMENTAL no produto**, e **não pode ser usado ao mesmo tempo que a Deduplicação.** Leia [Quando você pode usá-lo](#when-you-can-use-it) antes de habilitá-lo.

## O que ele faz

Digamos que um scanner reporte um achado que sua equipe investiga e marca como falso positivo. A cada varredura posterior, esse mesmo achado volta a aparecer. Normalmente, alguém precisa descartá-lo toda vez. Com o Histórico de Falsos Positivos habilitado, o DefectDojo reconhece o achado recorrente e o marca como Falso positivo automaticamente.

Os Achados marcados dessa forma também são definidos como **inativos** e **não verificados**, não apenas como Falso positivo. Isso é intencional — o achado sai completamente da sua fila ativa — mas surpreende quem espera que apenas o sinalizador de Falso positivo mude.

A regra que o DefectDojo mantém é: *dentro de um Produto, se um Achado é falso positivo, todos os Achados correspondentes também são.*

### Modo retroativo

O **Histórico de Falsos Positivos Retroativo** aplica a mesma regra de forma retroativa. Quando você marca um Achado como falso positivo, todos os outros Achados **ativos** correspondentes naquele Produto também são marcados como Falso positivo.

Isso reescreve dados existentes. Não há pré-visualização nem confirmação — a mudança simplesmente acontece em todo o Produto. Habilite essa opção de forma deliberada.

## Quando você pode usá-lo

**O Histórico de Falsos Positivos e a Deduplicação são mutuamente exclusivos.** Os dois recursos resolvem problemas sobrepostos, então o DefectDojo não permite que ambos sejam usados ao mesmo tempo: em Configurações do Sistema, habilitar um desativa (esmaece) o outro, e ativar a Deduplicação limpa as configurações do Histórico de Falsos Positivos.

Essa é a coisa mais importante a entender sobre esse recurso. A maioria das instâncias usa a Deduplicação e, para essas, o Histórico de Falsos Positivos não está disponível. Ele é destinado a instâncias que deliberadamente optaram por não deduplicar.

## Habilitando o recurso

Ambas as configurações ficam em **Configurações do Sistema**, no bloco de deduplicação, e ambas ficam **desativadas por padrão**:

| Configuração | O que faz |
| --- | --- |
| **Habilitar Histórico de Falsos Positivos** | Ativa o recurso para a instância. |
| **Habilitar Histórico de Falsos Positivos Retroativo** | Também aplica a regra de forma retroativa, conforme descrito acima. Requer a configuração acima. |

Essas configurações são **em nível de instância**. Não há substituição por Produto ou por Ferramenta — habilitar isso afeta todos os Produtos da instância.

## O que conta como correspondência

O Histórico de Falsos Positivos decide se dois Achados são "o mesmo" usando **o algoritmo de deduplicação configurado para a ferramenta que os reportou** — mesmo que o próprio recurso de Deduplicação precise estar desativado.

| Algoritmo de deduplicação da ferramenta | Os achados correspondem quando compartilham |
| --- | --- |
| **Hash Code** | o mesmo código de hash, construído a partir dos Hash Code Fields configurados para essa ferramenta |
| **Unique ID From Tool** | o mesmo ID exclusivo da ferramenta |
| **Unique ID From Tool or Hash Code** | qualquer um dos dois |
| **Legacy** | o mesmo título (sem diferenciar maiúsculas/minúsculas) e a mesma severidade |

Portanto, a precisão desse recurso depende inteiramente de quão bem a deduplicação dessa ferramenta está configurada. **Ajuste o algoritmo e os campos de hash da ferramenta antes de habilitar o Histórico de Falsos Positivos** — consulte [Ajuste fino da deduplicação](/triage_findings/finding_deduplication/pro__deduplication_tuning/) (Pro) ou [Ajuste fino da deduplicação](/triage_findings/finding_deduplication/os__deduplication_tuning/) (Open Source).

A correspondência tem escopo **dentro de um Produto**. Ela nunca se estende entre Produtos, nem se aplica em nível de instância.

### Correspondência baseada em conjuntos (Pro)

No DefectDojo Pro, a correspondência também respeita os **Hash Code Fields baseados em conjuntos** — os matchers de ID de vulnerabilidade e CWE (`vulnerability_ids_partial`, `vulnerability_ids_subset`, `cwes_partial`, `cwes_subset`, e suas formas de correspondência exata), com o mesmo significado que têm na deduplicação.

Isso torna a correspondência do Pro **mais restrita** do que a do Open Source, e esse é o objetivo: sem isso, o Histórico de Falsos Positivos poderia replicar um falso positivo para Achados que a deduplicação por mesma ferramenta nem sequer consideraria duplicados. Esse refinamento só pode reduzir o conjunto de Achados marcados — usar o Pro nunca fará com que *mais* Achados sejam marcados automaticamente.

No Open Source, a correspondência usa apenas o código de hash, portanto é mais ampla. Tenha isso em mente ao fazer o ajuste fino.

## Riscos que vale a pena entender antes de habilitar o recurso

Esse recurso marca Achados como falso positivo sem que um humano os analise. Seu raio de impacto é definido pela sua configuração de deduplicação, portanto uma configuração frouxa é perigosa.

* **Uma chave de correspondência frouxa pode descartar Achados não relacionados silenciosamente.** O algoritmo **Legacy** faz a correspondência com base apenas em título e severidade — então uma única marcação de falso positivo poderia marcar todo Achado com o mesmo título e a mesma severidade no Produto como falso positivo, incluindo os genuínos. O mesmo se aplica a um conjunto de Hash Code Fields excessivamente amplo. Ajuste o algoritmo antes de habilitar o recurso.
* **O modo retroativo reescreve Achados existentes** sem pré-visualização, sem confirmação e sem um resumo do que foi alterado.
* **Os Achados são desativados e não verificados**, não apenas sinalizados.
* **A atualização em massa ignora o processamento normal que ocorre ao salvar**, portanto automações que reagem a atualizações de Achados podem não ser acionadas para Achados alterados dessa forma.
* **Ainda é rotulado como EXPERIMENTAL** no próprio DefectDojo.

Um padrão mais seguro para a maioria das equipes é manter a Deduplicação habilitada e deixar que os duplicados herdem o status do Achado original, em vez de migrar para o Histórico de Falsos Positivos. Consulte [Sobre a Deduplicação](/triage_findings/finding_deduplication/about_deduplication/).
