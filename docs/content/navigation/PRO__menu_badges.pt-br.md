---
title: Selos do Menu
description: O que significam as etiquetas BETA, NEW, LEGACY e DEPRECATED na barra
  lateral do DefectDojo Pro, e o que cada uma pede que você faça
weight: 7
audience: pro
---

As entradas na barra lateral do DefectDojo Pro podem exibir uma pequena etiqueta colorida. Cada uma responde a uma pergunta diferente sobre o recurso ao lado do qual ela aparece, e duas delas são links.

| Selo | Cor | Significa | O que pede de você |
| --- | --- | --- | --- |
| `NEW` | Verde | Lançado recentemente | Nada — está ali apenas para que você perceba o recurso |
| `BETA` | Laranja | Funcional, mas ainda em finalização; o comportamento pode mudar entre versões | Experimente, e espere algumas arestas por lapidar |
| `LEGACY` | Vermelho | Substituído por um recurso mais novo, sem data de remoção anunciada | Prefira o substituto para novos trabalhos |
| `DEPRECATED` | Vermelho | Programado para remoção em uma versão nomeada | Migre antes dessa versão |

![O selo LEGACY na entrada de menu do Jira](images/menu_badge_legacy.png)

## LEGACY e DEPRECATED não são a mesma coisa

A distinção é proposital, porque os dois estados pedem respostas diferentes.

**`DEPRECATED`** significa que uma remoção foi anunciada. Passar o mouse sobre o selo informa em qual versão o recurso será removido, e clicar nele abre o aviso de descontinuação:

> \<Feature\> is deprecated and will be removed by \<release\>. Click for the deprecation notice.

**`LEGACY`** significa que o recurso foi substituído, mas nenhuma remoção foi programada. Deliberadamente não há data no texto exibido ao passar o mouse, porque inventar uma seria pior do que não dizer nada. Em vez disso, ele nomeia o substituto e aponta para a documentação correspondente:

> \<Feature\> is superseded by \<replacement\> and will not receive new development. Click for its documentation.

Um recurso `LEGACY` continua funcionando e continua recebendo correções. Ele apenas não ganhará novas capacidades, portanto qualquer coisa que você construir agora é melhor construída sobre o substituto.

Ambos os selos são links, porque uma dica (tooltip) desaparece no momento em que o cursor a deixa e, portanto, não pode conter um link clicável. Clicar em qualquer um dos selos abre seu aviso em uma nova aba; isso não navega para a entrada de menu abaixo dele.

## O que atualmente possui um selo

**`LEGACY`**

* **Connect > Jira** — a integração original com o Jira por produto, substituída pelo conector downstream para o Jira. Veja [Integrações Pro](/connectors/downstream/about/).

**`DEPRECATED`**

* **Settings > Configuration > Tool Types**
* **Settings > Configuration > Tool Configurations**

Ambos serão removidos na versão **3.5.0**, junto com os parsers baseados em API (pull) que existem para configurá-los. As [notas de atualização da 3.2](/releases/os_upgrading/3.2/) explicam para o que migrar e até quando.

![Selos DEPRECATED em Settings > Configuration](images/menu_badge_deprecated.png)

Quando o rótulo e seu selo não cabem lado a lado na barra lateral, o selo quebra para sua própria linha abaixo do rótulo, em vez de ser truncado.

## Relacionados

* [Notas de atualização da 3.2](/releases/os_upgrading/3.2/) — as descontinuações atuais e a versão em que serão removidas
* [Feature Flags](/admin/feature_flags/pro__feature_flags/) — ativando e desativando recursos opcionais, incluindo os em beta
