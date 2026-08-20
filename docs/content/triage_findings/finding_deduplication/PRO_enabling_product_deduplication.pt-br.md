---
title: Habilitando a Deduplicação
description: Como habilitar a Deduplicação no nível de Produto ou Engajamento
weight: 2
audience: pro
aliases:
- /pt-br/en/working_with_findings/finding_deduplication/enabling_product_deduplication
---

A Deduplicação pode ser aplicada em um nível abrangendo todo o Produto, ou restrita de forma mais específica a um único Engajamento.

## Deduplicação para Produtos

1. Navegue até a página System Settings: **Settings \> System \> ⚙️ System Settings** na barra lateral (**Settings \> Pro Settings \> System Settings** em instâncias que ainda usam o layout de menu anterior).

![imagem](images/enabling_product-level_deduplication.png)

2. O card **Deduplication and Finding Settings** fica no topo da página **System Settings**.

![imagem](images/enabling_product-level_deduplication_2.png)

### Enable Finding Deduplication

**Enable Finding Deduplication** ativa o Deduplication Algorithm para todos os achados. Uma vez ativado, a deduplicação é executada em cada importação subsequente — o DefectDojo compara os achados importados com os achados existentes no Produto de destino e marca duplicatas de acordo com sua configuração.

### Delete Duplicate Findings

**Delete Duplicate Findings**, combinado com o campo **Maximum Duplicates**, limita quantos achados duplicados o DefectDojo retém. Quando ativado, um job em segundo plano remove periodicamente o excesso de duplicatas, de modo que cada achado original mantenha no máximo a quantidade configurada em **Maximum Duplicates**. As duplicatas mais antigas são removidas primeiro.

## Deduplicação para Engajamentos

Em vez de deduplicar em todo um Produto, você pode restringir a deduplicação a um único Engajamento.

### Abrindo o formulário de Engagement

* **Para um novo Engajamento:** abra o submenu **📥 Engagements** na barra lateral e clique em **\+ New Engagement**.

![imagem](images/enabling_deduplication_within_an_engagement.png)

* **Para um Engajamento existente (a partir da página All Engagements):** abra o menu **⋮** do Engajamento e selecione **Edit Engagement**.

![imagem](images/enabling_deduplication_within_an_engagement_2.png)

* **Para um Engajamento existente (a partir da página do Engajamento):** abra o menu **⚙️ Gear** no canto superior direito da página e selecione **Edit Engagement**.

![imagem](images/enabling_deduplication_within_an_engagement_3.png)

### Preenchendo o formulário de Engagement

1. No formulário de Engajamento, localize a caixa de seleção ☐ **Isolate Deduplication from Other Engagements**. Ela aparece acima do painel **Optional Fields \+**.
2. Marque a caixa para restringir a deduplicação a este Engajamento.
3. Envie o formulário.

Quando essa opção está ativada, os achados deste Engajamento só serão deduplicados em relação a outros achados dentro do mesmo Engajamento. Achados em outros Engajamentos do mesmo Produto são ignorados pelo Deduplication Algorithm.

![imagem](images/enabling_deduplication_within_an_engagement_4.png)
