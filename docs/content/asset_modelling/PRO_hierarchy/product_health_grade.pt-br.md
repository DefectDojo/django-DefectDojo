---
title: Nota de Integridade do Produto
description: Como o DefectDojo calcula a Nota de Integridade do Produto
aliases:
- /pt-br/en/working_with_findings/organizing_engagements_tests/product_health_grade
---

O DefectDojo pode calcular uma nota para seus Produtos com base na quantidade de Achados neles contidos. As notas variam de A a F.

Observe que apenas Achados Ativos e Verificados contribuem para a Nota do Produto - Achados não verificados não têm impacto.

## Cálculo da Nota do Produto

Toda Nota de Produto começa em 100 (sem Achados).

O cálculo da nota começa observando o nível de **Severidade** mais alto de um Achado em um Produto, reduzindo a Integridade do Produto a um nível base.

| **Nível de Severidade Mais Alto de um Achado** | **Nota Máxima** |
| --- | --- |
| **Crítica** | **40** |
| **Alto** | **60** |
| **Médio** | **80** |
| **Baixo** | **95** |

Em seguida, mais pontos são deduzidos da Nota para cada Achado adicional:

| **Nível de Severidade de um Achado adicional** | **Redução na Nota** |
| --- | --- |
| **Crítica** | **5** |
| **Alto** | **3** |
| **Médio** | **2** |
| **Baixo** | **1** |
