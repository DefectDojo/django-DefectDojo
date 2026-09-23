---
title: Nota de Integridade do Ativo
description: Como o DefectDojo calcula a Nota de Integridade do Ativo
weight: 7
audience: opensource
aliases:
- /pt-br/asset_modelling/os_hierarchy/product_health_grade/
- /pt-br/en/asset_modelling/os_hierarchy/product_health_grade/
---

O DefectDojo pode calcular uma nota para seus Ativos com base na quantidade de Achados contidos neles. As notas são classificadas de A a F.

Observe que apenas Achados Ativos e Verificados contribuem para a Nota do Ativo - achados não verificados não terão impacto.

*A nota de integridade de cada Ativo (A a F) aparece ao lado do seu nome na Lista de Ativos.*

![Notas de Integridade do Ativo exibidas ao lado de cada Ativo na Lista de Ativos](images/asset-health-grade.png)

## Cálculo da Nota do Ativo

Toda Nota de Ativo começa em 100 (sem Achados).

O cálculo da nota começa observando o maior nível de **Severidade** de um Achado no Ativo, reduzindo a Integridade do Ativo a um nível base.

| **Maior Nível de Severidade de um Achado** | **Nota Máxima** |
| --- | --- |
| **Crítica** | **40** |
| **Alto** | **60** |
| **Médio** | **80** |
| **Baixo** | **95** |

Pontos adicionais são então deduzidos da Nota para cada Achado adicional:

| **Nível de Severidade de um Achado adicional** | **Redução na Nota** |
| --- | --- |
| **Crítica** | **5** |
| **Alto** | **3** |
| **Médio** | **2** |
| **Baixo** | **1** |
