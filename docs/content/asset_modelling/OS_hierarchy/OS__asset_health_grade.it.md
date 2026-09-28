---
title: Grado di salute dell'Asset
description: Come DefectDojo calcola il Grado di salute dell'Asset
weight: 7
audience: opensource
aliases:
- /it/asset_modelling/os_hierarchy/product_health_grade/
- /it/en/asset_modelling/os_hierarchy/product_health_grade/
---

DefectDojo può calcolare un grado per i tuoi Asset in base alla quantità di Riscontri in essi contenuti. I gradi sono classificati da A \- F.

Nota che solo i Riscontri Attivo \& Verificato contribuiscono al Grado dell'Asset \- i Riscontri non verificati non avranno alcun impatto.

*Il grado di salute di ogni Asset (A \- F) appare accanto al suo nome nell'Elenco degli Asset.*

![Gradi di salute dell'Asset mostrati accanto a ciascun Asset nell'Elenco degli Asset](images/asset-health-grade.png)

## Calcolo del Grado dell'Asset

Ogni Grado dell'Asset parte da 100 (in assenza di Riscontri).

Il calcolo del grado inizia osservando il livello di **Gravità** più alto di un Riscontro in un Asset, e riducendo la salute dell'Asset a un livello base.

| **Livello di Gravità più alto di un Riscontro** | **Grado massimo** |
| --- | --- |
| **Critica** | **40** |
| **Alta** | **60** |
| **Media** | **80** |
| **Bassa** | **95** |

Vengono poi sottratti ulteriori punti dal Grado per ogni Riscontro aggiuntivo:

| **Livello di Gravità di un Riscontro aggiuntivo** | **Riduzione del Grado** |
| --- | --- |
| **Critica** | **5** |
| **Alta** | **3** |
| **Media** | **2** |
| **Bassa** | **1** |
