---
title: Grado di Salute del Prodotto
description: Come DefectDojo calcola il Grado di Salute di un Prodotto
aliases:
- /it/en/working_with_findings/organizing_engagements_tests/product_health_grade
---

DefectDojo può calcolare un grado per i tuoi Prodotti in base alla quantità di Riscontri contenuti. I gradi vanno da A \- F.

Nota che solo i Riscontri Attivi \& Verificati contribuiscono al Grado di un Prodotto \- i Riscontri non verificati non avranno alcun impatto.

## Calcolo del Grado del Prodotto

Ogni Grado del Prodotto parte da 100 (in assenza di Riscontri).

Il calcolo del grado inizia osservando il livello di **Gravità** più alto di un Riscontro in un Prodotto, e riducendo la Salute del Prodotto a un livello base.

| **Livello di Gravità più alto di un Riscontro** | **Grado massimo** |
| --- | --- |
| **Critica** | **40** |
| **Alta** | **60** |
| **Media** | **80** |
| **Bassa** | **95** |

Ulteriori punti vengono poi sottratti dal Grado per ogni Riscontro aggiuntivo:

| **Livello di Gravità di un Riscontro aggiuntivo** | **Grado ridotto di** |
| --- | --- |
| **Critica** | **5** |
| **Alta** | **3** |
| **Media** | **2** |
| **Bassa** | **1** |
