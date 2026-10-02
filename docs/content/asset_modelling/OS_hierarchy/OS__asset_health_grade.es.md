---
title: Calificación de estado del Activo
description: Cómo calcula DefectDojo la calificación de estado de un Activo
weight: 7
audience: opensource
aliases:
- /es/asset_modelling/os_hierarchy/product_health_grade/
- /es/en/asset_modelling/os_hierarchy/product_health_grade/
---

DefectDojo puede calcular una calificación para sus Activos según la cantidad de Hallazgos que contengan. Las calificaciones van de A \- F.

Tenga en cuenta que solo los Hallazgos Activos \& Verificados contribuyen a la calificación de un Activo \- los Hallazgos no verificados no tienen ningún impacto.

*La calificación de estado de cada Activo (A \- F) aparece junto a su nombre en la lista de Activos.*

![Calificaciones de estado de los Activos que se muestran junto a cada Activo en la lista de Activos](images/asset-health-grade.png)

## Cálculo de la calificación del Activo

Toda calificación de Activo comienza en 100 (sin Hallazgos).

El cálculo de la calificación comienza observando el nivel de **Severidad** más alto de un Hallazgo en un Activo, y reduciendo el estado del Activo a un nivel base.

| **Nivel de Severidad más alto de un Hallazgo** | **Calificación máxima** |
| --- | --- |
| **Crítica** | **40** |
| **Alta** | **60** |
| **Media** | **80** |
| **Baja** | **95** |

Luego se restan puntos adicionales de la calificación por cada Hallazgo adicional:

| **Nivel de Severidad de un Hallazgo adicional** | **Reducción de la calificación** |
| --- | --- |
| **Crítica** | **5** |
| **Alta** | **3** |
| **Media** | **2** |
| **Baja** | **1** |
