---
title: Calificación de Salud del Producto
description: Cómo calcula DefectDojo la Calificación de Salud de un Producto
aliases:
- /es/en/working_with_findings/organizing_engagements_tests/product_health_grade
---

DefectDojo puede calcular una calificación para sus Productos en función de la cantidad de Hallazgos que contienen. Las calificaciones se clasifican de A \- F.

Tenga en cuenta que solo los Hallazgos Activos \& Verificados contribuyen a la Calificación de un Producto \- los Hallazgos no verificados no tendrán impacto.

## Cálculo de la Calificación del Producto

Toda Calificación de Producto comienza en 100 (sin Hallazgos).

El cálculo de la calificación comienza observando el nivel de **Severidad** más alto de un Hallazgo en un Producto, y reduciendo la Salud del Producto a un nivel base.

| **Nivel de Severidad más alto de un Hallazgo** | **Calificación máxima** |
| --- | --- |
| **Crítica** | **40** |
| **Alta** | **60** |
| **Media** | **80** |
| **Baja** | **95** |

A continuación se deducen puntos adicionales de la Calificación por cada Hallazgo adicional:

| **Nivel de Severidad de un Hallazgo adicional** | **Reducción de la Calificación** |
| --- | --- |
| **Crítica** | **5** |
| **Alta** | **3** |
| **Media** | **2** |
| **Baja** | **1** |
