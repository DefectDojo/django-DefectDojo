---
title: Actualización de DefectDojo Pro (On-Premise)
description: Procedimiento de actualización compatible para implementaciones autoalojadas
  de DefectDojo Pro que usan el Helm chart
draft: false
weight: 7
audience: pro
---

Esta página describe el procedimiento de actualización compatible para implementaciones autoalojadas de DefectDojo Pro que usan el Helm chart de DefectDojo Pro.

## Actualice todo como una sola unidad

Cada release de DefectDojo Pro consiste en una versión del Helm chart, versiones de imágenes de contenedor y los archivos de configuración (settings) de Pro. Estos se compilan y prueban juntos y deben actualizarse juntos como una sola unidad.

Actualizar solo las etiquetas de imagen no es compatible y romperá su implementación.

## Archivos de configuración y actualizaciones

DefectDojo Pro incluye un archivo `pro_settings.py` en cada release, y el archivo cambia en casi todas las versiones. No mantenga una copia de `pro_settings.py` de una actualización a otra, ni parchee a mano una copia antigua. La aplicación siempre debe ejecutar el `pro_settings.py` que corresponde a su versión.

Coloque sus propias personalizaciones en `local_settings.py`, nunca en `pro_settings.py`. Su `local_settings.py` se conserva a través de las actualizaciones.

El Helm chart incluye y monta automáticamente el `pro_settings.py` correspondiente y su `local_settings.py`. Cuando actualiza usando el chart, no hay nada que copiar o migrar a mano.

## Procedimiento de actualización compatible

1. Revise las notas de la versión de cada versión entre su versión actual y su versión de destino, no solo la de destino. Consulte el [Changelog de DefectDojo Pro](/releases/pro/changelog/) y las [notas de actualización](/releases/os_upgrading/upgrading_guide/) específicas de cada versión.
2. Haga una copia de seguridad de su base de datos.
3. Actualice al release del Helm chart que corresponde a su versión de aplicación de destino, reutilizando sus archivos de valores existentes. No cambie las etiquetas de imagen de forma independiente de la versión del chart.

Si tiene preguntas sobre cómo actualizar su implementación on-premise, contacte a [support@defectdojo.com](mailto:support@defectdojo.com).
