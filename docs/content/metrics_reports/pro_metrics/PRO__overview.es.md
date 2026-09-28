---
title: Descripción general de las métricas Pro
description: Cómo aprovechar las métricas en DefectDojo Pro
audience: pro
weight: 2
---

La interfaz de DefectDojo Pro cuenta con varios paneles de Métricas que ayudan a visualizar su postura de seguridad actual. Cada panel permite que las partes interesadas en distintos niveles de la organización tomen decisiones informadas sin necesidad de interpretar datos sin procesar ni navegar por Hallazgos individuales. Estos paneles incluyen:
* [Perspectivas ejecutivas](/metrics_reports/pro_metrics/pro__executive_insights/#main-content)
* [Perspectivas de prioridad](/metrics_reports/pro_metrics/pro__priority_insights/#main-content)
* [Perspectivas del programa](/metrics_reports/pro_metrics/pro__program_insights/#main-content)
* [Perspectivas de remediación](/metrics_reports/pro_metrics/pro__remediation_insights/#main-content)
* [Perspectivas de herramientas](/metrics_reports/pro_metrics/pro__tool_insights/#main-content)

![Descripción general de las métricas](images/metrics_image1.png)

## Funciones de las métricas

Antes de detallar cada panel en particular, vale la pena repasar algunos aspectos comunes a todos los paneles.

### Filtrado

Todas las Métricas se pueden filtrar por período, Organización, Activo y Etiqueta. Después de ajustar el filtro como desee, debe hacer clic en Aplicar filtro para que el filtro surta efecto. Si desea exportar en PDF todos los gráficos, tablas y diagramas del panel con el filtro actual aplicado, haga clic en Exportar como PDF. 

El período de filtrado está limitado al último año, pero se puede ajustar para incluir los últimos 7, 14, 30, 90 o 180 días.

Tenga en cuenta que los parámetros del filtro se reflejan en la URL, por lo que puede guardar como marcadores varias páginas con distintos parámetros de filtro.  Esto puede resultar útil para consultas rápidas o para generar de forma sistemática un tipo determinado de informe.

### Submenús 

Cada gráfico cuenta con un menú kebab (⋮) en la esquina superior derecha de cada vista, con las siguientes funciones:
* Actualización forzada — Actualiza manualmente para incorporar las novedades en los datos. 
* Ampliar gráfico — Abre el mismo gráfico en una ventana modal más grande.
* Descargar gráfico como SVG — Descarga el gráfico como un archivo SVG.
* Ver como tabla — Muestra los datos del gráfico en formato de tabla.
    * Cada columna de la tabla se puede alternar para que aparezca en orden ascendente o descendente al hacer clic en ella. También puede descargar cada tabla.

![Contenido del menú kebab](images/metrics_image2.png)

### Acceso

La sección de Métricas solo mostrará datos de las Organizaciones y Activos que cada Usuario tenga permiso para ver. Un Usuario con acceso limitado a un único Activo solo podrá ver las Métricas de ese Activo en particular, pero si no tiene acceso a los demás Activos dentro de la Organización superior, los datos de esos otros Activos no se mostrarán en las Métricas. 

### Visualización de datos dentro de los gráficos

El eje X de los gráficos de líneas siempre representará el período de filtrado actual. Al pasar el cursor sobre un gráfico de líneas, aparecerá una ventana con el recuento de las cifras del eje Y en ese momento. 

![Ventana emergente del gráfico](images/metrics_image3.png)

### Alternar resultados

Los Usuarios pueden alternar la visibilidad de ciertas categorías de Hallazgos en el gráfico haciendo clic en su color o nombre correspondiente en la parte superior de cada gráfico. 

Por ejemplo, en el gráfico de Hallazgos activos por Severidad que aparece a continuación, si solo desea ver los Hallazgos con severidad Alta o Crítica, debe hacer clic en Media, Baja e Informativa en la parte superior para eliminar esos resultados del gráfico. Si vuelve a hacer clic en Media, Baja e Informativa, esos resultados reaparecerán. 

![GIF de alternancia de resultados del gráfico](images/metrics_image4.gif)
