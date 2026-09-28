---
title: Hallazgos similares
description: Encuentre Hallazgos relacionados en la página Ver Hallazgo y vincúlelos
  manualmente como duplicados
audience: opensource
weight: 3
---

Si bien la [Deduplicación](../about_deduplication) se ejecuta automáticamente en el momento de la importación, **Hallazgos similares** es una herramienta manual e interactiva que se encuentra en la página **Ver Hallazgo**. Muestra otros Hallazgos del mismo Asset que se parecen al que está viendo, y le permite vincularlos manualmente en un clúster de duplicados.

Úsela cuando la deduplicación automática no agrupó Hallazgos que usted cree que pertenecen juntos, o cuando quiera explorar qué más en un Asset se parece a la vulnerabilidad actual.

## Dónde encontrarla

Abra cualquier Hallazgo para llegar a su página Ver Hallazgo. Desplácese hacia abajo hasta el panel **Hallazgos similares**. El número en el encabezado es la cantidad de Hallazgos del Asset que coinciden con los valores del Hallazgo actual.

![El encabezado del panel Hallazgos similares en la página Ver Hallazgo](images/similar_findings_panel.png)

El panel está contraído de forma predeterminada. Haga clic en el encabezado del panel (o en el chevron/botón de filtro de la derecha) para expandirlo y ejecutar la consulta.

## Cómo se emparejan los Hallazgos

Al abrir el panel, DefectDojo completa previamente un filtro con los valores del Hallazgo actual y busca en el **mismo Asset** otros Hallazgos que coincidan. Los campos utilizados para iniciar la coincidencia son:

- IDs de vulnerabilidad (por ejemplo, identificadores CVE)
- CWE
- Ruta de archivo
- Número de línea
- Unique ID from tool
- Tipo de test
- Asset (y tipo de Asset)

El Hallazgo actual siempre se excluye de sus propios resultados. La coincidencia está limitada al Asset, por lo que Hallazgos similares nunca busca entre distintos Assets. Si alguno de los Compromisos tiene habilitada la deduplicación a nivel de Compromiso, las coincidencias que cruzan un límite de Compromiso no se pueden vincular (consulte [Acciones](#actions) más abajo).

Esto es diferente del algoritmo de deduplicación automática, que compara `hash_code` (o Unique ID from tool) para decidir las coincidencias. Hallazgos similares amplía deliberadamente la red para que pueda descubrir Hallazgos relacionados que una coincidencia estricta por hash pasaría por alto.

## Refinar la coincidencia

Los valores iniciales son solo un punto de partida. El panel de filtros en la parte superior de la sección le permite hacer que la coincidencia sea más estricta o más laxa: quite un campo para ampliar los resultados, o agregue criterios (severidad, estado, endpoint, fechas, EPSS y más) para acotarlos.

![El panel de filtros de Hallazgos similares](images/similar_findings_filters.png)

- **Clear filters** vacía todos los campos para que pueda construir una consulta desde cero.
- **Restart** vuelve a la coincidencia predeterminada basada en los valores del Hallazgo actual.

## Interpretar los resultados

Cada Hallazgo coincidente se enumera en una tabla. La columna **Relationship** indica cómo se relaciona ese Hallazgo con el que está viendo:

- **Original**: el Hallazgo raíz/original del clúster de duplicados del Hallazgo actual
- **Duplicate**: un Hallazgo ya marcado como duplicado del actual
- **Similar**: una coincidencia que aún no forma parte del clúster del Hallazgo actual

![La tabla de resultados de Hallazgos similares](images/similar_findings_list.png)

La tabla también muestra Severity, Title, Date, Status, Test, Engagement, CWE, Vulnerability Id, EPSS score, File (con número de línea), y JIRA (cuando la integración de JIRA está habilitada). Todas las columnas se pueden ordenar, y los resultados se pueden exportar (Copy, Excel, CSV, PDF).

## Acciones

Si tiene permiso de edición sobre un Hallazgo, la columna **Action** ofrece un menú desplegable para gestionar el clúster de duplicados directamente desde esta página:

![El menú de acciones de fila de Hallazgos similares](images/similar_findings_actions.png)

- **Mark as duplicate**: vincula el Hallazgo similar al clúster de duplicados del Hallazgo actual.
- **Set as original**: promueve un Hallazgo para que sea el original (raíz del clúster).
- **Reset finding duplicate status**: elimina un Hallazgo de su clúster.

Una acción puede no estar disponible (se muestra como **None**) cuando no es válida, por ejemplo cuando el Hallazgo similar se encuentra en un Compromiso diferente y la deduplicación a nivel de Compromiso está habilitada, o cuando ya es el original de un clúster distinto. Estas acciones manipulan las mismas relaciones de duplicado que utiliza la deduplicación automática, por lo que un Hallazgo que marque aquí se comporta exactamente igual que un duplicado detectado automáticamente.

## Habilitar y deshabilitar Hallazgos similares

Hallazgos similares se controla mediante una configuración global del sistema. Vaya a **Configuration > System Settings** y active el interruptor **Enable Similar Findings**. Está habilitado de forma predeterminada.

![La configuración del sistema Enable Similar Findings](images/similar_findings_enable_setting.png)

Debido a que la consulta busca en todo un Asset, puede ser costosa en Assets grandes. Si nota que las páginas Ver Hallazgo se vuelven lentas, puede deshabilitar esta función aquí, o limitar la cantidad de resultados devueltos con la variable de entorno `DD_SIMILAR_FINDINGS_MAX_RESULTS` (predeterminado `25`).
