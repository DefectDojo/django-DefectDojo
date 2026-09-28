---
title: Hallazgos similares
description: Busque Hallazgos relacionados en la página Ver hallazgo y vincúlelos
  manualmente como duplicados
audience: pro
weight: 3
---

Mientras la [Deduplicación](../about_deduplication) se ejecuta automáticamente en el momento de la importación, **Hallazgos similares** es una herramienta manual e interactiva en la página **Ver hallazgo**. Muestra otros Hallazgos del mismo Activo que se parecen al que está viendo, y le permite vincularlos en un clúster de duplicados a mano.

Utilícela cuando la deduplicación automática no haya agrupado Hallazgos que usted cree que pertenecen juntos, o cuando quiera explorar qué más en un Activo se parece a la vulnerabilidad actual.

## Dónde encontrarla

Abra cualquier Hallazgo y desplácese hasta la tarjeta **Hallazgos duplicados y similares**. Tiene dos pestañas:

- **Hallazgos duplicados** – los Hallazgos ya vinculados a este como duplicados (el clúster automático).
- **Hallazgos similares** – otros Hallazgos del Activo que coinciden con los valores del Hallazgo actual pero que aún no forman parte de su clúster.

Seleccione la pestaña **Hallazgos similares** para ejecutar la consulta.

![La tarjeta Hallazgos duplicados y similares en la página Ver hallazgo](images/pro_similar_findings.png)

## Cómo se emparejan los Hallazgos

DefectDojo busca en el **mismo Activo** Hallazgos que se parezcan al actual, basándose en valores como los ID de vulnerabilidad (por ejemplo, identificadores CVE), CWE, ruta del archivo, número de línea y el Unique ID From Tool. El Hallazgo actual siempre se excluye de sus propios resultados, y la coincidencia nunca cruza entre Activos.

Esto es distinto del algoritmo de deduplicación automática, que compara `hash_code` (o Unique ID From Tool) para decidir las coincidencias. Hallazgos similares extiende deliberadamente una red más amplia para que pueda descubrir Hallazgos relacionados que la coincidencia estricta por hash pasaría por alto.

## Trabajar con los resultados

La pestaña Hallazgos similares es una tabla de datos completa con los mismos controles que usa en el resto de la interfaz de Pro:

- La **búsqueda por palabra clave** y los controles de filtro por columna (embudo) y de orden le permiten acotar la lista.
- El menú desplegable de **vistas guardadas** (**Predeterminada**) y el ícono de guardar le permiten almacenar un diseño de filtros/columnas para reutilizarlo.
- Los botones de configuración de columnas y de diseño controlan qué columnas se muestran.
- **Exportar** descarga los resultados actuales, y **Borrar filtros** restablece la tabla.

Cada fila muestra el ID del Hallazgo coincidente, Severidad, Prioridad, Riesgo, nombre del Hallazgo, CWE, puntajes CVSS, ID de vulnerabilidad, datos EPSS, inteligencia de explotación (Explotado conocido / Ransomware), estado, Activo, y más. Haga clic en el nombre de un Hallazgo para abrirlo.

## Acciones

Abra el menú de acciones (el botón **⋮** al inicio de una fila) para gestionar el clúster de duplicados directamente desde esta página:

![El menú de acciones de fila de Hallazgos similares](images/pro_similar_findings_actions.png)

- **Establecer como Hallazgo original** – asciende un Hallazgo para que sea el original (raíz del clúster).
- **Marcar como duplicado** – vincula el Hallazgo similar al clúster de duplicados del Hallazgo actual.

Estas acciones manipulan las mismas relaciones de duplicados que usa la deduplicación automática, de modo que un Hallazgo que vincule aquí se comporta exactamente igual que un duplicado detectado automáticamente. Cualquier Hallazgo que marque como duplicado aparecerá luego en la pestaña **Hallazgos duplicados** de esta tarjeta.

Una acción puede no estar disponible cuando no es válida, por ejemplo cuando el Hallazgo similar ya es el original de otro clúster, o cuando vincularlo cruzaría un límite de Compromiso mientras la deduplicación a nivel de Compromiso está habilitada.

## Habilitación y deshabilitación de Hallazgos similares

Hallazgos similares se controla mediante la configuración global del sistema **Habilitar Hallazgos similares**, que está habilitada de forma predeterminada. Debido a que la consulta abarca todo un Activo, puede resultar costosa en Activos grandes; si nota que las páginas Ver hallazgo son lentas, esta configuración se puede deshabilitar.
