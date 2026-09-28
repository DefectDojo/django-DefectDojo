---
title: Panel principal de DefectDojo
description: Cómo trabajar con la página principal de DefectDojo
weight: 1
audience: opensource
aliases:
- /es/en/customize_dojo/dashboards/Introduction_dashboard
- /es/en/customize_dojo/dashboards/pro_dashboards
---

El Panel probablemente sea la primera página que verá al abrir DefectDojo. Resume el rendimiento de su equipo y ofrece herramientas de seguimiento para supervisar áreas específicas de su entorno de gestión de vulnerabilidades.

<div class="version-opensource">

![imagen](images/dashboard.png)

</div>
<div class="version-pro">

> **💡 DefectDojo Pro:** En DefectDojo Pro, la página principal es un **panel totalmente personalizable**: usted lo arma a partir de widgets y los organiza usted mismo, en lugar de usar el diseño fijo que se describe a continuación. Consulte **[Paneles personalizables](../custom-dashboards/)** para conocer los conceptos y ver un recorrido por la interfaz. El resto de esta página describe el Panel principal de código abierto.

</div>

<div class="version-opensource">

## Componentes del panel

El panel de código abierto ofrece una instantánea general de su postura de seguridad mediante los siguientes componentes integrados:

### Tarjetas de resumen

La fila superior del panel muestra cuatro tarjetas de resumen que ofrecen una vista rápida de la actividad:

* **Compromisos activos** — cantidad total de Compromisos actualmente abiertos en todos los Productos.
* **Hallazgos en los últimos 7 días** — Hallazgos nuevos creados en la última semana.
* **Cerrados en los últimos 7 días** — Hallazgos que se resolvieron recientemente.
* **Aceptados en los últimos 7 días** — Hallazgos cuyo riesgo se aceptó recientemente.

Cada tarjeta enlaza directamente a la lista filtrada correspondiente, para que pueda profundizar con un solo clic.

### Severidad histórica de Hallazgos

Este gráfico circular desglosa todos los Hallazgos creados en DefectDojo por Severidad (Crítica, Alta, Media, Baja, Informativa), lo que le permite obtener una lectura rápida de la distribución general de vulnerabilidades en su entorno.

### Severidad de Hallazgos reportados por mes

Este gráfico de líneas representa el volumen y la severidad de los Hallazgos entrantes mes a mes, lo que ayuda a detectar tendencias, como picos tras la integración de un nuevo escáner o una mejora sostenida gracias a los esfuerzos de remediación.

### Configuración del panel

Los Superusuarios pueden alternar qué gráficos aparecen en el panel. Vaya al menú del engranaje en la esquina superior derecha y seleccione **Editar configuración del panel** para mostrar u ocultar:

* **Mostrar gráficos** — controla los gráficos de Severidad histórica de Hallazgos y Severidad de Hallazgos reportados.
* **Mostrar encuestas** — controla la tabla de Cuestionarios de Compromiso respondidos sin asignar.
* **Mostrar tablas de datos** — controla las tablas de los 10 Productos mejor y peor calificados.

Seleccione **Restablecer configuración del panel** en el mismo menú para volver a los valores predeterminados.

</div>
