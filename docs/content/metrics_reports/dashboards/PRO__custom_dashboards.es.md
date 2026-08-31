---
title: Paneles personalizables
description: Cree paneles personalizados en DefectDojo Pro a partir de widgets organizados
  en una cuadrícula de arrastrar y soltar
draft: false
audience: pro
weight: 10
slug: custom-dashboards
aliases:
- /es/en/customize_dojo/dashboards/about_custom_dashboard_tiles
- /es/metrics_reports/dashboards/about_custom_dashboard_tiles
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: los Paneles personalizables (diseños, widgets y el catálogo de widgets) son una función de DefectDojo Pro. Están desactivados de forma predeterminada: un Superusuario puede activarlos desde **Configuración > Feature Flags** tanto en instancias Cloud como On-Premise.</span>

Los Paneles personalizables de DefectDojo Pro permiten que cada usuario arme su propia página principal a partir de **widgets** (contadores, gráficos, tablas de clasificación, feeds y notas) organizados en una cuadrícula de arrastrar y soltar. En lugar de un único panel fijo para todos, usted construye los **diseños** que le resultan útiles: una vista general ejecutiva, una cola de triaje, un tablero de velocidad de remediación, una vista de eficacia de escáneres. Puede mantener los diseños privados, publicarlos para todo su equipo, establecer uno como página de inicio predeterminada y clonar cualquier diseño (propio o una plantilla compartida) como punto de partida.

![Un panel personalizable de DefectDojo Pro: el diseño del Panel predeterminado.](images/pro_dashboard_v2_default.png)

## Comparación con la versión de código abierto

La versión de código abierto de DefectDojo cuenta con un único [Panel principal](../introduction_dashboard/) integrado, con un conjunto fijo de tarjetas de resumen y gráficos que un Superusuario puede mostrar u ocultar. Es igual para todos los usuarios.

DefectDojo Pro reemplaza esa página fija por **paneles personalizables por usuario**. Usted elige qué widgets aparecen, cómo se filtran y dónde se ubican en la cuadrícula. Puede crear cualquier cantidad de diseños con nombre, alternar entre ellos, compartirlos con su equipo y controlar todo el sistema desde la [REST API](../custom-dashboards-api/) o un [LLM](../custom-dashboards-llm/).

> **💡 Tip:** en DefectDojo Pro, los **Activos** antes se llamaban **Productos** y las **Organizaciones** antes eran **Tipos de producto**. La interfaz usa la nueva terminología, pero algunas configuraciones de widgets subyacentes todavía usan los nombres antiguos; por ejemplo, la mayoría de los widgets toman un `model` de `finding`, `product`, `engagement` o `test`. Donde esto sea relevante, se indicará más adelante.

## Activación de los Paneles personalizables

Los Paneles personalizables están desactivados de forma predeterminada. Un Superusuario puede activarlos desde **Configuración > Feature Flags**, tanto en instancias Cloud como On-Premise. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Una vez activada, la página **🏠 Inicio** muestra su panel personalizable y queda disponible la [API REST de paneles](../custom-dashboards-api/).

> **🔑 Important:** mientras la función esté desactivada, la página de inicio conserva el panel anterior y todos los endpoints `/api/v2/dashboards/` devuelven `403 Dashboards 2.0 is not enabled.` Activarla **no** cambia el acceso a los datos de nadie: cada widget sigue respetando el control de acceso basado en roles de DefectDojo, de modo que cada usuario solo ve los Hallazgos, Activos y demás registros que está autorizado a ver.

## Conceptos fundamentales

Un panel personalizable se construye a partir de unas pocas piezas simples.

### Diseños

Un **diseño** es un panel con nombre: un conjunto de widgets y sus posiciones en la cuadrícula. Cada diseño le pertenece a usted, y puede tener tantos como desee — por ejemplo un tablero de "Triaje diario" y otro independiente de "Vista general ejecutiva." Un diseño almacena tres cosas:

- **widgets** — la lista ordenada de widgets que contiene, cada uno con su propio tipo, título y configuración.
- **layout** — dónde se ubica cada widget y qué tamaño tiene en la cuadrícula.
- **settings** — opciones de visualización a nivel de diseño.

La primera vez que abre los Paneles personalizables, DefectDojo le proporciona una copia personal del panel inicial **Panel predeterminado**, para que nunca se encuentre frente a una página en blanco.

### Widgets

Un **widget** es un único panel dentro del panel general. Cada widget es una instancia de un **tipo** del catálogo (un Contador, un Gráfico, una tabla de clasificación Top-N, etc.), y tiene su propia **configuración**: qué **modelo** de datos lee (`finding`, `product`, `engagement` o `test`), qué **filtros** lo delimitan, y opciones de visualización específicas del tipo, como el tipo de gráfico, los colores o la agrupación. Dos widgets del mismo tipo con filtros distintos son completamente independientes.

Cada widget también tiene un **intervalo de actualización automática** opcional (desactivado, 30 segundos, 1 minuto, 5 minutos o 15 minutos) y un **título** editable.

### El catálogo de widgets

El **catálogo** es el menú fijo de tipos de widgets que admite la plataforma, agrupados en cuatro categorías — **Números**, **Gráficos**, **Listas y feeds**, y **Estático y utilidades**. Al agregar un widget, usted elige su tipo en el catálogo. El catálogo también está disponible a través de la [API](../custom-dashboards-api/), de modo que los scripts y los LLM puedan descubrir los tipos de widgets disponibles y una configuración inicial ya probada para cada uno. Consulte [El catálogo de widgets](#the-widget-catalog-1) más abajo para ver la lista completa.

### La cuadrícula

Los widgets se ubican en una **cuadrícula de 12 columnas**. En el modo de edición, se arrastran los widgets para moverlos y se arrastra la esquina inferior derecha para cambiar su tamaño; la cuadrícula se compacta hacia arriba para llenar los espacios vacíos. Cada tipo de widget tiene tamaños mínimos y máximos razonables para que los gráficos y las tablas se mantengan legibles.

### Uso compartido, clonación y valores predeterminados

- **Default** — uno de sus diseños es su diseño **predeterminado**: el que se carga al abrir la página de inicio. Puede cambiar cuál es su diseño predeterminado en cualquier momento.
- **Clone** — copie cualquier diseño (uno propio o una plantilla compartida) en su propio espacio como punto de partida nuevo e independiente. Al clonar, la copia obtiene sus propios widgets, de modo que editar el clon nunca afecta al original.
- **Share** — publique uno de sus diseños para todo el equipo como **diseño compartido**. Otros usuarios pueden verlo y clonarlo, pero solo un **Mantenedor** del equipo puede publicar, editar o dejar de compartir un diseño compartido. Compartir un diseño solo comparte su *diseño visual* — cada usuario que lo vea seguirá viendo únicamente los datos que sus propios permisos le permitan.
- **Starter & shared templates** — DefectDojo incluye un conjunto de **plantillas compartidas** seleccionadas que puede clonar como punto de partida (consulte [Plantillas compartidas](#shared-templates) más abajo). El **Panel predeterminado** es la plantilla especial "inicial" que se entrega automáticamente a los usuarios nuevos.

## Creación de un panel en la interfaz

### La barra de herramientas del panel

La barra de herramientas ubicada en la parte superior de la página de inicio es donde se cambian y administran los diseños. Incluye un **selector de diseños** (con distintivos que marcan su diseño predeterminado y cualquier diseño o plantilla compartida), y botones para crear un **Nuevo diseño**, abrir **Administrar diseños**, **Actualizar** todos los widgets y alternar el modo **Editar**.

![La barra de herramientas del panel (resaltada): el selector de diseños, además de Nuevo diseño, Administrar diseños, Actualizar y Editar](images/pro_dashboard_v2_home.png)

### Paso 1: Ingresar al modo de edición

Haga clic en **Editar** para desbloquear el panel. La cuadrícula se vuelve arrastrable y redimensionable, y aparece un botón **Agregar widget**. Haga clic en **Listo** cuando termine — el modo de edición también se desactiva automáticamente al cambiar de diseño.

![Un panel en modo de edición, con controles de arrastre y cambio de tamaño](images/pro_dashboard_v2_edit_grid.png)

### Paso 2: Agregar un widget

En el modo de edición, haga clic en **Agregar widget** para abrir el selector. Tiene dos pestañas:

- **By Type** — explore el catálogo por categoría (Números, Gráficos, Listas y feeds, Estático y utilidades). Cada tarjeta muestra el nombre del widget y una breve descripción. Al elegir uno, se agrega a la cuadrícula y se abre su cuadro de diálogo de configuración.
- **From Catalog** — comience a partir de un widget preconfigurado tomado de una de las plantillas compartidas (por ejemplo, el gráfico "Findings by Severity" del Panel predeterminado). Estos vienen listos para usar, por lo que se colocan directamente en la cuadrícula.

![El cuadro de diálogo Agregar widget, pestaña Por tipo](images/pro_dashboard_v2_add_widget.png)

### Paso 3: Configurar el widget

Cada widget abre un cuadro de diálogo de configuración adaptado a su tipo. Las opciones comunes incluyen:

- **Title** — el encabezado que se muestra en el widget.
- **Model** — qué registros lee el widget (Hallazgo, Activo, Compromiso o Test), cuando corresponda.
- **Filters** — una interfaz de filtro de vista de lista incorporada que limita el widget exactamente a los registros que usted desea (por ejemplo, hallazgos Críticos activos). Los filtros que elija aquí son los mismos que usaría en la página de lista de ese objeto.
- **Refresh interval** — con qué frecuencia se recarga el widget por sí solo.
- **Type-specific options** — por ejemplo, el tipo de gráfico y la dimensión de agrupación para un Gráfico, los umbrales para un Indicador, o la métrica para una tabla de clasificación Top-N.

![Configuración de un widget de Gráfico](images/pro_dashboard_v2_widget_config.png)

> **💡 Tip:** los datos de un widget siempre respetan sus permisos. Si un diseño compartido incluye un widget "My Work", cada usuario verá *sus propias* asignaciones y menciones — no las del autor del diseño.

### Paso 4: Organizar y guardar

Arrastre los widgets para reorganizarlos y arrastre una esquina para cambiar su tamaño. Use el ícono de engranaje de un widget para reconfigurarlo, y el ícono de papelera para eliminarlo. Los cambios de posición y tamaño se guardan automáticamente a medida que los realiza. Haga clic en **Listo** para salir del modo de edición.

### Administración de diseños

El cuadro de diálogo **Administrar diseños** (el botón de engranaje en la barra de herramientas) es el centro de todo lo relacionado con los diseños:

- **Your Layouts** — cambie el nombre, defina como predeterminado, comparta o deje de compartir, clone o elimine cada diseño que le pertenece.
- **Create New** — comience un diseño nuevo y vacío para construir desde cero.
- **Shared Templates** — explore diseños seleccionados y publicados por el equipo, agrupados por categoría, y haga clic en **Usar diseño** para clonar uno en su propio espacio.

![El cuadro de diálogo Administrar diseños](images/pro_dashboard_v2_manage_layouts.png)

### Plantillas compartidas

DefectDojo incluye cuatro plantillas compartidas listas para usar que puede clonar como punto de partida:

| Plantilla | Objetivo |
|----------|---------|
| **Panel predeterminado** | La vista de inicio clásica — 12 contadores rápidos, gráficos de severidad y los Activos mejor y peor calificados. Es la plantilla inicial que reciben automáticamente todos los usuarios nuevos. |
| **Diseño de prioridad** | Un tablero centrado en el triaje, organizado según la prioridad y el riesgo de los hallazgos. |
| **Diseño de mitigación** | Un tablero de velocidad de remediación (tendencias de cierre, MTTR/MTTD, antigüedad). |
| **Diseño de herramientas** | Un tablero de eficacia de escáneres organizado según los tipos de test y la actividad de escaneo reciente. |

> **💡 Tip:** al clonar una plantilla se crea una copia independiente. Personalice el clon libremente — no afectará a la plantilla ni a nadie más que la clone.

### El estado vacío

Un diseño completamente nuevo sin widgets muestra un mensaje de **"Build Your First Dashboard"**. Haga clic en **Agregar su primer widget** para pasar directamente al modo de edición y comenzar a elegir widgets.

![El estado de diseño vacío](images/pro_dashboard_v2_empty_state.png)

## El catálogo de widgets

Los Paneles personalizables incluyen los siguientes tipos de widgets, organizados en cuatro categorías. La mayoría de los widgets leen uno de cuatro modelos — `finding`, `product` (Activos), `engagement` o `test` — y se delimitan mediante los filtros que usted elija. Las opciones de configuración completas y detalladas de cada widget están documentadas en la [guía de la API](../custom-dashboards-api/).

### Números

Métricas de un vistazo — contadores, KPI e indicadores.

| Widget | Qué muestra |
|--------|---------------|
| **Count** | Un único número a partir de una consulta filtrada — por ejemplo "Open Critical Findings" o "Active Engagements." Funciona con finding / asset / engagement / test. |
| **KPI / Trend** | Un número principal más su variación respecto del período anterior, con un minigráfico opcional. |
| **Gauge** | Una proporción representada como un indicador de arco — un filtro "universo" como denominador y un filtro "aprobado" como numerador. Se usa para el cumplimiento de SLA, la tasa de mitigación o la cobertura de escaneo, con umbrales de advertencia/correcto configurables. |
| **License Usage** | El estado de uso de la licencia de su cuenta, con un desglose por señal (tamaño de la base de datos, volumen semanal de hallazgos, y así sucesivamente). *Requiere el rol de Mantenedor.* |
| **Scan Coverage** | Qué fracción de los activos se escaneó dentro de 30 / 90 / 180 / 365 días, como resumen de múltiples ventanas. |

### Gráficos

Visualizaciones de series temporales y distribución.

| Widget | Qué muestra |
|--------|---------------|
| **Graph** | Un gráfico de uso general sobre cualquier modelo y dimensión de agrupación — de barras, de líneas, de área, circular o de anillo. Por ejemplo, Findings by Severity, Findings by Month. |
| **Sankey** | Un diagrama de flujo desde una dimensión de origen hacia una dimensión de destino — por ejemplo Severity → Status. |
| **Sunburst** | Un desglose radial de uno o dos niveles — por ejemplo Severity, y luego Test Type dentro de cada severidad. |
| **Risk Matrix** | Un mapa de calor de hallazgos según probabilidad EPSS × riesgo — seguro en la esquina inferior izquierda, peligroso en la superior derecha. |
| **Priority Histogram** | La distribución de las puntuaciones de **priority** de los hallazgos según el motor de priorización, agrupadas automáticamente. |
| **Rate by Category** | Una proporción por categoría (numerador / denominador) — por ejemplo la False-Positive Rate by Tool o la Mitigation Rate by Asset. |
| **Finding Velocity** | Hallazgos creados frente a cerrados a lo largo del tiempo, mostrando si el backlog crece o disminuye. |
| **MTTR / MTTD** | Tiempo Medio de Remediación y Tiempo Medio de Detección, como series temporales emparejadas. |
| **Vulnerability Aging** | Hallazgos abiertos agrupados por rango de antigüedad (0–30d / 30–90d / 90–180d / 180d+), apilados por severidad. |
| **Activity Heatmap** | Un calendario de actividad diaria al estilo GitHub durante una ventana móvil. |
| **Portfolio Treemap** | Rectángulos anidados para un resumen de cartera (Organization → Asset), dimensionados por cantidad y coloreados según la severidad. |

### Listas y feeds

Listas clasificadas, feeds y tablas incorporadas.

| Widget | Qué muestra |
|--------|---------------|
| **Top-N Leaderboard** | Una lista clasificada en uno de dos modos: *aggregate* (los principales grupos por dimensión según la cantidad, por ejemplo Top 10 CWEs) o *records* (los principales registros individuales según una métrica, por ejemplo Top 10 Assets by Grade). |
| **Embedded Table** | Una vista de lista completa (Findings, Assets, Engagements, Tests, Risk Acceptances, Organizations o Test Types) con filtros y ordenamiento preestablecidos — incluida la paginación, la ordenación y la exportación a CSV. |
| **Recent Activity** | Un feed desplazable de los registros actualizados más recientemente, con enlaces a las páginas de detalle. |
| **SLA Burndown** | Hallazgos que se acercan al incumplimiento del SLA, clasificados por días restantes, con distintivos de cuenta regresiva. |
| **My Work** | Su cola personal — asignaciones, menciones y revisiones de aceptación de riesgo pendientes. Siempre limitado al propio usuario. |
| **Saved Reports** | Acceso con un clic a sus Plantillas de informe guardadas. *Requiere la función de Informes.* |

### Estático y utilidades

Notas, accesos directos y estructura.

| Widget | Qué muestra |
|--------|---------------|
| **Favorites** | Enlaces rápidos seleccionados por el usuario hacia páginas específicas de la aplicación. |
| **Section Break** | Un divisor con etiqueta para agrupar widgets relacionados bajo un encabezado. |
| **Markdown / Notes** | Un panel de texto enriquecido en línea para encabezados, notas de contexto o enlaces de referencia. |
| **Quick Actions** | Botones de acción con un clic que navegan hacia una página elegida. |

## Próximos pasos

- **[Automatización de paneles con la API](../custom-dashboards-api/)** — descubra el catálogo de widgets, cree y actualice diseños, y renderice datos de widgets a través de la REST API, con un script completo.
- **[Creación de paneles con un LLM](../custom-dashboards-llm/)** — deje que un LLM diseñe y construya paneles por usted (la API de paneles se diseñó pensando en agentes de IA).
