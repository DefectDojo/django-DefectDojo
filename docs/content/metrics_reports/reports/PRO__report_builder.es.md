---
title: Generador de informes
description: Cree informes personalizados y reutilizables en DefectDojo Pro con Themes,
  Blocks y Templates
draft: false
audience: pro
weight: 20
slug: report-builder
aliases:
- /es/en/share_your_findings/pro_reports/using_the_report_builder
- /es/metrics_reports/reports/using_the_report_builder
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: El generador de informes reutilizable (Themes, Blocks, Templates e Informes generados guardados) es una función de DefectDojo Pro, actualmente en beta.</span>

El generador de informes de DefectDojo Pro le permite componer informes pulidos a partir de partes reutilizables, de modo que puede crear las piezas una vez y reutilizarlas en todas partes en lugar de reconstruir un informe desde cero cada vez. Se accede a él desde el área **📄 Informes** en la barra lateral.

## Cómo se compara con la versión de código abierto

DefectDojo de código abierto puede crear un informe, ejecutarlo y permitirle obtener el resultado, pero **no** guarda las plantillas de informe ni conserva los informes que genera. Cada informe es un esfuerzo puntual.

DefectDojo Pro convierte la generación de informes en bloques de construcción reutilizables. Usted guarda **Themes**, **Blocks** y **Templates** que puede combinar, adaptar y reutilizar, y cada informe que ejecuta se conserva como un **Generated Report** que puede descargar o volver a ejecutar más tarde. Pro también expone todo el flujo de trabajo mediante una API REST completa y admite la creación asistida por LLM, de modo que los informes se pueden crear y ejecutar de forma programática.

> **💡 Tip:** Si utiliza DefectDojo de código abierto, consulte en su lugar el [generador de informes de código abierto](../using-the-report-builder/).

## Conceptos fundamentales

El generador de informes se compone de cuatro piezas, cada una disponible como recurso REST bajo `/api/v2/`: `report_themes`, `report_blocks`, `report_templates` y `generated_reports`. Comprender cómo encajan entre sí es la clave para crear informes de manera eficiente.

### Themes

Un **Theme** controla el estilo visual y la marca de un informe: los colores, las imágenes de encabezado y pie de página, y el texto del pie de página. Al definir un Theme una vez, puede aplicar una marca corporativa consistente a cada informe que produzca.

Un Theme tiene los siguientes ajustes:

| Ajuste | Finalidad | Valor predeterminado |
|---------|---------|---------|
| Name | Una etiqueta para el Theme | — |
| Primary color | Color principal de la marca | `#1e3a5f` |
| Secondary color | Color de marca de apoyo | `#4a90a4` |
| Accent color | Color de resaltado | `#e67e22` |
| Text color | Color del texto del cuerpo | `#333333` |
| Background color | Color de fondo de la página | `#ffffff` |
| Footer text | Texto mostrado en el pie de página | — |
| Show page numbers | Si se deben imprimir los números de página | On |
| Header image | Imagen mostrada en el encabezado | — |
| Footer image | Imagen mostrada en el pie de página | — |

> **💡 Tip:** Los cinco colores se expresan como valores hexadecimales de 7 caracteres (por ejemplo, `#1e3a5f`), para que pueda igualar exactamente la paleta de marca de su organización.

Puede crear esto en la interfaz de usuario (más abajo) o automatizarlo con la [API](../report-builder-api/).

### Blocks

Un **Block** es una unidad de contenido reutilizable. Usted crea un Block una vez, configura lo que muestra y luego lo coloca en tantas Templates como desee. Hay cuatro tipos de bloque:

| Tipo de bloque | Qué produce |
|------------|------------------|
| **Stock** | Contenido sin datos, como una página de portada, un índice, un salto de página, una imagen o un bloque de texto. |
| **Tabular** | Una tabla de registros extraídos de una única entidad. |
| **Detail** | Un diseño por registro, ideal para campos extensos que se representan como markdown (por ejemplo, descripción, impacto, mitigación y referencias). |
| **Chart** | Gráficos visuales. *Próximamente* — este tipo de bloque está definido en el modelo de datos, pero aún no está disponible en la API ni en la interfaz de usuario. |

Un bloque **Stock** se configura eligiendo uno de cinco tipos de stock, junto con un título, subtítulo, contenido de texto o imagen según corresponda:

- **Cover page**
- **Table of contents**
- **Page break**
- **Image**
- **Text block**

Los bloques **Tabular** y **Detail** extraen ambos registros en vivo de una entidad. Usted elige la entidad mediante una selección de modelo y luego selecciona qué campos incluir y cómo ordenar los registros. La selección de modelo es exactamente una de estas siete entidades:

- **Organization**
- **Asset**
- **Engagement**
- **Test**
- **Finding**
- **Test type**
- **Risk acceptance**

> **💡 Tip:** En DefectDojo Pro, los **Assets** se llamaban anteriormente **Products** y las **Organizations** eran anteriormente **Product Types**. Es posible que aún encuentre la terminología heredada en algunos nombres de campos y filtros subyacentes.

La diferencia está en la presentación: un bloque **Tabular** organiza los registros como una tabla de columnas, lo cual es ideal para resúmenes e inventarios, mientras que un bloque **Detail** representa un registro a la vez en un diseño extenso, más adecuado para campos ricos en markdown como descripción, impacto, mitigación y referencias.

> **💡 Tip:** Los filtros residen en el Block, no en la Template. Un Block lleva consigo sus propios filtros, de modo que reutilizar un Block reutiliza sus filtros de forma idéntica en todos los lugares donde aparece. Si necesita el mismo contenido pero con un filtro diferente, duplique el Block y ajuste la copia.

Puede crear esto en la interfaz de usuario (más abajo) o automatizarlo con la [API](../report-builder-api/).

### Templates

Una **Template** es una lista ordenada de Blocks vinculada a un único Theme. La Template define qué aparece en el informe y en qué orden, mientras que el Theme al que está vinculada controla su apariencia.

Dado que una Template hace referencia a los Blocks por inclusión, el mismo Block puede aparecer en una Template más de una vez. Un Block reutilizable de salto de página, por ejemplo, se puede insertar entre varias secciones del mismo informe.

Puede crear esto en la interfaz de usuario (más abajo) o automatizarlo con la [API](../report-builder-api/).

### Generated Reports

Ejecutar una Template produce un **Generated Report**: un archivo PDF o HTML persistido que puede descargar y volver a ejecutar bajo demanda. Cada Generated Report queda **congelado en el tiempo** — captura los datos de DefectDojo en el momento en que se generó y **no** se actualiza automáticamente cuando los datos subyacentes cambian después. Para obtener una instantánea actualizada, vuelva a ejecutar la Template.

Un Generated Report atraviesa estos estados a medida que se construye:

| Estado | Significado |
|--------|---------|
| Pending | El informe ha sido solicitado y está en cola. |
| Processing | El informe se está ensamblando. |
| Completed | El informe está listo para descargar. |
| Failed | El informe no se pudo generar. |

> **🔑 Important:** La generación de informes está activada de forma predeterminada. Un superusuario puede activarla o desactivarla desde **Settings > Feature Flags** (consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/)). La visualización respeta el control de acceso basado en roles (RBAC) de DefectDojo — los usuarios solo ven los datos que están autorizados a ver, incluso dentro de un informe.

Puede crear esto en la interfaz de usuario (más abajo) o automatizarlo con la [API](../report-builder-api/).

## Creación de un informe en la interfaz de usuario

Los siguientes pasos recorren la creación de un informe de principio a fin: crear un Theme, crear los Blocks que contienen su contenido, ensamblarlos en una Template y generar el informe final.

### Paso 1: Crear un Theme

Comience en el área de Themes. La lista de Themes muestra cada Theme que ha definido y le permite crear uno nuevo.

![Lista de temas](images/pro_report_themes_list.png)

Abra un nuevo Theme para establecer su marca. El formulario del Theme expone los cinco colores, una imagen opcional de encabezado y pie de página, el texto del pie de página y el interruptor de números de página. Elija colores que coincidan con la marca de su organización para que cada informe que produzca se vea consistente.

![Formulario de edición de tema](images/pro_report_theme_new.png)

### Paso 2: Crear Blocks

A continuación, cree los Blocks de contenido. La lista de Blocks muestra todos sus Blocks de cada tipo.

![Lista de bloques](images/pro_report_blocks_list.png)

Para crear un Block basado en datos, elija su tipo y configúrelo. El siguiente ejemplo es un Block **Tabular** nombrado para hallazgos abiertos: el Block Type se establece en Tabular, se proporciona un encabezado, el Model es **Finding**, los campos seleccionados son Severity, Title, Product, Age (Days) y SLA Days Remaining, y los registros se ordenan por Numerical Severity en orden descendente. Dado que los filtros residen en el Block, las **Filter Entries** aquí delimitan exactamente qué registros extraerá este Block dondequiera que se use.

![Configuración de bloque tabular](images/pro_report_block_new_tabular.png)

Puede usar **Preview** para ver cómo se representará un Block con un Theme aplicado antes de incorporarlo a una Template. La vista previa siguiente muestra una página de portada con estilo ("DefectDojo Security Report") que adopta los colores y la marca del Theme.

![Vista previa del bloque renderizado](images/pro_report_block_preview.png)

> **💡 Tip:** Use **Duplicate** para copiar un Block existente cuando necesite el mismo diseño con un filtro diferente. Dado que los filtros viajan con el Block, duplicar es la forma correcta de producir, por ejemplo, una tabla de "hallazgos críticos" y una tabla de "hallazgos altos" a partir del mismo diseño de columnas.

### Paso 3: Ensamblar una Template

Con sus Blocks listos, cree una Template. La lista de Templates muestra sus Templates guardadas.

![Lista de plantillas](images/pro_report_templates_list.png)

En el editor de Templates, seleccione un Theme y organice los Blocks en el orden en que deben aparecer. El ejemplo siguiente secuencia Cover Page → Executive Intro → Open Findings → KEV → Page Break → Asset Inventory. Use **Add Existing Block** para reutilizar un Block que ya creó, o **Add New Block** para crear uno en el momento, y use los controladores de arrastre para reordenar. Recuerde que el mismo Block puede aparecer más de una vez — se puede insertar un único Block de salto de página entre varias secciones.

![Editor de plantillas](images/pro_report_template_new.png)

### Paso 4: Generar y descargar

Cuando la Template esté lista, genere el informe. El cuadro de diálogo de generación confirma la Template y le permite elegir el formato de salida — **HTML** o **PDF**.

![Cuadro de diálogo de generación de informe](images/pro_generate_report_dialog.png)

Los informes generados se recopilan en la lista de Generated Reports, que muestra el estado de cada informe, el formato de archivo, el momento en que se solicitó y se completó, y un enlace de descarga.

![Lista de informes generados](images/pro_generated_reports_list.png)

Puede volver a ejecutar una Template en cualquier momento para producir un informe nuevo. Tenga en cuenta que cada Generated Report queda congelado en el tiempo — refleja sus datos a partir del momento en que se generó y no cambiará a medida que cambien los datos de DefectDojo, así que vuelva a ejecutar la Template cuando necesite una instantánea actualizada.

## Migración desde el motor de informes clásico

El motor de informes clásico — las páginas **Report Builder**, **Report Templates** y **Generated Reports** que aparecen bajo *Classic Report Engine* en la barra lateral — se elimina en la versión **3.3.0 (8 de septiembre de 2026)**. Hasta entonces, esas páginas muestran un aviso que recuerda la fecha, y tanto ellas como este generador de informes ofrecen una migración con un solo clic.

### Migración de sus plantillas guardadas

Use **Migrate to the new engine** en cualquier página clásica, o **Import from Classic Engine** en *All Report Templates* aquí. Ambas opciones ejecutan la misma conversión, por lo que no importa desde cuál comience, y ambas son seguras de ejecutar más de una vez: una plantilla clásica cuyo nombre ya existe aquí se informa como *already migrated* en lugar de duplicarse.

Cada widget clásico se convierte en un Block:

| Widget clásico | Se convierte en |
|----------------|---------|
| Cover Page | Block stock de página de portada |
| Table Of Contents | Block stock de índice |
| Page Break | Block stock de salto de página |
| Custom Content / WYSIWYG | Block de texto |
| Findings | Block Tabular sobre Hallazgos, que conserva los filtros del widget |
| Vulnerable Endpoints | Block Tabular sobre URLs |
| Severities | Block de gráfico de Hallazgos activos por Severity |

Dos no se trasladan, y la migración lo indica por plantilla en lugar de convertirlos en algo aproximado:

- **Executive Summary** — el motor clásico derivaba esto de los widgets de Findings que estuvieran en el mismo informe. No existe un Block agregado equivalente; reconstrúyalo como un Block de texto si lo necesita.
- **Report Options** — no es un Block. Su *Report name* se convierte en el nombre de la nueva Template. Finding notes, finding images y los saltos de página por widget son ajustes a nivel de Theme en el nuevo motor.

### Qué sucede con los informes que ya ha ejecutado

Nada. Los Generated Reports producidos por el motor clásico son archivos terminados, por lo que no hay nada que convertir. Permanecen listados y disponibles para descargar hasta que se elimine el motor — guarde todo lo que desee conservar más allá de la versión 3.3.0.

### Si el Report Builder está desactivado

La migración sigue funcionando con el feature flag **Reporting** desactivado. Las Templates convertidas simplemente no aparecen hasta que se vuelva a activar el indicador, así que puede trasladar sus plantillas según su propio calendario.

## Próximos pasos

- **[API del generador de informes](../report-builder-api/)** — automatice mediante scripts todo el flujo de trabajo (Themes, Blocks, Templates e Informes generados) para generar informes repetibles y automatizados.
- **[Generador de informes con un LLM](../report-builder-llm/)** — use la creación asistida por LLM para diseñar y construir informes de forma conversacional.
