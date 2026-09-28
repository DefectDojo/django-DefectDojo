---
title: Uso del generador de informes
description: Cree, ejecute y obtenga un informe personalizado en DefectDojo de código
  abierto
draft: false
audience: opensource
weight: 24
slug: using-the-report-builder
aliases:
- /es/en/share_your_findings/pro_reports/working_with_generated_reports
- /es/metrics_reports/reports/working_with_generated_reports
---

DefectDojo's report builder lets you assemble a custom report from a set of content widgets, run it, and export the result (for example, by printing it to PDF). Custom reports can summarize the Findings or Endpoints you want to share with an external audience, and can include branding and boilerplate text.

> **Nota:** En DefectDojo de código abierto, usted crea un informe, lo ejecuta y obtiene su resultado como un esfuerzo puntual. Los diseños de informe (plantillas) y la salida del informe generado **no se guardan** en la versión de código abierto. Para reutilizar un diseño, debe reconstruirlo en el generador de informes. Para guardar Temas, Bloques y Plantillas reutilizables, y para mantener un historial persistente de los informes generados, consulte el [Generador de informes](../report-builder/) de DefectDojo Pro.

## Apertura del generador de informes

El generador de informes se puede abrir desde la página **📄 Informes** en la barra lateral.

![image](images/Using_the_Report_Builder.png)

La página del generador de informes está organizada en dos columnas. La columna izquierda **Formato del informe** es donde se diseña el informe, usando los widgets de la columna derecha **Widgets disponibles**.

![image](images/Using_the_Report_Builder_2.png)

## Paso 1: Configurar las opciones del informe

![image](images/Using_the_Report_Builder_3.png)

Desde la sección Opciones del informe, puede realizar las siguientes acciones:

* Establecer un **Nombre del informe** para el informe
* Incluir **Notas de hallazgos** creadas por el usuario en el informe
* Incluir **Imágenes de hallazgos** en el informe
* Cargar una **Imagen** de encabezado en el informe

### Seleccionar una imagen de encabezado para su informe

Para agregar una imagen en la parte superior de su informe, haga clic en el botón **Elegir archivo** y cargue una imagen en DefectDojo.

La imagen se redimensionará automáticamente para ajustarse al documento, y se representará directamente encima de su **Nombre del informe**.

![image](images/Using_the_Report_Builder_4.png)

## Paso 2: Agregar contenido con widgets

Una vez que haya configurado las opciones del informe, puede comenzar a diseñar su informe utilizando los widgets de DefectDojo.

Los widgets son elementos de contenido de un informe que se agregan arrastrándolos y soltándolos en la columna **Formato del informe**. El informe final se generará según la posición de cada widget, con el **Nombre del informe** y la **Imagen de encabezado** representados en la parte superior.

* Los elementos de su informe se pueden reordenar arrastrando y soltando los widgets en un nuevo orden.
* Para eliminar un widget de un informe, haga clic y arrástrelo de vuelta a la columna derecha.
* Los widgets también se pueden contraer haciendo clic en el encabezado gris, para facilitar la navegación por el generador de informes.
* El widget de Hallazgos, el widget WYSIWYG y el widget de Endpoints se pueden usar cada uno más de una vez.

Para obtener más información sobre los widgets de informe, consulte el [Índice de widgets de informe](./#report-widget-index).

## Paso 3: Ejecutar y ver el informe

Una vez que haya terminado de crear su informe, puede generarlo haciendo clic en el botón verde **Ejecutar** en la parte inferior de la sección **Formato del informe**.

DefectDojo genera el informe a partir de los widgets que ensambló. Cuando finaliza la generación, puede ver el informe HTML resultante en su navegador.

![image](images/Using_the_Report_Builder_14.png)

Un informe generado es una instantánea de un momento determinado: refleja los datos de DefectDojo en el momento en que se ejecutó y no se actualiza automáticamente a medida que cambian sus datos.

## Paso 4: Exportar el informe

Los informes están configurados para que puedan exportarse o imprimirse fácilmente.

El método más sencillo es imprimir a PDF. Con el informe HTML abierto, abra un cuadro de diálogo de **Impresión** en su navegador y establezca **Guardar como PDF** como **Destino de impresión**.

![image](images/Using_the_Report_Builder_15.png)

## Sugerencias de formato del informe

* Las secciones WYSIWYG se pueden usar para contextualizar o resumir listas de hallazgos. Considere usar este widget a lo largo de su informe, entre los widgets de Hallazgos o Endpoints vulnerables.

## Índice de widgets de informe

### Widget de página de portada

El widget de página de portada le permite establecer un encabezado, un subencabezado y metadatos adicionales para su informe. Solo puede tener una única página de portada por informe.

![image](images/Using_the_Report_Builder_5.png)

### Widget de resumen ejecutivo

El widget de resumen ejecutivo está pensado para resumir su informe de un vistazo. Contiene un encabezado (por defecto, Resumen ejecutivo), así como un cuadro de texto que puede contener cualquier información que considere necesaria para resumir el informe.

![image](images/Using_the_Report_Builder_6.png)

También puede **incluir los SLA** en su resumen ejecutivo. Para agregar imágenes, formato de marcado o cualquier cosa más allá de texto puro, considere agregar un **widget de contenido WYSIWYG** inmediatamente después del resumen ejecutivo.

* Solo puede tener un único resumen ejecutivo por informe.
* Si su informe contiene varias configuraciones de SLA (por ejemplo, tiene Hallazgos de Productos distintos que tienen cada uno sus propios estándares de SLA), cada configuración de SLA se listará en el Resumen ejecutivo como una fila independiente.

### Widget de severidades

Dado que cada organización tendrá definiciones diferentes para cada nivel de severidad, el widget de severidades le permite definir los niveles de severidad utilizados en su informe para facilitar su comprensión.

![image](images/Using_the_Report_Builder_7.png)

### Widget de índice

El widget de índice crea una lista de cada Hallazgo en su informe, para un acceso más rápido a Hallazgos específicos. El índice crea un encabezado independiente para cada severidad contenida en el informe. Cada Hallazgo listado en el índice tiene un enlace de anclaje adjunto para saltar rápidamente al Hallazgo en el informe.

![image](images/Using_the_Report_Builder_8.png)

* Puede agregar una sección de **Contenido personalizado**, que añadirá texto debajo del encabezado.
* Puede cargar una imagen al índice haciendo clic en el botón **Elegir archivo** junto a la línea **Imagen**. La imagen cargada se representará directamente encima del encabezado seleccionado. Las imágenes se redimensionarán para ajustarse al documento.

### Widget de contenido WYSIWYG

El widget WYSIWYG (What You See Is What You Get, «lo que ve es lo que obtiene») se puede usar para agregar una sección que contenga texto e imágenes en su informe. Se pueden agregar varias copias de este widget para proporcionar contexto a otras secciones de su informe.

![image](images/Using_the_Report_Builder_9.png)

* El contenido WYSIWYG puede incluir un encabezado opcional.
* Se pueden agregar imágenes a un widget WYSIWYG arrastrándolas y soltándolas directamente en el cuadro **Contenido**. Las imágenes insertadas en el cuadro Contenido se representarán a su resolución completa.
* Puede agregar varios widgets WYSIWYG a un informe.

### Widget de hallazgos

El widget de hallazgos proporciona una lista y un resumen de cada Hallazgo que desee incluir en su informe. Puede establecer el alcance de los Hallazgos que desea incluir mediante filtros.

El widget de hallazgos se divide en dos secciones. La sección superior contiene una lista de filtros que se pueden usar para determinar qué Hallazgos desea incluir, y la sección inferior contiene la lista resultante de Hallazgos después de aplicar los filtros.

Para aplicar filtros a su widget de hallazgos, configure los parámetros de filtro y haga clic en el botón **Aplicar filtro** en la parte inferior. Puede obtener una vista previa de los resultados de su filtro consultando la lista de Hallazgos ubicada debajo de la sección Filtros.

![image](images/Using_the_Report_Builder_10.png)

* Al igual que con los widgets, la sección Filtros se puede expandir y contraer haciendo clic en el encabezado gris Filtros.
* Puede agregar varios widgets de hallazgos independientes a su informe con distintos parámetros de filtro si desea que el informe contenga más de una lista de Hallazgos.
* Solo se incluyen en estos listados los Hallazgos que usted está autorizado a ver, de acuerdo con el Control de acceso basado en roles.

#### Ejemplo de lista de hallazgos renderizada

![image](images/Using_the_Report_Builder_11.png)

### Widget de endpoints vulnerables

El widget de endpoints vulnerables es similar al widget de hallazgos. Puede usar este widget para listar todos los Hallazgos de Endpoints específicos, y ordenar la lista de Hallazgos por Endpoint en lugar de por nivel de severidad.

El widget **Endpoints vulnerables** lista cada Hallazgo activo para los Endpoints seleccionados. En lugar de crear una única lista de Hallazgos sin ordenar, esta función los separa según su contexto de Endpoint.

Al igual que el widget de hallazgos, el widget de endpoints vulnerables se divide en una sección de filtros y una lista de Endpoints resultantes según los parámetros de filtro.

![image](images/Using_the_Report_Builder_12.png)

Seleccione aquí los parámetros para los Endpoints que desea incluir y haga clic en el botón **Aplicar hallazgos** en la parte inferior. Puede obtener una vista previa de los resultados de su filtro consultando la lista de Endpoints ubicada debajo de la sección Filtros.

* Puede agregar varios widgets de endpoints vulnerables independientes a su informe con distintos parámetros de filtro si desea que el informe contenga más de una lista.
* Solo se incluyen en estos listados los Hallazgos que usted está autorizado a ver, de acuerdo con el Control de acceso basado en roles.

### Widget ---- (separador)

Este widget representa una línea horizontal gris claro para dividir las secciones.

![image](images/Using_the_Report_Builder_13.png)
