---
title: Hallazgos
description: Información sobre los Hallazgos en DefectDojo OS
audience: opensource
weight: 5
---

Organizaciones	→ Activos → Compromisos → Tests → **HALLAZGOS**

## Descripción general

Los **Hallazgos** representan el nivel más bajo de la Jerarquía de Productos donde se rastrean y gestionan las vulnerabilidades individuales, y son la forma principal en que DefectDojo estandariza y guía el proceso de reporte y remediación de sus herramientas de seguridad. Independientemente de si una vulnerabilidad fue reportada en SonarQube, Acunetix o la herramienta personalizada de su equipo, los Hallazgos le permiten gestionar cada vulnerabilidad de la misma manera.

Ejemplos de Hallazgos incluyen:
- Cookie no marcada como HttpOnly
- Versión desactualizada (PHP)
- Evaluación de código fuera de banda (PHP)
- Versión desactualizada (MySQL)
- Código fuente de respaldo detectado
- Cross-Site Scripting ciego

Además de almacenar los datos de la vulnerabilidad y proporcionar un marco de remediación, DefectDojo también mejora sus Hallazgos de las siguientes maneras:
- Añadiendo automáticamente las puntuaciones EPSS relacionadas a un Hallazgo para describir su explotabilidad
- Traduciendo automáticamente la métrica de severidad de una herramienta de seguridad en una puntuación de Severidad para cada Hallazgo, lo que confiere un SLA al Hallazgo según la configuración de SLA de su Activo. Para más información sobre la configuración de SLA, haga clic [aquí](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content).

En general, los Hallazgos están diseñados para trabajar con la Jerarquía de Productos con el fin de estandarizar sus esfuerzos y aplicar un método coherente a cada Activo.

## Acceso a los Hallazgos

Se puede acceder a los Hallazgos desde la barra lateral. El submenú ofrece acceso a los Hallazgos abiertos y cerrados, a todos los Hallazgos (independientemente de su estado abierto o cerrado), a los [Hallazgos con riesgo aceptado](/triage_findings/findings_workflows/os__risk_acceptance/), así como a las Plantillas de Hallazgos. También se puede acceder a los Hallazgos individuales desde dentro del Test que los contiene.

![image](images/osfindings_ss1.png)

### Permisos

Todo Hallazgo pertenece a un Test, lo que permite a DefectDojo conservar qué escaneo o evaluación identificó originalmente la vulnerabilidad.

Dado que los Hallazgos pertenecen a Tests, el acceso a los Hallazgos está determinado por el acceso de un Usuario al Activo que contiene el Test. Los Tests no tienen listas de control de acceso independientes.

## Vista de Hallazgos
Las vistas de Hallazgo contienen una variedad de tablas para ayudar a interpretar de un vistazo el estado de un Hallazgo. Esto incluye:
- **Descripción general**
    - **ID**: El número de ID único de ese Hallazgo.
    - **Severidad**: La calificación de severidad de ese Hallazgo, que se aplica automáticamente.
        - Como se mencionó anteriormente, DefectDojo traduce automáticamente la métrica de severidad de una herramienta de seguridad en una puntuación de Severidad para cada Hallazgo, lo que confiere un SLA al Hallazgo según la configuración de SLA de su Activo.
    - **SLA**: La fecha de vencimiento prevista para la resolución del Hallazgo.
    - **Estado**: El estado del Hallazgo (p. ej., Activo, Verificado, Falso positivo, Duplicado, Fuera de alcance y En revisión por defecto).
    - **Tipo de Hallazgo**: Si el Hallazgo es Estático (SAST) o Dinámico (DAST).
    - **Fecha de descubrimiento**: La fecha en que se descubrió el Hallazgo.
    - **CWE**: La clasificación CWE del Hallazgo.
    - **ID de vulnerabilidad**: IDs de vulnerabilidades en avisos de seguridad asociados al Hallazgo (p. ej., CVE u otras fuentes).
    - **Encontrado por**: La herramienta que reveló el Hallazgo.
- **Hallazgos similares**: Otros Hallazgos dentro del mismo Activo que no son duplicados exactos pero tienen valores similares de ID de vulnerabilidad, CWE, file_path, número de línea, etc.
- **Historial de importación**: Lista de importaciones/reimportaciones que crearon/cerraron/reactivaron este Hallazgo en cualquier Test.
- **Endpoints/sistemas vulnerables**: Endpoints/Sistemas que el Hallazgo revela como vulnerables.
- **Descripción**: La descripción del Hallazgo (añadida automáticamente según el tipo de Hallazgo, o creada manualmente).
- **Mitigación**: Pasos sugeridos para mitigar.
- **Impacto**: Impacto potencial de dejar el Hallazgo sin resolver.
- **Pasos para reproducir**: Pasos para reproducir el Hallazgo.
- **Justificación de la severidad**: Descripción escrita de por qué se asoció una determinada calificación de Severidad al Hallazgo.
- **Referencias**: URL para hacer referencia cruzada a la descripción específica de la herramienta de escaneo de terceros del Hallazgo. Por ejemplo, las Referencias podrían ser enlaces a una entrada relevante en un catálogo de Hallazgos, o una única URL de aviso.
- **Notas**: Notas dejadas por los Usuarios relacionadas con el Hallazgo. Marcar una nota como Privada significará que no se incluirá en ningún informe generado que incluya el Hallazgo seleccionado.

## Datos de los Hallazgos

Los Hallazgos requieren los siguientes metadatos:
**Título**
**Fecha**
**Severidad**
**Descripción**

Además de los metadatos correspondientes a las tablas en la vista de un Hallazgo, los campos de metadatos opcionales incluyen:
- **Grupo**: Grupos de Hallazgos que incluyen el Hallazgo seleccionado.
- **Vector y puntuación CVSS3/CVSS4**: El vector y la puntuación CVSS3 y CVSS4 del Hallazgo seleccionado.
- **Pares de solicitud y respuesta**: Una copia del mensaje enviado por el cliente y la respuesta del servidor a la solicitud.
- **Endpoints a añadir**: Endpoints vulnerables que pueden verse afectados por el Hallazgo seleccionado y que no se reflejan en la lista anterior de sistemas/endpoints.
- **Puntuación y percentil EPSS**: Puntuación y percentil EPSS para el CVE.
- **Fecha de incorporación a KEV**: La fecha en que se añadió el Hallazgo al catálogo KEV.
- **Disponibilidad y versión de la corrección**: Define si existe una corrección disponible para la vulnerabilidad, y la versión del componente afectado en la que se implementó la corrección.
- **Usuario que solicitó una revisión de defecto**: Registra quién solicitó una revisión de defecto para el fallo en cuestión.
- **Número de línea**: Número de línea de origen del vector de ataque.
- **Ruta del archivo**: Archivos identificados que contienen el fallo.
- **Nombre y versión del componente**: Nombre y versión del componente afectado.
- **ID único de la herramienta**: ID técnico de la vulnerabilidad proveniente de la herramienta de origen.
- **ID de vulnerabilidad de la herramienta**: ID técnico no único proveniente de la herramienta de origen.
- **Objeto de origen, número de línea y ruta de archivo SAST**: Objeto de origen, número de línea y ruta de archivo del vector de ataque.
- **Objeto de destino SAST**: Objeto de destino del vector de ataque.
- **Número de repeticiones**: Número de repeticiones en la herramienta de origen cuando se encontraron y agregaron varias vulnerabilidades por el escáner.
- **Fecha de publicación**: Fecha en que se publicó el Hallazgo.
- **Servicio**: Servicios conectados (piezas autónomas de funcionalidad dentro de un Activo) que se ven afectados por el Hallazgo seleccionado. Cuando se completa, este campo se incluye en la coincidencia de deduplicación (es decir, los Hallazgos con campos de Servicio idénticos se deduplicarán).
- **Fecha y versión de remediación planificada**: La fecha en que está previsto remediar el Hallazgo, y la versión del componente afectado en la que se implementará la corrección.
- **Esfuerzo de corrección**: El nivel de esfuerzo que implica corregir el Hallazgo (p. ej., Baja, Media o Alta).
- **Etiquetas**: Cualquier etiqueta que se haya añadido al Hallazgo.

Los metadatos exactos disponibles dependerán del analizador/escáner que reveló el Hallazgo. Algunos proporcionan solo información básica como título y severidad, mientras que otros incluyen vectores CVSS, componentes vulnerables, endpoints, pares de solicitud/respuesta y otros metadatos específicos del escáner.

Estos metadatos mejoran el filtrado, los informes y la priorización en todo su programa de seguridad, permitiendo el seguimiento a largo plazo y el análisis de tendencias. Puede encontrar más detalles y descripciones de metadatos [aquí](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page).

### Deduplicación

DefectDojo incluye capacidades de deduplicación que ayudan a identificar y gestionar Hallazgos que representan la misma vulnerabilidad subyacente. A medida que se importan los resultados de escaneo desde una o más herramientas, DefectDojo utiliza una lógica de coincidencia configurable para identificar Hallazgos que representan la misma vulnerabilidad.

La deduplicación evita que la misma vulnerabilidad aparezca varias veces cuando es descubierta repetidamente por el mismo escáner o por escáneres diferentes, permitiendo que el historial de remediación permanezca vinculado a un único Hallazgo.

Puede encontrar más información sobre la deduplicación [aquí](/triage_findings/finding_deduplication/about_deduplication/).

### Reimportación

La función de Reimportación de DefectDojo permite actualizar los Hallazgos a medida que se importan nuevos resultados de escaneo. Cuando se reimporta un escaneo, DefectDojo compara los resultados entrantes con los Hallazgos existentes y actualiza los registros coincidentes en lugar de crear otros completamente nuevos. Esto preserva un contexto valioso, como los cambios de estado, el historial de remediación, los comentarios y la información de propiedad, proporcionando un registro continuo del ciclo de vida de un Hallazgo a lo largo de múltiples ciclos de testing.

Puede encontrar más información sobre la función de Reimportación [aquí](/import_data/import_intro/reimport/#main-content).

### Aceptaciones de riesgo

Las Aceptaciones de riesgo son un estado especial que se puede aplicar a los Hallazgos para documentar formalmente y operacionalizar la decisión de reconocerlos sin remediarlos de inmediato.

Puede encontrar más información sobre las Aceptaciones de riesgo [aquí](/triage_findings/findings_workflows/os__risk_acceptance/).

### Estados

Cada Hallazgo creado en DefectDojo tiene un Estado que comunica información relevante y ayuda a su equipo a llevar un seguimiento de su progreso en la resolución de problemas.

Puede encontrar más información sobre los Estados [aquí](/triage_findings/findings_workflows/finding_status_definitions/).

## Trabajar con Hallazgos

### Creación de Hallazgos

Si bien la mayoría de los Hallazgos se generan automáticamente mediante importaciones de escaneos e integraciones, DefectDojo también admite la creación manual de Hallazgos. Los Hallazgos manuales son útiles para rastrear vulnerabilidades y problemas de seguridad identificados mediante pruebas de penetración, revisiones de arquitectura, evaluaciones de cumplimiento, programas de bug bounty, compromisos con consultores u otras actividades que no producen salida de escáner.

Para crear un Hallazgo manualmente:
1. Navegue hasta el Test en el que desea añadir manualmente el Hallazgo, haga clic en el signo + Más y luego haga clic en **New Finding**.

![image](images/osfindings_ss2.png)

2. Esto abre el formulario New Finding, que puede completar con cualquier información relevante sobre su Hallazgo.

3. Seleccione **Add Another Finding** para añadir manualmente otro Hallazgo, o **Finished** para finalizar el proceso de creación manual del Hallazgo.

El Hallazgo aparecerá ahora dentro de la lista de Hallazgos contenidos en el Test original.

Es importante destacar que añadir manualmente un Hallazgo desde la barra superior creará automáticamente un Compromiso y un Test ad hoc para contener el nuevo Hallazgo, en lugar de añadirlo al Test que se está viendo actualmente (vea la imagen a continuación). Esto se debe a que la barra superior corresponde al Activo en su conjunto. Si desea añadir manualmente un Hallazgo a un Test específico ya existente, es mejor hacerlo desde dentro del propio Test, como se describe en los pasos 1-3 anteriores.

![image](images/osfindings_ss3.png)

### Edición de Hallazgos

#### Menú kebab ⋮

El menú kebab ⋮ junto a los Hallazgos contiene las siguientes funciones:
- **View**: Abre y visualiza el Hallazgo.
- **Edit**: Edita el Hallazgo.
- **Copy**: Crea una copia del Hallazgo. La copia se puede guardar en cualquiera de los Tests contenidos dentro del Compromiso correspondiente.
- **Request Peer Review**: Inicia el proceso de Revisión por Pares y cambia el estado del Hallazgo a “Under Review”. Puede encontrar más información sobre las Revisiones por Pares [aquí](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Touch Finding**: Registrará la interactividad con el Hallazgo en el historial del Hallazgo.
- **Make Finding a Template**: Creará automáticamente una Plantilla de Hallazgo basada en el Hallazgo seleccionado.
- **Apply Template to Finding**: Permitirá aplicar una Plantilla de Hallazgo ya existente a un Hallazgo.
- **Close Finding**: Iniciará el proceso de cierre del Hallazgo.
- **Add Risk Acceptance**: Iniciará el proceso de Aceptación de riesgo. Puede encontrar más información [aquí](/triage_findings/findings_workflows/os__risk_acceptance/#main-content).
- **View History**: Muestra el historial del Hallazgo seleccionado.
- **Delete**: Elimina el Hallazgo seleccionado.

#### Adjuntar archivos a los Hallazgos
Puede adjuntar archivos a cualquier Hallazgo para proporcionar contexto visual; por ejemplo, una captura de pantalla de una vulnerabilidad en acción o una imagen de prueba de concepto.

Los tipos de archivo admitidos incluyen:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Para adjuntar un archivo a un Hallazgo:
1. Abra el Hallazgo al que desea adjuntar un archivo.
2. Abra el menú de acciones (el botón ☰ en la parte superior derecha del Hallazgo) y haga clic en Manage Files.

![image](images/OS_manage_files_menu.png)

3. En la página Add files, introduzca un Título para el archivo y elija el archivo desde su ordenador. Puede añadir hasta tres archivos a la vez; guarde y vuelva para añadir más si es necesario.

![image](images/OS_manage_files_form.png)

4. Haga clic en **Save**.

El archivo se muestra entonces en el panel **Files** del Hallazgo. Los archivos de imagen aparecen como miniaturas:

![image](images/OS_finding_files_panel.png)

#### Edición masiva de Hallazgos

Los Hallazgos se pueden editar de forma masiva desde una lista de Hallazgos, como la tabla de All Findings accesible desde la barra lateral, o desde la tabla de Hallazgos dentro de un Test específico.

Puede encontrar más información sobre cómo editar Hallazgos de forma masiva [aquí](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings).

### Cierre de Hallazgos

Una vez completado el trabajo en un Hallazgo, puede cerrarlo manualmente haciendo clic en **Close Finding** dentro del menú kebab ⋮ o del menú de acciones ☰ del Hallazgo. Alternativamente, si se reimporta un escaneo en DefectDojo que no contiene un Hallazgo previamente registrado, ese Hallazgo se cerrará automáticamente.

Si no desea que se cierre ningún Hallazgo, puede deshabilitar este comportamiento en la Reimportación:

- Desmarque la casilla Close Old Findings si utiliza la UI
- Establezca close_old_findings en False si utiliza la API ​

### Eliminación de Hallazgos

La eliminación de un Hallazgo se puede realizar desde el menú kebab ⋮ o el menú de acciones ☰ del Hallazgo. Esta acción no se puede deshacer.

Por motivos de auditoría, se recomienda cerrar los Hallazgos remediados en lugar de eliminarlos.

## Grupos de Hallazgos

Los **Grupos de Hallazgos** le permiten tratar varios Hallazgos relacionados como una sola unidad lógica para la triaje, los informes y la coordinación de la remediación.

Por ejemplo, un escaneo podría producir 10 Hallazgos de inyección SQL en diferentes endpoints. En lugar de gestionar cada uno de forma independiente, puede agruparlos en un único Grupo de Hallazgos que represente el problema de inyección SQL más amplio.

Un Grupo de Hallazgos no reemplaza a los Hallazgos individuales. Cada Hallazgo sigue existiendo con su propia severidad, estado, metadatos, comentarios e historial de remediación. Un Grupo de Hallazgos simplemente proporciona una capa organizativa adicional por encima de los Hallazgos que contiene.

### Acceso a los Grupos de Hallazgos

Se puede acceder a los Grupos de Hallazgos desde la barra lateral. El submenú ofrece acceso a los Grupos de Hallazgos abiertos y cerrados, así como a todos los Grupos de Hallazgos (independientemente de su estado abierto).

![image](images/osfindings_ss1.png)

### Creación de Grupos de Hallazgos


Los Grupos de Hallazgos se pueden crear de forma manual o automática.

Cabe destacar que los Grupos de Hallazgos solo se pueden crear a partir de los Hallazgos contenidos dentro de un único Test. Los Hallazgos de diferentes Tests, Compromisos o Productos no se pueden añadir al mismo Grupo de Hallazgos.

#### Grupos de Hallazgos manuales

Para realizar acciones de Grupo de Hallazgos manualmente:
1. Navegue hasta una lista de Hallazgos dentro de un Test.
2. Seleccione el/los Hallazgo(s) que desea añadir a un Grupo de Hallazgos haciendo clic en la casilla correspondiente.
3. Haga clic en la casilla **Group**.
4. Haga clic en la acción correspondiente que desea completar.
    - **Create**: Crea un Grupo de Hallazgos que incluye los Hallazgos seleccionados.
    - **Add to**: Añade los Hallazgos seleccionados a un Grupo de Hallazgos ya existente.
    - **Remove from any group**: Elimina los Hallazgos seleccionados de cualquier Grupo de Hallazgos del que formaran parte anteriormente.
    - **Group by**: Agrupa los Hallazgos seleccionados según la opción elegida (p. ej., nombre de componente, ruta de archivo, título del Hallazgo, etc.)
5. Haga clic en **Submit**.

![image](images/osfindings_ss4.png)

Tenga en cuenta que la única acción posible al seleccionar Hallazgos desde la lista All Findings es eliminar los Hallazgos seleccionados de cualquier Grupo de Hallazgos. Esto se debe a que, como se mencionó, los Grupos de Hallazgos solo se pueden crear a partir de los Hallazgos contenidos dentro de un único Test.

#### Grupos de Hallazgos automáticos

Al importar un escaneo, la función “Group By” puede crear automáticamente Grupos de Hallazgos según un método de agrupación elegido. Esto es útil cuando un escáner produce muchos Hallazgos relacionados que deben gestionarse juntos.

La casilla adyacente **Create Finding Groups for all Findings** cumple dos funciones:
- **Marcada**: Crea un Grupo de Hallazgos para cada Hallazgo importado, incluso si ese Hallazgo es el único miembro del grupo.
- **Desmarcada**: Crea Grupos de Hallazgos solo cuando realmente hay varios Hallazgos que agrupar.

![image](images/osfindings_ss5.png)

Si no se selecciona ninguna opción en el menú desplegable Group By durante la importación, no se producirá ninguna agrupación.

Si el criterio de agrupación (p. ej., nombre de componente, ID de vulnerabilidad, etc.) no está completado en el Hallazgo, no se creará un grupo para él ni se añadirá a un Grupo de Hallazgos ya existente.

Si se importa un escaneo que revela 10 Hallazgos que no están agrupados, y se reimporta el mismo escaneo y los Hallazgos se agrupan, los primeros 10 Hallazgos no se añadirán a ese Grupo de Hallazgos (es decir, el Grupo de Hallazgos solo incluirá los 10 Hallazgos de la reimportación, no los 10 Hallazgos de la importación inicial y las subsiguientes).

## Plantillas de Hallazgos

Las **Plantillas de Hallazgos** permiten a los Usuarios crear plantillas reutilizables para vulnerabilidades y problemas de seguridad reportados habitualmente. Una plantilla puede incluir información estandarizada como título, descripción, impacto, pasos para reproducir, mitigación, referencias y otros metadatos del Hallazgo.

Las Plantillas de Hallazgos son más útiles en situaciones donde los Usuarios necesitan crear Hallazgos manuales repetidamente y quieren evitar volver a introducir la misma información de respaldo cada vez.

### Acceso a las Plantillas de Hallazgos

Las Plantillas de Hallazgos se encuentran dentro del submenú de Hallazgos en la barra lateral.

![image](images/osfindings_ss6.png)

### Creación de Plantillas de Hallazgos

Las Plantillas de Hallazgos se pueden crear haciendo clic en el botón + Más en la parte superior derecha de la vista Finding Templates.

La página resultante ofrece una visión general de los metadatos que se aplicarán a un Hallazgo cuando se utilice una Plantilla de Hallazgo.

También puede usar un Hallazgo ya existente como base para una nueva Plantilla de Hallazgo haciendo clic en **Make Finding a Template** dentro del menú kebab ⋮ del Hallazgo.

### Aplicación de Plantillas de Hallazgos

Las Plantillas de Hallazgos se pueden aplicar a los Hallazgos haciendo clic en el botón **Apply Template to Finding** dentro del menú kebab ⋮ del Hallazgo seleccionado.

![image](images/osfindings_ss7.png)

La página resultante le permitirá seleccionar la plantilla que se aplicará al Hallazgo en cuestión, y luego decidir si mantener, reemplazar o combinar los metadatos del Hallazgo con los de la plantilla.

### Informes

El generador de informes de DefectDojo le permite ensamblar un informe personalizado a partir de un conjunto de widgets de contenido, ejecutarlo y exportar el resultado (por ejemplo, imprimiéndolo en PDF). Los informes personalizados pueden resumir los Hallazgos o Endpoints que desea compartir con una audiencia externa, y pueden incluir branding y texto estándar.

Puede encontrar más información sobre el Generador de Informes de DefectDojo [aquí](/metrics_reports/reports/using-the-report-builder/).

#### Exportar Hallazgos

Las páginas que muestran una lista de Hallazgos o una lista de Compromisos tienen una opción de exportación a CSV y Excel en el menú desplegable de la parte superior derecha.

Desde cualquier página de lista de Hallazgos, abra el menú desplegable en la esquina superior derecha para exportar los Hallazgos visibles como archivo CSV o Excel. La lista de Compromisos también se puede exportar como CSV o Excel utilizando el mismo menú desplegable en la página de lista de Compromisos.
