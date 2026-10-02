---
title: Hallazgos
description: Cómo funcionan los Hallazgos en DefectDojo Pro
audience: pro
weight: 5
---

Organizations	→ Activos → Compromisos → Tests → **HALLAZGOS**

## Descripción general
Los **Hallazgos** representan el nivel más bajo de la Jerarquía de Productos, donde se rastrean y gestionan las vulnerabilidades individuales, y constituyen la forma principal en que DefectDojo estandariza y guía el proceso de generación de informes y remediación de sus herramientas de seguridad. Independientemente de si una vulnerabilidad fue reportada en SonarQube, Acunetix o la herramienta personalizada de su equipo, los Hallazgos le permiten gestionar cada vulnerabilidad de la misma manera.

Ejemplos de Hallazgos incluyen:
- **Cookie no marcada como HttpOnly**
- **Versión desactualizada (PHP)**
- **Evaluación de código fuera de banda (PHP)**
- **Versión desactualizada (MySQL)**
- **Código fuente de respaldo detectado**
- **Cross-Site Scripting ciego**

Además de almacenar los datos de la vulnerabilidad y proporcionar un marco de remediación, DefectDojo también mejora sus Hallazgos de las siguientes maneras:
- Agregar automáticamente las puntuaciones EPSS relacionadas a un Hallazgo para describir su explotabilidad
- Traducir automáticamente la métrica de severidad de una herramienta de seguridad en una puntuación de Severidad para cada Hallazgo, lo que otorga un SLA al Hallazgo según la configuración de SLA de su Activo. Para obtener más información sobre la configuración de SLA, haga clic [aquí](/asset_modelling/pro_hierarchy/priority_sla/#working-with-slas).

En general, los Hallazgos están diseñados para funcionar junto con la Jerarquía de Productos, con el fin de estandarizar sus esfuerzos y aplicar un método coherente a cada Activo.

## Acceso a los Hallazgos
Se puede acceder a los Hallazgos desde la barra lateral. El submenú brinda acceso a los Hallazgos Activos y Mitigados, a Todos los Hallazgos (independientemente de su estado Abierto o Cerrado), a los Grupos de Hallazgos, a las Plantillas de Hallazgos y al flujo de trabajo de Nuevo Hallazgo. También se puede acceder a los Hallazgos individuales desde dentro del Test que los contiene.

[Hallazgos con Riesgo aceptado] (/triage_findings/findings_workflows/os__risk_acceptance/) son accesibles desde la sección **Risk Acceptances** de la barra lateral.

![image](images/profindings_ss1.png)

### Permisos
Cada Hallazgo pertenece a un Test, lo que permite a DefectDojo conservar qué análisis o evaluación identificó originalmente la vulnerabilidad.

Dado que los Hallazgos pertenecen a Tests, el acceso a los Hallazgos está determinado por el acceso de un Usuario al Activo que contiene el Test. Los Tests no tienen listas de control de acceso independientes.

## Vista de Hallazgos
Las vistas de Hallazgos contienen una variedad de tablas que ayudan a interpretar de un vistazo el estado de un Hallazgo.

### Resumen del Hallazgo
- **Description**: La descripción del Hallazgo (agregada automáticamente según el tipo de Hallazgo, o creada manualmente).
- **Mitigation**: Pasos sugeridos para mitigar.
- **General Mitigation Policy**: La política de mitigación estandarizada para el Hallazgo seleccionado.
Las políticas de mitigación se pueden consultar y editar en la barra lateral, en **Configuration** → **Mitigation Policies**.
- **Impact**: El impacto potencial de dejar el Hallazgo sin resolver.
- **References**: URL para hacer referencia cruzada a la descripción específica del Hallazgo proporcionada por la herramienta de análisis de terceros. Por ejemplo, las Referencias podrían ser enlaces a una entrada relevante en un catálogo de Hallazgos, o una única URL de un aviso.
- **Files**: Cualquier archivo que se haya agregado para contextualizar el Hallazgo.
- **Notes**: Notas dejadas por los Usuarios relacionadas con el Hallazgo. Marcar una nota como Privada implica que no se incluirá en ningún informe generado que contenga el Hallazgo seleccionado.

### Metadatos
- **ID**: El ID único del Hallazgo en DefectDojo.
- **Organization, Asset, Engagement, and Test**: Los objetos principales del Hallazgo seleccionado.
- **Status**: El estado del Hallazgo (por ejemplo, Activo, Verificado, Falso positivo, Duplicado, Fuera de alcance y En revisión de defecto).
- **Severity**: La calificación de severidad de ese Hallazgo, que se aplica automáticamente.
    - Como se mencionó anteriormente, DefectDojo traduce automáticamente la métrica de severidad de una herramienta de seguridad en una puntuación de Severidad para cada Hallazgo, lo que otorga un SLA al Hallazgo según la configuración de SLA de su Activo.
- **Risk**: Un sistema de clasificación de 4 niveles que tiene en cuenta la explotabilidad de un Hallazgo y se aplica automáticamente.
    - Puede encontrar detalles sobre cómo se calculan la prioridad, el riesgo y los SLA [aquí](/asset_modelling/pro_hierarchy/priority_sla/#main-content). Puede encontrar más detalles sobre las definiciones de estado y nivel de riesgo de los Hallazgos [aquí](/triage_findings/findings_workflows/finding_status_definitions/).
- **Priority**: Un rango numérico calculado que se aplica a todos los Hallazgos y que le permite comprender rápidamente las vulnerabilidades en su contexto.
- **Age**: Cuánto tiempo lleva abierto el Hallazgo seleccionado.
- **SLA**: La fecha límite en la que se espera que el Hallazgo esté resuelto.
- **Type**: Si el Hallazgo fue detectado por una herramienta de seguridad de aplicaciones estática o dinámica (Estático, Dinámico o Estático/Dinámico).
- **Location and Line**: El archivo y el número de línea en los que se encontró el Hallazgo seleccionado.
- **Component Name and Version**: El nombre y la versión del componente en el que se encontró el Hallazgo seleccionado.
- **Date Discovered**: La fecha en la que se descubrió el Hallazgo.
- **Planned Remediation Date and Version**: La fecha en la que está previsto remediar el Hallazgo, y la versión del componente afectado en la que se implementará la corrección.
- **Service**: Los Servicios conectados (partes autónomas de funcionalidad dentro de un Activo) que se ven afectados por el Hallazgo seleccionado. Cuando está completo, este campo se incluye en la coincidencia de deduplicación (es decir, los Hallazgos con campos de Servicio idénticos se deduplicarán).
- **Reporter**: El Usuario que reveló el Hallazgo.
- **CWE**: La clasificación de debilidad CWE del Hallazgo. Un Hallazgo puede tener **múltiples CWE** — un CWE principal, más cualquier CWE adicional proporcionado por la herramienta de reporte. El CWE principal es el que se utiliza para la deduplicación heredada y el cálculo del código hash; el conjunto completo de CWE también se puede utilizar para la coincidencia mediante los Campos de código hash basados en conjuntos de Pro (consulte [Deduplication Tuning](/triage_findings/finding_deduplication/pro__deduplication_tuning/#set-based-hash-code-fields-vulnerability-ids-and-cwes)).
    - Un CWE describe una *clase* de debilidad (por ejemplo, "Inyección SQL"), no una instancia específica de vulnerabilidad — para eso están los ID de vulnerabilidad.
- **Vulnerability IDs**: Identificadores de vulnerabilidad reconocidos públicamente y asociados con el Hallazgo, como CVE, GHSA u otras referencias de asesorías estandarizadas. En DefectDojo Pro, también se utilizan para realizar búsquedas de EPSS y KEV.
    - Los ID de vulnerabilidad se almacenan como registros de primera clase, por lo que el mismo CVE se rastrea una sola vez y es compartido por todos los Hallazgos que lo referencian. Puede revisarlos — junto con sus valores de EPSS y KEV — en el **Vulnerability Explorer**. Consulte [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/#viewing-kevepss-in-the-vulnerability-explorer).
- **Unique ID From Tool**: Un identificador estable asignado por la herramienta de origen a una instancia específica de Hallazgo. Los ID únicos están diseñados para mantenerse consistentes a través de análisis repetidos, lo que permite que la herramienta reconozca el mismo Hallazgo a lo largo del tiempo.
    - A diferencia de los ID de vulnerabilidad, este valor es propio de la herramienta de reporte y no es una referencia pública de vulnerabilidad.
        - Ejemplo: `finding-12345`
- **Vulnerability ID From Tool**: Un identificador de vulnerabilidad o regla propio, asignado por la herramienta de origen para describir el tipo de vulnerabilidad detectada.
    - A diferencia del ID único de la herramienta, este identificador no es exclusivo de un Hallazgo individual y puede aparecer en muchos Hallazgos que coincidan con la misma regla de detección.
    - A diferencia de los ID de vulnerabilidad, estos identificadores son específicos de la herramienta de reporte y no están estandarizados públicamente.
        - Ejemplo: `semgrep.rule.lang.security.sql-injection`
- **EPSS Score / Percentile**: Puntuación y percentil EPSS para el CVE.
- **Known Exploited**: Si existe confirmación de que la vulnerabilidad ha sido explotada.
- **Ransomware Used**: Si se utilizó ransomware en la explotación de la vulnerabilidad.
- **KEV Date**: La fecha en la que el Hallazgo se agregó al catálogo KEV.
- **Found By**: El tipo de herramienta que identificó la vulnerabilidad.
- **CVSSv3 and CVSSv4 Vector and Score**: El vector y la puntuación CVSS3 y CVSS4 del Hallazgo seleccionado.
- **Integrator Tickets**: Números de ticket de sistemas de seguimiento de incidencias de terceros asociados con el Hallazgo.

### Endpoints vulnerables
Esta sección incluye una tabla de los Endpoints afectados por el Hallazgo seleccionado, junto con cualquier metadato relevante.

### Detalles adicionales
- **Request/Response Pairs**: Una copia del mensaje enviado por el cliente y la respuesta del servidor a la solicitud.
- **Steps to Reproduce**: Pasos para reproducir el Hallazgo.
- **Severity Justification**: Descripción escrita de por qué se asoció una determinada calificación de Severidad al Hallazgo.

## Datos de los Hallazgos
Los Hallazgos requieren los siguientes metadatos:
- **Name**
- **Date**
- **Severity**
- **Description**

Además de los metadatos correspondientes a las tablas en la vista de un Hallazgo, los campos de metadatos opcionales incluyen:
- **Tags**: Cualquier etiqueta que se haya agregado al Hallazgo.
- **Owners**: El grupo de usuarios que será responsable del Hallazgo seleccionado.
- **Push to Jira**: Envía el Hallazgo a Jira con fines de creación de tickets.
- **Push to Integrator**: Envía el Hallazgo a cualquier sistema de seguimiento de incidencias de terceros integrado.
- **Risk and priority settings**: Ofrece la opción de anular el cálculo automático que hace DefectDojo del riesgo y la prioridad del Hallazgo.
- **Endpoints to add**: Endpoints vulnerables que pueden verse afectados por el Hallazgo seleccionado y que no están reflejados en la lista anterior de sistemas/endpoints.
- **Defect review requested by**: Registra quién solicitó una revisión de defecto para el fallo en cuestión.
- **SAST source object, line number, and file path**: Objeto de origen, número de línea y ruta de archivo del vector de ataque.
- **SAST sink object**: Objeto de destino del vector de ataque.
- **Number of occurrences**: Número de ocurrencias en la herramienta de origen cuando el escáner encontró y agregó varias vulnerabilidades.
- **Publish date**: La fecha en la que se publicó la vulnerabilidad.
- **Effort estimation**: El nivel de esfuerzo que implica corregir el Hallazgo (por ejemplo, Baja, Media o Alta).

Los metadatos exactos disponibles dependerán del parser/escáner que reveló el Hallazgo. Algunos solo proporcionan información básica, como el título y la severidad, mientras que otros incluyen vectores CVSS, componentes vulnerables, endpoints, pares de solicitud/respuesta y otros metadatos específicos del escáner.

Estos metadatos mejoran el filtrado, la generación de informes y la priorización en todo su programa de seguridad, lo que permite el seguimiento a largo plazo y el análisis de tendencias. Puede encontrar detalles adicionales y descripciones de metadatos [aquí](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page).

### Deduplicación
DefectDojo incluye capacidades de deduplicación que ayudan a identificar y gestionar los Hallazgos que representan la misma vulnerabilidad subyacente. A medida que se importan los resultados de análisis desde una o más herramientas, DefectDojo utiliza una lógica de coincidencia configurable para identificar los Hallazgos que representan la misma vulnerabilidad.

La deduplicación evita que la misma vulnerabilidad aparezca varias veces cuando es descubierta repetidamente por el mismo escáner o por escáneres distintos, lo que permite que el historial de remediación permanezca vinculado a un único Hallazgo.

Puede encontrar más información sobre la deduplicación [aquí](/triage_findings/finding_deduplication/about_deduplication/).

### Reimportación
La función de Reimportación de DefectDojo permite actualizar los Hallazgos a medida que se importan nuevos resultados de análisis. Cuando se reimporta un análisis, DefectDojo compara los resultados entrantes con los Hallazgos existentes y actualiza los registros coincidentes en lugar de crear otros completamente nuevos. Esto conserva contexto valioso, como cambios de estado, historial de remediación, comentarios e información de propiedad, proporcionando un registro continuo del ciclo de vida de un Hallazgo a través de múltiples ciclos de prueba.

Puede encontrar más información sobre la función de Reimportación [aquí](/import_data/import_intro/reimport/).

### Aceptaciones de riesgo
Las Aceptaciones de riesgo son un estado especial que se puede aplicar a los Hallazgos para documentar formalmente y operacionalizar la decisión de reconocerlos sin remediarlos de inmediato.

Puede encontrar más información sobre las Aceptaciones de riesgo [aquí](/triage_findings/findings_workflows/pro__risk_acceptance/).

### Estados
Cada Hallazgo creado en DefectDojo tiene un Estado que comunica información relevante y ayuda a su equipo a hacer seguimiento del progreso en la resolución de los problemas.

Puede encontrar más información sobre los Estados [aquí](/triage_findings/findings_workflows/finding_status_definitions/).

## Cómo trabajar con los Hallazgos

### Creación de Hallazgos
Si bien la mayoría de los Hallazgos se generan automáticamente mediante importaciones de análisis e integraciones, DefectDojo también admite la creación manual de Hallazgos. Los Hallazgos manuales son útiles para rastrear vulnerabilidades y problemas de seguridad identificados mediante pruebas de penetración, revisiones de arquitectura, evaluaciones de cumplimiento, programas de recompensas por errores, compromisos con consultores, u otras actividades que no producen salida de un escáner.

Los Hallazgos se pueden agregar manualmente haciendo clic en **New Finding** dentro de la sección **Findings** de la barra lateral, o seleccionando **Add Finding** dentro del menú de engranaje del Test al que desea agregar el Hallazgo.

### Edición de Hallazgos
El menú kebab ⋮ junto a los Hallazgos contiene las siguientes funciones:
- **Edit Finding**: Edita el Hallazgo.
- **Copy Finding**: Crea una copia del Hallazgo en otro Test. La copia se puede guardar en cualquier Test dentro del mismo Compromiso para el que tenga permiso de edición. Copiar es útil cuando la misma vulnerabilidad debe rastrearse por separado en más de un contexto de Test.
- **Close Finding**: Inicia el proceso de cierre del Hallazgo.
- **Request Review**: Inicia el proceso de Revisión por pares y cambia el estado del Hallazgo a "Under Review." Puede encontrar más información sobre las Revisiones por pares [aquí](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Add Risk Acceptance**: Inicia el proceso de Aceptación de riesgo. Puede encontrar más información [aquí](/triage_findings/findings_workflows/pro__risk_acceptance/).
- **Add File**: Inicia el proceso para agregar un archivo al Hallazgo (consulte la sección a continuación).
- **Add Note**: Inicia el proceso para agregar una nota al Hallazgo.
- **Add Custom Field**: Abre una ventana emergente que le permite agregar y definir un campo personalizado para aplicar al Hallazgo.
- **Push to Jira**: Envía el Hallazgo a Jira con fines de creación de tickets.
- **Push to Integrator**: Envía el Hallazgo a cualquier sistema de seguimiento de incidencias de terceros integrado.
- **Delete Finding**: Elimina el Hallazgo seleccionado.
- **Finding History**: Muestra el historial del Hallazgo seleccionado.

#### Adjuntar archivos a los Hallazgos
Puede adjuntar archivos a cualquier Hallazgo para proporcionar contexto adicional — por ejemplo, una captura de pantalla de una vulnerabilidad en acción o una imagen de prueba de concepto.

Los tipos de archivo admitidos incluyen:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Para adjuntar un archivo a un Hallazgo, haga clic en **Add File** desde el menú kebab ⋮ o el menú de engranaje del Hallazgo seleccionado. Ingrese un Título para el archivo, elija el archivo desde su computadora y haga clic en **Submit**.

El archivo aparecerá entonces en la sección Files de la tabla **Test Overview** dentro de la vista del Hallazgo.

#### Edición masiva de Hallazgos
Los Hallazgos se pueden editar de forma masiva desde una Lista de Hallazgos, como la tabla de Todos los Hallazgos accesible desde la barra lateral, o desde la tabla de Hallazgos dentro de un Test específico.

Puede encontrar más información sobre cómo editar Hallazgos de forma masiva [aquí](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings).

### Cierre de Hallazgos
Una vez que el trabajo sobre un Hallazgo está completo, puede cerrarlo manualmente haciendo clic en **Close Finding** dentro del menú kebab ⋮ o el menú de engranaje del Hallazgo. Alternativamente, si se reimporta un análisis en DefectDojo que no contiene un Hallazgo previamente registrado, ese Hallazgo se cerrará automáticamente.

Si no desea que se cierre ningún Hallazgo, puede deshabilitar este comportamiento en el formulario de Reimport Scan:

- Desmarque la casilla Close Old Findings si utiliza la interfaz de usuario
- Establezca close_old_findings en False si utiliza la API ​

### Eliminación de Hallazgos
Se puede eliminar un Hallazgo desde el menú kebab ⋮ o el menú de engranaje del Hallazgo. Esta acción no se puede deshacer.

Para fines de auditoría, se recomienda cerrar los Hallazgos remediados en lugar de eliminarlos.

## Grupos de Hallazgos
Los **Grupos de Hallazgos** le permiten tratar varios Hallazgos relacionados como una única unidad lógica para la clasificación, la generación de informes y la coordinación de la remediación.

Por ejemplo, un análisis podría producir 10 Hallazgos de inyección SQL en diferentes endpoints. En lugar de gestionar cada uno de forma independiente, puede agruparlos en un único Grupo de Hallazgos que represente el problema general de inyección SQL.

Un Grupo de Hallazgos no reemplaza a los Hallazgos individuales. Cada Hallazgo sigue existiendo con su propia severidad, estado, metadatos, comentarios e historial de remediación. Un Grupo de Hallazgos simplemente proporciona una capa organizativa adicional sobre los Hallazgos que contiene.

### Acceso a los Grupos de Hallazgos
Se puede acceder a los Grupos de Hallazgos desde la barra lateral. El submenú brinda acceso a los Grupos de Hallazgos Abiertos y Cerrados, así como a Todos los Grupos de Hallazgos (independientemente de su estado Abierto).

![image](images/profindings_ss1.png)

### Creación de Grupos de Hallazgos
Los Grupos de Hallazgos se pueden crear de forma manual o automática.

Cabe destacar que los Grupos de Hallazgos solo se pueden crear a partir de los Hallazgos contenidos en un único Test. Los Hallazgos de diferentes Tests, Compromisos o Productos no se pueden agregar al mismo Grupo de Hallazgos.

#### Grupos de Hallazgos manuales
Para realizar acciones de Grupo de Hallazgos de forma manual:
1. Navegue hasta una lista de Hallazgos dentro de un Test.
2. Seleccione el/los Hallazgo(s) que desea agregar a un Grupo de Hallazgos haciendo clic en la casilla correspondiente del Hallazgo.
3. Haga clic en el botón **Finding Group** que aparece en la parte superior de la lista de Hallazgos.
4. Haga clic en la acción correspondiente que desea completar.
    - **Add to New Finding Group**: Crea un nuevo Grupo de Hallazgos que incluye los Hallazgos seleccionados.
    - **Add to Existing Finding Group**: Agrega los Hallazgos seleccionados a un Grupo de Hallazgos preexistente.
    - **Remove from Finding Group**: Elimina los Hallazgos seleccionados de cualquier Grupo de Hallazgos del que formaran parte anteriormente.
5. Haga clic en **Submit**.

Tenga en cuenta que la agrupación estará deshabilitada a menos que todos los Hallazgos seleccionados sean editables, no estén agrupados y pertenezcan al mismo Test.

Además, tenga en cuenta que la única acción posible al seleccionar Hallazgos desde la lista Todos los Hallazgos es eliminarlos de cualquier Grupo de Hallazgos. Esto se debe a que, como se mencionó, los Grupos de Hallazgos solo se pueden crear a partir de los Hallazgos contenidos en un único Test.

#### Grupos de Hallazgos automáticos
Al importar un análisis, la función **Group By** dentro del menú desplegable **Optional Fields** puede crear automáticamente Grupos de Hallazgos según el método de agrupación elegido. Esto es útil cuando un escáner produce muchos Hallazgos relacionados que deben gestionarse juntos.

La casilla adyacente **Create Finding Groups for all Findings** cumple dos funciones:
- **Checked**: Crea un Grupo de Hallazgos para cada Hallazgo importado, incluso si ese Hallazgo es el único miembro del grupo.
- **Unchecked**: Crea Grupos de Hallazgos solo cuando realmente hay varios Hallazgos para agrupar.

![image](images/profindings_ss2.png)

Si no se selecciona ninguna opción en el menú desplegable Group By durante la importación (por ejemplo, **Finding Title** en la captura de pantalla anterior, etc.), no se producirá ninguna agrupación.

Si el criterio de agrupación (por ejemplo, nombre del componente, ID de vulnerabilidad, título del Hallazgo, etc.) no está completo en el Hallazgo, no se le creará un grupo ni se agregará a un Grupo de Hallazgos preexistente.

Si se importa un análisis que revela 10 Hallazgos que no están agrupados, y luego se reimporta el mismo análisis y los Hallazgos quedan agrupados, los primeros 10 Hallazgos no se agregarán a ese Grupo de Hallazgos (es decir, el Grupo de Hallazgos incluirá únicamente los 10 Hallazgos de la reimportación, y no los 10 Hallazgos de la importación inicial).

## Plantillas de Hallazgos
Las **Plantillas de Hallazgos** permiten a los Usuarios crear plantillas reutilizables para vulnerabilidades y problemas de seguridad reportados con frecuencia. Una plantilla puede incluir información estandarizada, como un título, descripción, impacto, pasos para reproducir, mitigación, referencias y otros metadatos del Hallazgo.

Las Plantillas de Hallazgos son especialmente útiles en situaciones en las que los Usuarios necesitan crear Hallazgos manuales de forma repetida y desean evitar volver a ingresar la misma información de respaldo cada vez.

### Acceso a las Plantillas de Hallazgos
Las Plantillas de Hallazgos se encuentran dentro del submenú Findings en la barra lateral.

![image](images/profindings_ss1.png)

### Creación de Plantillas de Hallazgos
Las Plantillas de Hallazgos se pueden crear haciendo clic en el botón **New Finding Template** en la parte superior izquierda de la vista de Plantillas de Hallazgos.

La página siguiente ofrece un resumen de los metadatos que se aplicarán a un Hallazgo cuando se utilice una Plantilla de Hallazgo.

### Aplicación de Plantillas de Hallazgos
Las Plantillas de Hallazgos difieren entre DefectDojo OS y DefectDojo Pro. En Pro, las Plantillas de Hallazgos no se pueden aplicar a Hallazgos preexistentes, ni se pueden crear a partir de Hallazgos preexistentes.

Sin embargo, puede agregar manualmente un Hallazgo a un Test a partir de una Plantilla de Hallazgo, ya sea mediante el menú kebab ⋮ junto al Test en la vista del Compromiso principal, o mediante el menú de engranaje en la vista del Test.

![image](images/profindings_ss3.png)

![image](images/profindings_ss4.png)

## Generación de informes
El generador de informes de DefectDojo le permite ensamblar un informe personalizado a partir de un conjunto de widgets de contenido, ejecutarlo y exportar el resultado (por ejemplo, imprimiéndolo en PDF). Los informes personalizados pueden resumir los Hallazgos o Endpoints que desea compartir con una audiencia externa, y pueden incluir elementos de marca y texto estándar.

Puede encontrar más información sobre el Generador de informes de DefectDojo [aquí](/metrics_reports/reports/report-builder/).

### Exportar Hallazgos
Las páginas que muestran una lista de Hallazgos o una lista de Compromisos tienen una opción de exportación a CSV y Excel en la parte superior izquierda. Para los Hallazgos, también existe la opción de realizar una Exportación rápida, que abrirá una nueva pestaña con tablas de metadatos correspondientes a cada Hallazgo.
