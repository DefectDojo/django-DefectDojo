---
title: Compromisos
description: Información sobre los Compromisos en DefectDojo OS
audience: opensource
weight: 3
---

Organizaciones → Activos → **COMPROMISOS** → Tests → Hallazgos

## Descripción general

En la jerarquía de productos de DefectDojo, los Compromisos son contenedores delimitados por tiempo o por pipeline que representan grupos de Tests relacionados dentro de un Producto específico. Si tiene previsto un esfuerzo de testing programado, ya sea de forma rutinaria o puntual, un Compromiso le ofrece un lugar donde almacenar todos los resultados relacionados.

Ejemplos de Compromisos incluyen:
- Pruebas de penetración puntuales
- Escaneos mensuales o trimestrales recurrentes
- Períodos de revisión de bug bounty
- Ejecuciones de pipeline de CI/CD (para equipos que tratan cada pipeline como su propio Compromiso)
- Ciclos de lanzamiento de código (p. ej., “revisión de seguridad del lanzamiento v4.2”)

### Tipos de Compromiso

DefectDojo admite dos tipos de Compromiso: **Interactivo** y **CI/CD**. Estos tipos determinan cómo se crean normalmente los Tests y cómo se importan los resultados del escaneo.

Un Compromiso Interactivo suele ser ejecutado por un ingeniero. Los Compromisos Interactivos se centran en probar una aplicación mientras está en ejecución, mediante un test automatizado, un probador humano o cualquier actividad que “interactúe” con la funcionalidad de la aplicación.

Un Compromiso de CI/CD es para la integración automatizada con un pipeline de CI/CD. Los Compromisos de CI/CD están pensados para importar datos como una acción automatizada, desencadenada por un paso del proceso de lanzamiento.

| **Categoría**                | **Compromisos Interactivos**                             | **Compromisos de CI/CD**                                              |
|------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| **Caso de uso principal**   | Testing de seguridad manual o puntual                            | Testing de seguridad automatizado y recurrente dentro de pipelines             |
| **Duración**           | Delimitada en el tiempo y finita                                        | Potencialmente de duración infinita                                      |
| **Frecuencia**          | Periódica o puntual                                          | Continua o por cada commit                                           |
| **Flujo de trabajo**           | El probador humano ejecuta la herramienta → importa los resultados manualmente            | El pipeline ejecuta la herramienta → envía automáticamente los resultados a DefectDojo    |
| **Método de importación de resultados** | Carga manual mediante la UI o la CLI                                 | Importación mediante API a través de automatización (p. ej., CLI, conectores, cron jobs, scripts de pipeline) |
| **Tipo de testing habitual** | Pruebas de penetración, ejercicios de red team, evaluaciones manuales   | Análisis estático, escaneo de dependencias, escaneo de contenedores           |

### Datos del Compromiso

Como contenedores que organizan la actividad de testing, los Compromisos pueden almacenar o registrar una variedad de datos:

- Fechas objetivo de inicio y fin
- Descripción y notas de alcance
- Estado (en curso, planificado, completado, etc.)
- Responsable / Líder
- Tests asociados (p. ej., escaneos, pruebas de penetración, tests manuales, etc.)
- Hallazgos y tipos de Hallazgo (p. ej., activo, mitigado, riesgo aceptado, duplicado, etc.)
- Modelos de amenaza o información de aceptación de riesgo
- Etiquetas
- Archivos y notas
- Configuración del proyecto de Jira
- Detalles del entorno (p. ej., staging frente a producción)
- IDs de build (si está vinculado a CI/CD)
- Datos históricos de Tests anteriores dentro del Compromiso

## Acceso a los Compromisos

Se puede acceder a los Compromisos desde la barra lateral. El submenú ofrece acceso a los Compromisos activos y a todos los Compromisos, así como la opción de ver los Compromisos organizados por Producto, tipos de Test y Entornos.

![image](images/engagement_ss17.png)

Alternativamente, se puede acceder a los Compromisos dentro de un Producto concreto desde el submenú de la opción Compromisos en la barra superior.

![image](images/engagement_ss18.png)

### Permisos

Los Compromisos se sitúan por debajo de los Productos y por encima de los Tests en la jerarquía de objetos. Por lo tanto, el acceso a un Producto otorga automáticamente acceso a todos los Compromisos dentro de ese Producto. Los Compromisos no tienen listas de control de acceso independientes.

## Trabajar con Compromisos

### Crear Compromisos

Existen varios enfoques para crear un Compromiso. Cada enfoque requiere que primero cree un Producto que lo contenga.

Una vez creado un Producto, puede añadir un nuevo Compromiso Interactivo o de CI/CD en la sección Compromisos de la barra de navegación del Producto.

![image](images/engagement_ss4.png)

Todo Compromiso debe tener definidos los siguientes campos:
- Tipo (Interactivo o CI/CD)
- Un nombre único
- Fechas objetivo de inicio y fin
    - Esto determinará la aparición del Compromiso en la sección Calendario
- Producto
- Estado

#### Estados del Compromiso

Los Compromisos pueden etiquetarse con diferentes estados al crearlos. El estado también se puede cambiar posteriormente en la configuración del Compromiso.

Un Compromiso puede tener cualquiera de los siguientes estados:
- No iniciado
- Bloqueado
- Cancelado
- Completado
- En curso
- En espera
- Programado
- Esperando recurso

Cambiar el estado de un Compromiso a “Completado” significará que la mayoría de las operaciones de escritura (p. ej., añadir tests, importar escaneos) dejarán de estar disponibles o quedarán ocultas. Otros estados no afectarán materialmente a la funcionalidad del Compromiso, y son más bien para fines de filtrado/información.

### Editar Compromisos

Los Compromisos se pueden editar haciendo clic en el botón **Editar** dentro de la configuración del Compromiso. Todos los campos editables subsiguientes también están disponibles al crear el Compromiso.

### Copiar Compromisos

Puede duplicar fácilmente los Compromisos navegando a la lista de Compromisos dentro de un Producto y haciendo clic en el botón **Copiar** dentro del menú kebab ⋮ junto al Compromiso que desea copiar. Esto creará una copia exacta del Compromiso original dentro del Producto principal, incluyendo los metadatos, Tests y Hallazgos que contiene.

![image](images/engagement_ss19.png)

### Cerrar Compromisos

Los Compromisos se pueden cerrar navegando a la lista de Compromisos dentro de un Producto y haciendo clic en “Cerrar” dentro del menú kebab ⋮ del Compromiso elegido.

![image](images/engagement_ss20.png)

Una vez cerrado, el estado del Compromiso cambiará a “Completado”. No obstante, la mayoría de las operaciones de escritura (p. ej., añadir tests, importar escaneos) seguirán estando disponibles.

Cerrar un Compromiso no cambia el estado de los Hallazgos dentro de ninguno de los Tests del Compromiso. Los Hallazgos permanecen abiertos, mitigados o con riesgo aceptado según su propio ciclo de vida, y siguen siendo accesibles para su visualización e informes.

Si el Compromiso está vinculado a un Epic de Jira (consulte **[Integración con Jira: Habilitar el mapeo de Epics de Compromiso](/connectors/os_jira/os__jira_guide/#enable-engagement-epic-mapping-for-products)**), cerrar el Compromiso desencadenará una tarea asíncrona que cierra el Epic de Jira asociado en su Espacio de Jira conectado.

### Reabrir Compromisos

Si un Compromiso está cerrado, se puede reabrir haciendo clic en **Reabrir** dentro de su menú kebab ⋮ en la tabla de Compromisos cerrados. Esto hará que el Compromiso vuelva a estar activo y su estado regresará a “En curso”.

![image](images/engagement_ss21.png)

### Compromisos vencidos

Un Compromiso vence una vez que pasa su fecha objetivo de fin.

El vencimiento del Compromiso no tiene un impacto directo en su funcionalidad, y sirve principalmente como mecanismo de monitoreo/notificación.

Una vez vencido, aparecerá una notificación en rojo de “X días de retraso” en el campo “Duración” del Compromiso, pero no restringirá ninguna de sus funcionalidades. El estado del Compromiso seguirá apareciendo como “En curso”.

Aunque no está habilitado de forma predeterminada, existe una opción dentro de la configuración del sistema para cerrar automáticamente un Compromiso una vez que ha estado vencido durante un determinado número de días.

![image](images/engagement_ss22.png)

### Eliminar Compromisos

La eliminación de un Compromiso se puede realizar seleccionando **Eliminar** en la configuración del Compromiso. Esta acción no se puede deshacer.

Eliminar un Compromiso también eliminará lo siguiente:
- Cualquier Test asociado al Compromiso
- Todos los Hallazgos dentro de esos Tests
- Cualquier mapeo de Epic de Jira vinculado (el Epic en sí permanecerá en Jira, pero se eliminará el vínculo entre DefectDojo y Jira)
- Todas las notas y archivos adjuntos asociados al Compromiso

Por motivos de auditoría, se recomienda cerrar los Compromisos completados en lugar de eliminarlos.

| **Operación** | **Resultados** | **Reversible** |
|----------|---------|------------|
| **Cerrar** | Se marca como inactivo; los datos permanecen; se puede reabrir | Sí (reabrir) |
| **Vencer** | Solo advertencia visual; cierre automático opcional; notificaciones | N/D |
| **Eliminar** | Elimina permanentemente el Compromiso, los Tests, los Hallazgos, las notas, los archivos y cualquier mapeo de Epic de Jira (los Epics permanecen en Jira) | No |

## Integración con Jira

Los Compromisos se pueden vincular a un Espacio de Jira conectado, lo que permite que los Hallazgos dentro del Compromiso se envíen a Jira como Issues. Para obtener una guía completa sobre cómo configurar Jira, consulte **[Conectar DefectDojo a Jira](/connectors/os_jira/os__jira_guide/)**.

### Mapeo de Epics de Compromiso

Cuando la opción **Habilitar el mapeo de Epics de Compromiso** está marcada en la configuración de Jira de un Producto, los Compromisos se enviarán a Jira como Epics. Los Hallazgos dentro del Compromiso se envían como Issues secundarios bajo el Epic, reflejando la jerarquía Compromiso → Hallazgos de DefectDojo en la estructura Epic → Issue de Jira.

Para más información sobre esta configuración, consulte **[Habilitar el mapeo de Epics de Compromiso](/connectors/os_jira/os__jira_guide/#enable-engagement-epic-mapping-for-products)**.

### Configuración de Jira a nivel de Compromiso

De forma predeterminada, los Compromisos heredan su configuración de Jira de su Producto principal. Sin embargo, los Compromisos individuales pueden anular esta configuración para usar configuraciones de Jira diferentes. Los siguientes ajustes se pueden personalizar por Compromiso:

- **Clave del proyecto** — enrutar los Hallazgos a un Espacio de Jira diferente
- **Plantilla de Issue** — usar una plantilla diferente para los Issues creados a partir de este Compromiso
- **Campos personalizados** — aplicar diferentes mapeos de campos personalizados
- **Etiquetas de Jira** — etiquetar los Issues con etiquetas específicas del Compromiso
- **Responsable predeterminado** — asignar los Issues a otro miembro del equipo

Estos ajustes están disponibles desde la página **Editar Compromiso**. Para más detalles, consulte **[Configuración de Jira a nivel de Compromiso](/connectors/os_jira/os__jira_guide/#engagement-level-jira-settings)**.
