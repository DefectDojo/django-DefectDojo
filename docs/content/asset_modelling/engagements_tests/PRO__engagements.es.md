---
title: Compromisos
description: Comprender los Compromisos en DefectDojo Pro
audience: pro
weight: 3
---

Organizaciones → Activos → **COMPROMISOS** → Tests → Hallazgos 

## Descripción general

En la Jerarquía de Activos de DefectDojo, los Compromisos son contenedores delimitados por tiempo o por pipeline que representan grupos de Tests relacionados dentro de un Activo específico. Si tiene programado un esfuerzo de testing planificado, ya sea de forma rutinaria o puntual, un Compromiso le ofrece un lugar donde almacenar todos los resultados relacionados.

Algunos ejemplos de Compromisos incluyen: 
- Pruebas de penetración puntuales
- Escaneos mensuales o trimestrales recurrentes
- Períodos de revisión de bug bounty
- Ejecuciones de pipeline de CI/CD (para equipos que tratan cada pipeline como su propio Compromiso)
- Ciclos de lanzamiento de código (por ejemplo, "revisión de seguridad del lanzamiento v4.2")

### Tipos de Compromiso 

DefectDojo admite dos tipos de Compromiso: **Interactivo** y **CI/CD**. Estos tipos determinan cómo se crean habitualmente los Tests y cómo se importan los resultados de los escaneos.

Un Compromiso Interactivo suele ser ejecutado por un ingeniero. Los Compromisos Interactivos se centran en probar una aplicación mientras esta se está ejecutando, mediante un test automatizado, un tester humano o cualquier actividad que "interactúe" con la funcionalidad de la aplicación. 

Un Compromiso de CI/CD está pensado para la integración automatizada con un pipeline de CI/CD. Los Compromisos de CI/CD tienen como fin importar datos como una acción automatizada, activada por un paso del proceso de lanzamiento.

| **Categoría**                | **Compromisos Interactivos**                             | **Compromisos de CI/CD**                                              |
|------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| **Caso de uso principal**   | Testing de seguridad manual o puntual                            | Testing de seguridad automatizado y recurrente dentro de pipelines             |
| **Duración**           | Delimitada en el tiempo y finita                                        | Duración potencialmente infinita                                      |
| **Frecuencia**          | Periódica o puntual                                          | Continua o por cada commit                                           |
| **Flujo de trabajo**           | El tester humano ejecuta la herramienta → importa los resultados manualmente            | El pipeline ejecuta la herramienta → envía automáticamente los resultados a DefectDojo    |
| **Método de importación de resultados** | Carga manual mediante la UI o la CLI                                 | Importación mediante automatización basada en API (por ejemplo, CLI, conectores, cron jobs, scripts de pipeline) |
| **Tipo de testing habitual** | Pruebas de penetración, ejercicios de red team, evaluaciones manuales   | Análisis estático, escaneo de dependencias, escaneo de contenedores           |

### Datos del Compromiso 

Como contenedores que organizan la actividad de testing, los Compromisos pueden almacenar o hacer seguimiento de diversos datos:

- Fechas de inicio y fin previstas
- Descripción y notas de alcance
- Estado (en curso, planificado, completado, etc.)
- Persona asignada / Responsable
- Tests asociados (por ejemplo, escaneos, pruebas de penetración, tests manuales, etc.)
- Hallazgos y Tipos de Hallazgo (por ejemplo, activo, mitigado, riesgo aceptado, duplicado, etc.) 
- Modelos de amenaza o información de aceptación de riesgo
- Etiquetas
- Archivos y notas
- Configuración del proyecto de Jira
- Detalles del entorno (por ejemplo, staging vs. producción)
- IDs de compilación (si está vinculado a CI/CD)
- Datos históricos de Tests anteriores dentro del Compromiso 

## Acceso a los Compromisos 

Se puede acceder a los Compromisos desde la barra lateral. El submenú brinda acceso a Compromisos Activos y Todos los Compromisos, además de la opción de crear nuevos Compromisos.

![image](images/engagement_ss13.png)

Como alternativa, se puede acceder a los Compromisos dentro de un Activo desde la ventana ubicada en la parte inferior de la vista del Activo.

![image](images/engagement_ss14.png)

### Permisos 

Los Compromisos se ubican debajo de los Activos y por encima de los Tests en la jerarquía de objetos. Por lo tanto, el acceso a un Activo otorga automáticamente acceso a todos los Compromisos dentro de ese Activo. Los Compromisos no cuentan con listas de control de acceso independientes.

## Trabajar con Compromisos

### Crear Compromisos 

Antes de crear un Compromiso, primero debe haber [creado un Activo](/asset_modelling/engagements_tests/pro__assets/#create-assets) que lo contenga. 

Existen varias formas de crear un Compromiso: 

- Desde el menú desplegable de Compromisos en la sección Gestionar de la barra lateral
    - Deberá seleccionar el Activo al que se atribuirá el Compromiso al completar el formulario de nuevo Compromiso

![image](images/engagement_ss1.png)

- El ícono de engranaje ubicado en la esquina superior derecha de la vista de un Activo

![image](images/engagement_ss9.png)

- El botón "+ Nuevo Compromiso" que se encuentra en la lista de Compromisos dentro de un Activo

![image](images/engagement_ss2.png)

- Si aún no ha creado un Compromiso dentro de un Activo, puede hacerlo mientras importa un escaneo. 

![image](images/engagement_ss3.png)

Todo Compromiso debe tener definidos los siguientes campos:
- Tipo (Interactivo o CI/CD)
- Un nombre único 
- Fechas de inicio y fin previstas 
    - Esto determinará la aparición del Compromiso en la sección Calendario
- Activo 
- Estado 

#### Estados del Compromiso 

Los Compromisos pueden etiquetarse con distintos estados al momento de su creación. El estado también se puede cambiar posteriormente en la configuración del Compromiso. 

Un Compromiso puede tener cualquiera de los siguientes estados: 
- No iniciado
- Bloqueado
- Cancelado 
- Completado 
- En curso 
- En espera 
- Programado 
- Esperando recurso 

Cambiar el estado de un Compromiso a "Completado" hará que la mayoría de las operaciones de escritura (por ejemplo, agregar tests, importar escaneos) queden no disponibles u ocultas. Los demás estados no afectan de manera sustancial la funcionalidad del Compromiso y cumplen principalmente fines de filtrado o informativos.

### Editar Compromisos 

Los Compromisos se pueden editar haciendo clic en **Editar Compromiso** dentro del menú de engranaje. Se puede acceder al mismo menú haciendo clic en el menú de tres puntos ⋮ a la izquierda del Activo en la vista Todos los Activos. 

Todos los campos que se pueden editar a continuación también están disponibles al momento de crear el Compromiso. 

![image](images/engagements_ss99.png)

### Copiar Compromisos 

Puede duplicar fácilmente los Compromisos seleccionando "Copiar Compromiso" dentro de la configuración del Compromiso. Esto creará una copia exacta del Compromiso original dentro del Activo principal, incluyendo los metadatos, Tests y Hallazgos que contiene.

### Cerrar Compromisos 

Los Compromisos se cierran seleccionando **Cerrar Compromiso** dentro de la configuración del Compromiso. Una vez cerrado, el estado del Compromiso cambiará a "Completado". No obstante, la mayoría de las operaciones de escritura (por ejemplo, agregar tests, importar escaneos) seguirán estando disponibles.

Cerrar un Compromiso no cambia el estado de los Hallazgos dentro de ninguno de los Tests del Compromiso. Los Hallazgos permanecen activos, mitigados o con riesgo aceptado según su propio ciclo de vida, y siguen estando accesibles para su visualización e inclusión en informes.

Si el Compromiso está vinculado a una Épica de Jira (consulte **[Integración con Jira: Habilitar la asignación de Épicas a Compromisos](/connectors/downstream/pro__jira_guide/#enable-engagement-epic-mapping)**), cerrar el Compromiso activará una tarea asíncrona que cierra la Épica de Jira asociada en su Espacio de Jira conectado.

### Reabrir Compromisos 

Si un Compromiso está cerrado, se puede reabrir seleccionando **Reabrir Compromiso** dentro de su configuración. Esto hará que el Compromiso vuelva a estar activo y su estado regrese a "En curso." 

### Compromisos vencidos 

Un Compromiso vence una vez que transcurre su fecha de finalización prevista.

A diferencia de cerrar o eliminar un Compromiso, que un Compromiso venza no tiene un impacto directo en su funcionalidad, y sirve principalmente como un mecanismo de monitoreo/notificación.  

Una vez vencido, aparecerá una etiqueta "Vencido" junto al Compromiso, pero esto no restringirá ninguna de sus funcionalidades. El estado del Compromiso seguirá apareciendo como "En curso." 

Si bien no está habilitada de forma predeterminada, existe una opción dentro de la configuración del sistema para cerrar automáticamente un Compromiso una vez que ha estado vencido durante una cierta cantidad de días. 

![image](images/engagement_ss15.png)

### Eliminar Compromisos

Se puede eliminar un Compromiso seleccionando **Eliminar Compromiso** en la configuración del Compromiso. Esta acción no se puede deshacer.

Eliminar un Compromiso también eliminará lo siguiente:
Cualquier Test asociado con el Compromiso
Todos los Hallazgos dentro de esos Tests
Cualquier asignación vinculada a una Épica de Jira (la Épica en sí permanecerá en Jira, pero se eliminará el vínculo entre DefectDojo y Jira)
Todas las notas y archivos cargados asociados con el Compromiso

Para fines de auditoría, se recomienda cerrar los Compromisos completados en lugar de eliminarlos.

| **Operación** | **Resultados** | **Reversible** |
|----------|---------|------------|
| **Cerrar** | Se marca como inactivo; los datos permanecen; se puede reabrir | Sí (reabrir) |
| **Vencer** | Solo advertencia visual; cierre automático opcional; notificaciones | N/D |
| **Eliminar** | Elimina de forma permanente el Compromiso, los Tests, los Hallazgos, las notas, los archivos y cualquier asignación de Épica de Jira (las Épicas permanecen en Jira) | No |

## Integración con Jira

Los Compromisos se pueden vincular a un Espacio de Jira conectado, lo que permite enviar los Hallazgos dentro del Compromiso a Jira como Issues. Para obtener una guía completa sobre la configuración de Jira, consulte **[Conectar DefectDojo con Jira](/connectors/downstream/pro__jira_guide/)**.

### Asignación de Épicas a Compromisos

Cuando la opción **Habilitar la asignación de Épicas a Compromisos** está marcada en la configuración de Jira de un Producto, los Compromisos se enviarán a Jira como Épicas. Los Hallazgos dentro del Compromiso se envían como Issues secundarios debajo de la Épica, reflejando la jerarquía de Compromiso → Hallazgos de DefectDojo en la estructura de Épica → Issue de Jira.

Para obtener más información sobre esta configuración, consulte **[Habilitar la asignación de Épicas a Compromisos](/connectors/downstream/pro__jira_guide/#enable-engagement-epic-mapping)**.

### Configuración de Jira a nivel de Compromiso

De forma predeterminada, los Compromisos heredan su configuración de Jira del Activo (Producto) principal. Sin embargo, los Compromisos individuales pueden anular esta configuración para usar configuraciones de Jira diferentes. Los siguientes ajustes se pueden personalizar por Compromiso:

- **Clave del proyecto** — envía los Hallazgos a un Espacio de Jira diferente
- **Plantilla de Issue** — usa una plantilla diferente para los Issues creados a partir de este Compromiso
- **Campos personalizados** — aplica asignaciones de campos personalizados diferentes
- **Etiquetas de Jira** — etiqueta los Issues con etiquetas específicas del Compromiso
- **Persona asignada predeterminada** — asigna los Issues a un miembro diferente del equipo

Se puede acceder a esta configuración desde la página **Editar Compromiso**. Para obtener más detalles, consulte **[Configuración de Jira a nivel de Compromiso](/connectors/downstream/pro__jira_guide/#engagement-level-jira-settings)**.
