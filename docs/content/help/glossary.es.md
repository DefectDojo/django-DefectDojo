---
title: Glosario
weight: 1
---

A continuación se presenta un glosario simple para ayudar a comprender las diversas capacidades de DefectDojo, junto con una indicación de si cada función definida está presente/es aplicable en la versión Pro de DefectDojo, en la versión OS, o en ambas.

## Jerarquía de Productos (Ambas)
El modelo estructural utilizado para organizar los datos de seguridad dentro de DefectDojo, compuesto por Organizaciones → Activos → Compromisos → Tests → Hallazgos.
## Organización (Ambas)
Un objeto jerárquico de nivel superior que actúa como objeto padre de los Activos en DefectDojo Pro. Proporciona un contexto compartido para la gobernanza, el control de acceso y los informes en todos los Activos hijos.
## Activo (Ambas)
Un objeto de primera clase que representa una entidad de sistema desplegable o lógica (por ejemplo, una aplicación, un host, un entorno) dentro de las Organizaciones. Los Activos admiten relaciones padre-hijo y metadatos de negocio más completos en la versión Pro, pero no admiten relaciones padre-hijo en la versión OS.
### Jerarquía de Activos (Pro)
Un modelo de relación padre-hijo entre Activos que permite la herencia de contexto y la agregación de Hallazgos.
## Compromiso (Ambas)
Una actividad de seguridad delimitada que representa una ventana de pruebas, un pipeline o un contexto de evaluación.
## Test (Ambas)
Una única ejecución de un escáner o de una evaluación manual dentro de un Compromiso. Los Tests almacenan metadatos de ejecución y actúan como el punto de ingesta de los Hallazgos.
## Servicio (Ambas)
Un subobjeto opcional utilizado para atribuir Hallazgos a un componente o interfaz específicos dentro de un Activo. Los Servicios son más útiles en DefectDojo OS, ya que su funcionalidad se replica y mejora mediante la Jerarquía de Activos en la versión Pro.
## Componentes (Ambas)
Una biblioteca de terceros, un módulo de software o una dependencia externa que se rastrea en DefectDojo Pro. Los Componentes importados se derivan de los datos de escaneo y se asocian con los Hallazgos. En la interfaz de Pro, la Tabla de Componentes agrega los recuentos de Hallazgos Activos, Duplicados y Totales por Componente, y permanece poblada incluso cuando todos los Hallazgos asociados están Mitigados.
## Hallazgo (Ambas)
El objeto de vulnerabilidad más granular en la Jerarquía de Productos de DefectDojo, que representa un problema de seguridad discreto.
### Estado del Hallazgo (Ambas)
El estado actual del ciclo de vida de un Hallazgo (por ejemplo, Activo, Verificado, Inactivo/Mitigado, En revisión, Riesgo aceptado, Falso positivo, Fuera de alcance). El Estado del Hallazgo determina su inclusión en las métricas y los paneles.
### Prioridad/Riesgo del Hallazgo (Pro)
Un valor calculado o derivado que representa la urgencia de remediación combinando la severidad con factores contextuales como la criticidad del activo o la explotabilidad. La Prioridad es distinta de la severidad bruta y se utiliza para la toma de decisiones basada en riesgo.
### Grupos de Hallazgos (Ambas)
Un mecanismo para agrupar Hallazgos relacionados entre Organizaciones, Activos o herramientas. Los Grupos de Hallazgos permiten un análisis consolidado y un reporte de nivel superior.
## Endpoint (Ambas)
Una ubicación accesible por red (URL, IP, puerto) asociada a un Hallazgo. Los Endpoints proporcionan contexto técnico de explotación.
## Importación (Ambas)
El proceso de ingesta de resultados de escaneo o hallazgos manuales en DefectDojo, normalmente mediante la carga de un archivo o el envío de datos a través de la API. Durante la importación, DefectDojo analiza, normaliza, deduplica y asocia los hallazgos con el Activo, el Compromiso, el Test y demás objetos correspondientes.
## Reimportación (Ambas)
La acción de ingerir nuevos resultados de escaneo en un Test existente. La reimportación actualiza los estados de los Hallazgos según su presencia o ausencia en los nuevos datos.
## Deduplicación (Ambas)
El proceso de correlacionar los Hallazgos entrantes con los existentes mediante hashes y lógica de coincidencia, lo que permite el seguimiento histórico entre ejecuciones de escaneo.
## Falso positivo (Ambas)
Un estado de Hallazgo que indica que el problema no es válido o no es explotable. Los falsos positivos se conservan para fines de auditoría, pero se excluyen de los cálculos de riesgo.
## Aceptación de riesgo (Ambas)
Un estado de flujo de trabajo que indica un Hallazgo reconocido pero no resuelto. Los riesgos aceptados permanecen visibles, pero se excluyen de la aplicación de SLA.
## Metadatos (Ambas)
Datos clave adjuntos a los Tests o los Hallazgos, como el nombre de la rama o el ID de build, generalmente proporcionados a través de pipelines de CI/CD.
## Integración de CI/CD (Ambas)
Ingesta automatizada de resultados de escaneo durante los flujos de trabajo de compilación o despliegue. Las integraciones normalmente dependen de la API y del framework de importadores.
## API (Ambas)
Una interfaz RESTful utilizada para gestionar objetos de DefectDojo de forma programática. La API es el mecanismo principal para la automatización y la integración con pipelines.
## Webhook (Pro)
Una llamada HTTP saliente activada por eventos específicos (por ejemplo, la creación de un Hallazgo). Los Webhooks permiten la integración en tiempo real con sistemas externos.
## Configuración de SLA (Pro)
Definiciones de políticas que asignan plazos de remediación en función de la severidad o de los atributos de riesgo. Los SLA permiten su aplicación y la medición del rendimiento.
## Rol de usuario (Ambas)
Un conjunto de permisos que define las acciones permitidas dentro de DefectDojo. Los roles aplican el control de acceso en los Activos y los Compromisos.
## Importador Universal (Pro)
Un mecanismo de ingesta flexible que permite importar datos de escaneo sin un importador específico para cada herramienta. Se basa en un mapeo de campos normalizado en lugar de esquemas de escáner predefinidos.
## DefectDojo-CLI (Pro)
Una interfaz de línea de comandos utilizada para interactuar con DefectDojo de forma programática. La CLI se utiliza habitualmente en pipelines de CI/CD para automatizar la carga de escaneos y la gestión de objetos.
## Conectores (Pro)
El área unificada de la interfaz de Pro (dentro de Import) para todas las herramientas con las que DefectDojo se comunica. Los Conectores Ascendentes extraen hallazgos desde los escáneres; los Conectores Descendentes envían hallazgos hacia los sistemas de seguimiento de incidencias.
## Conectores Ascendentes / Conectores de API (Pro)
Conectores prediseñados y gestionados que extraen hallazgos e inventario de activos hacia DefectDojo desde escáneres externos y herramientas de seguridad a través de sus API, reduciendo la necesidad de scripting personalizado. Anteriormente llamados Conectores de API.
## Conectores Descendentes (Pro)
Integraciones gestionadas que envían Hallazgos y Grupos de Hallazgos desde DefectDojo hacia sistemas de seguimiento de incidencias y tickets (por ejemplo, Jira, Azure DevOps, GitHub). Anteriormente llamados Integraciones.
## Parser Universal (Pro)
Un motor de análisis generalizado utilizado por el Importador Universal para interpretar los datos de escaneo entrantes. Aplica una lógica de normalización y deduplicación consistente en formatos no compatibles.
## Carga Inteligente (Pro)
Un flujo de ingesta inteligente que determina automáticamente cómo deben asignarse los resultados de escaneo a los Activos o Compromisos, reduciendo la configuración manual durante la importación.
## Información Ejecutiva (Pro)
Análisis de alto nivel orientados al negocio, diseñados para audiencias directivas, centrados en tendencias, exposición y salud del programa en lugar de Hallazgos individuales.
## Información de Prioridad (Pro)
Vistas analíticas que muestran los riesgos más críticos según la puntuación de prioridad en lugar de la severidad por sí sola, respaldando la planificación de remediación basada en riesgo.
## Información del Programa (Pro)
Métricas y visualizaciones que evalúan la eficacia y la madurez de un programa de seguridad a lo largo del tiempo. La Información del Programa enfatiza las tendencias, la cobertura y el rendimiento operativo.
## Información de Herramientas (Pro)
Análisis centrado en el rendimiento de los escáneres, la cobertura y su contribución a los Hallazgos, ayudando a los equipos a optimizar el uso de herramientas y reducir el ruido.
## Motor de Reglas (Pro)
Un sistema de automatización basado en políticas que aplica lógica condicional a los Hallazgos durante la ingesta o los eventos del ciclo de vida, automatizando cambios de severidad, asignaciones o flujos de trabajo.
## Integraciones (Ambas)
Conexiones entre DefectDojo y herramientas o plataformas externas para la ingesta de datos, notificaciones o automatización de flujos de trabajo. Pro incluye integraciones más profundas y gestionadas, más allá de los importadores básicos y el uso de la API.
