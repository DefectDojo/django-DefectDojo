---
title: 'Jerarquía de Activos: Descripción general'
description: Comprenda las Organizaciones, los Activos, los Compromisos, los Tests
  y los Hallazgos
weight: 1
audience: opensource
aliases:
- /es/en/working_with_findings/organizing_engagements_tests/product_hierarchy
- /es/asset_modelling/os_hierarchy/product_hierarchy/
- /es/en/asset_modelling/os_hierarchy/product_hierarchy/
---

DefectDojo utiliza cinco clases de datos principales para organizar su trabajo: **Organizaciones, Activos**, **Compromisos**, **Tests** y **Hallazgos**.

DefectDojo está diseñado para adaptarse a su equipo, en lugar de obligar a su equipo a adaptarse a la herramienta. Podrá diseñar un espacio de trabajo robusto y adaptable una vez que comprenda cómo se pueden usar estas clases de datos para organizar su trabajo.

### Diagrama de jerarquía de Activos
![image](images/Asset_Hierarchy_Full.png)


## **Organizaciones**

La primera categoría de datos que deberá configurar en DefectDojo es una Organización. Las Organizaciones están pensadas para categorizar los Activos de una manera específica. Esto podría ser:

* por dominio de negocio
* por equipo de desarrollo
* por equipo de seguridad

![image](images/Asset_Hierarchy_Overview.png)
*Los Activos se agrupan y anidan dentro de su Organización.*

A las Organizaciones se les pueden aplicar reglas de Control de Acceso Basado en Roles, que limitan la capacidad de los miembros del equipo para ver e interactuar con sus datos (incluidos los Activos subyacentes con datos de Compromisos, Tests y Hallazgos). Para obtener más información sobre los roles de usuario, consulte nuestro artículo **Introducción a los Roles**.

#### ¿Qué puede representar una Organización?

* Si un proyecto de software en particular tiene muchos despliegues o versiones distintas, puede valer la pena crear una única Organización que cubra el alcance de todo el proyecto, y hacer que cada versión exista como Activos individuales.
​
* También podría considerar usar las Organizaciones para representar etapas de su proceso de desarrollo de software: una Organización para 'En desarrollo', otra Organización para 'En producción', etc.
​
* En última instancia, depende de usted decidir cómo desea organizar sus Activos y qué quiere que representen sus Organizaciones. Es posible que su jerarquía de DefectDojo deba cambiar para adaptarse a las necesidades de sus equipos de seguridad.

## **Activos**

Un **Activo** en DefectDojo está pensado para representar cualquier proyecto, programa o aplicación que esté probando actualmente. El Activo alberga todo el trabajo de seguridad y el historial de testing relacionado con el objetivo subyacente.

![image](images/Asset_Hierarchy_Overview_2.png)

* un **Nombre** único
* una **Descripción**
* una **Organización**
* una **Configuración de SLA** asignada

Los Activos pueden tener un alcance tan amplio o específico como desee. Por defecto, los Activos son objetos completamente independientes en la jerarquía, pero se pueden agrupar mediante una **Organización**.

Los Activos están 'aislados' y no interactúan con otros Activos. Las Funciones Inteligentes de DefectDojo, como la **Deduplicación**, solo se aplican dentro del contexto de un único Activo.

Al igual que las **Organizaciones**, a los **Activos** se les pueden aplicar reglas de Control de Acceso Basado en Roles, que limitan la capacidad de los miembros del equipo para verlos e interactuar con ellos (así como con los datos subyacentes de Compromisos, Tests y Hallazgos). Para obtener más información sobre los roles de usuario, consulte nuestro artículo **Introducción a los Roles**.

#### ¿Qué puede representar un Activo?

El concepto de 'Activo' de DefectDojo no necesariamente corresponde 1:1 con lo que su organización denominaría un 'Producto'. El desarrollo de software es complejo, y las necesidades de seguridad pueden variar mucho incluso dentro del alcance de una sola pieza de software.

Los siguientes escenarios son buenas razones para considerar la creación de un Activo de DefectDojo independiente:

* “**ExampleAsset**” tiene una versión para Windows, una versión para Mac y una versión en la nube
* “**ExampleAsset 1\.0**” utiliza componentes de software completamente diferentes de “**ExampleAsset 2\.0**”, y ambas versiones cuentan con soporte activo de su empresa.
* El equipo asignado para trabajar en “**ExampleAsset version A**” es diferente del equipo de Activo asignado para trabajar en “**ExampleAsset version B**”, y como resultado necesita tener asignados permisos de seguridad diferentes.

Estas variaciones dentro de un único Activo también se pueden gestionar a nivel de Compromiso. Tenga en cuenta que los Compromisos no tienen control de acceso de la misma manera que los Activos y las Organizaciones.

## **Compromisos**

Una vez configurado un Activo, puede comenzar a crear y programar Compromisos. Los Compromisos están pensados para representar momentos en el tiempo en los que se realiza testing, y contienen uno o más **Tests**.

Los Compromisos siempre tienen:

* un **Nombre** único
* **Fechas de inicio y fin** objetivo
* **Estado** (Not Started, In Progress, Cancelled, Completed...)
* un **Testing Lead** asignado
* un **Activo** asociado

Existen dos tipos de Compromiso: **Interactive** y **CI/CD**.

* Un **Interactive Engagement** normalmente lo ejecuta un ingeniero. Los Interactive Engagements se centran en probar la aplicación mientras esta se está ejecutando, usando una prueba automatizada, un tester humano o cualquier actividad que “interactúe” con la funcionalidad de la aplicación. Consulte la [definición de IAST de OWASP](https://owasp.org/www-project-devsecops-guideline/latest/02c-Interactive-Application-Security-Testing#:~:text=Interactive%20Application%20Security%20Testing,interacting%E2%80%9D%20with%20the%20application%20functionality.).
* Un **CI/CD Engagement** es para la integración automatizada con un pipeline de CI/CD. Los CI/CD Engagements están pensados para importar datos como una acción automatizada, activada por un paso del proceso de release.

Los Compromisos se pueden seguir usando la vista de **Calendario** de DefectDojo.

#### ¿Qué puede representar un Compromiso?

Los Compromisos están pensados para representar grupos de esfuerzos de testing relacionados. La forma en que desee agrupar sus esfuerzos de testing depende de su enfoque.

Si tiene un esfuerzo de testing planificado y programado, un Compromiso le ofrece un lugar para almacenar todos los resultados relacionados. Aquí tiene un ejemplo de este tipo de Compromiso:

#### **Compromiso:** ExampleSoftware 1\.5\.2 \- Esfuerzo de testing interactivo

*En este ejemplo, un equipo de seguridad ejecuta múltiples tests el mismo día como parte de un release de software.*

* **Test:** Resultados de Nessus Scan (12 de marzo\)
* **Test:** Resultados de NPM Scan Audit (12 de marzo\)
* **Test:** Resultados de Snyk Scan (12 de marzo\)
​
También puede organizar los resultados de Tests de CI/CD dentro de un Compromiso. Este tipo de Compromisos son de 'duración abierta' ('Open\-Ended'), lo que significa que no tienen una fecha, y en su lugar añadirán datos adicionales cada vez que se ejecuten las acciones de CI/CD asociadas.

#### Compromiso: ExampleSoftware CI/CD Testing

*En este ejemplo, varios escaneos de CI/CD se importan automáticamente como Tests cada vez que se crea un nuevo release de software.*

* Test: Resultados de escaneo 1\.5\.2 (12 de marzo\)
* Test: Resultados de escaneo 1\.5\.1 (3 de marzo\)
* Test: Resultados de escaneo 1\.5\.0 (14 de febrero\)

Los Compromisos se pueden organizar de la manera que mejor funcione para su equipo. Todos los Compromisos anidados bajo un Activo pueden ser vistos por el equipo asignado para trabajar en el Activo.

## **Tests**

Los Tests son una agrupación de actividades realizadas por ingenieros para intentar descubrir fallos en un Activo.

Los Tests siempre tienen:

* un **Título de Test** único
* un **Test Type** específico (API Test, Nessus Scan, etc)
* un **Entorno** de test asociado
* un **Compromiso** asociado

Los Tests se pueden crear de diferentes maneras.  Los Tests pueden crearse automáticamente cuando los datos de escaneo se importan directamente en un Compromiso, lo que da como resultado un nuevo Test que contiene los datos del escaneo. Los Tests también pueden crearse anticipándose a la planificación de futuros compromisos, o para hallazgos de seguridad ingresados manualmente que requieran seguimiento y remediación.

### **Tipos de Test**

DefectDojo admite dos categorías de Test Types:

1. **Test Types basados en parser**: Corresponden a escáneres de seguridad específicos que producen salidas en formatos como XML, JSON o CSV. Al importar resultados de escaneo, DefectDojo utiliza parsers especializados para convertir la salida del escáner en Hallazgos.

2. **Test Types sin parser**: Se utilizan para Hallazgos creados manualmente que no se importan desde archivos de escaneo.  Estos Test Types utilizan el método [Generic Findings Import](/supported_tools/parsers/generic_findings_import/) para representar los Hallazgos y sus metadatos.

Los siguientes Test Types aparecen en el menú desplegable “Scan Type” al crear un nuevo test.
   * API Test
   * Static Check
   * Pen Test
   * Web Application Test
   * Security Research
   * Threat Modeling
   * Manual Code Review

Los Test Types sin parser deben usarse cuando necesita crear manualmente hallazgos que requieran remediación pero que no se originen en la salida de un escáner automatizado.

#### **Test Types basados en parser**

Los test types basados en parser se pueden categorizar según cómo se determina el nombre de su test type:

- **Nombres de Test Type fijos**: El nombre del test type está predefinido y se conoce antes de la importación (por ejemplo, “ZAP Scan”, “Nessus Scan”).

- **Nombres de Test Type definidos por el informe**: El nombre del test type se extrae del contenido del informe de escaneo en el momento de la importación.

Algunos ejemplos incluyen:
  - **Generic Findings Import**: Crea test types basados en el campo `type` de los informes JSON
  - **SARIF**: Crea test types basados en los nombres de herramientas del informe SARIF (por ejemplo, “Dockle Scan (SARIF)”)
  - **OpenReports**: Crea test types independientes por cada fuente encontrada en el informe

**Reglas de nomenclatura de Test Type definidos por el informe:**
- Si el campo `type` del informe es igual al tipo de escaneo → se usa el tipo de escaneo directamente (por ejemplo, “Generic Findings Import”)
- Si el campo `type` del informe es diferente → se crea el formato “{type} Scan ({scan_type})” (por ejemplo, “Tool1 Scan (Generic Findings Import)”)
- Si el campo `type` del informe ya termina con el sufijo “ ({scan_type})” → se usa tal cual, de modo que el sufijo nunca se duplica (por ejemplo, “Tool1 (Generic Findings Import)” permanece como “Tool1 (Generic Findings Import)”)
- Si no se proporciona ningún campo `type` → se usa el tipo de escaneo directamente

**Consideraciones importantes:**
- Los test types definidos por el informe se crean automáticamente cuando se detecta un tipo nuevo durante la importación o reimportación.
- En las reimportaciones, el nombre del test type debe coincidir exactamente - las discrepancias generarán un error de validación
- La configuración de Deduplicación (`HASHCODE_FIELDS_PER_SCANNER`) usa los nombres de test type como claves, por lo que los nombres definidos por el informe deben configurarse en consecuencia si desea un comportamiento de deduplicación personalizado

#### **¿Cómo interactúan los Tests entre sí?**

Los Tests toman sus datos de testing y los agrupan en Hallazgos. Por lo general, los equipos de seguridad ejecutan el mismo esfuerzo de testing de manera repetida, y los Tests en DefectDojo le permiten gestionar este proceso de forma elegante.

**Los tests importados previamente se pueden reimportar** \- Si está ejecutando el mismo tipo de test dentro del mismo contexto de Compromiso, puede Reimportar los resultados del test después de cada escaneo completado. DefectDojo comparará los datos Reimportados con el resultado existente, y no creará nuevos Hallazgos si existen duplicados en los datos del escaneo.

**Los Tests se pueden importar por separado** \- Si ejecuta el mismo test en un Activo dentro de Compromisos separados, DefectDojo igualmente comparará los datos con Tests anteriores para encontrar Hallazgos duplicados. Esto le permite hacer seguimiento de los Hallazgos previamente mitigados o con riesgo aceptado.

Si se agrega un Test directamente a un Activo sin un Compromiso, se creará automáticamente un Compromiso genérico para contenerlo. Esto permite importaciones de datos ad\-hoc.

**Ejemplos de Tests:**

* Burp Scan del 29 de oct. de 2015 al 29 de oct. de 2015
* Nessus Scan del 31 de oct. de 2015 al 31 de oct. de 2015
* API Test del 15 de oct. de 2015 al 20 de oct. de 2015

## **Hallazgos**

Una vez que se han añadido y cargado datos en un Test, los resultados de esos datos se enumerarán en el Test como **Hallazgos** individuales para su revisión.

Un hallazgo representa un fallo específico descubierto durante el testing.

Los Hallazgos siempre tienen:

* un **Nombre de Hallazgo** único
* la **Fecha** en que fueron descubiertos
* múltiples **Estados** asociados, como Activo, Verificado o Falso positivo
* un **Test** asociado
* un nivel de **Severidad**: Crítica, Alta, Media, Baja e Informativa (Info).

Los Hallazgos se pueden agregar mediante una importación de datos, pero también se pueden agregar manualmente a un Test.

**Ejemplos de Hallazgos:**

* OpenSSL 'ChangeCipherSpec' Vulnerabilidad potencial de MiTM
* Aplicación web potencialmente vulnerable a Clickjacking
* Protección XSS del navegador web no habilitada

## **Endpoints**

Los datos de escaneo generalmente contienen referencias a los hosts o endpoints afectados por un Hallazgo determinado.  DefectDojo agrega automáticamente los Hallazgos por endpoint, por lo que puede usar la vista de Endpoint para ver todos los Hallazgos que afectan a un Endpoint o Hostname determinado.

Ejemplos:
-   https://www.example.com
-   https://www.example.com:8080/products
-   192.168.0.36
