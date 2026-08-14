---
title: 🌐 Universal Parser
description: ''
draft: 'false'
weight: 1
audience: pro
aliases:
- /es/en/connecting_your_tools/universal_parser
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: El Universal Parser solo está disponible en DefectDojo Pro.</span>

El Universal Parser está activado en todas las instancias de DefectDojo Pro; no hay nada que habilitar. Consulte nuestra [presentación de anuncio](https://community.defectdojo.com/universalparser) para más información.

## Acerca del Universal Parser
DefectDojo cuenta con una biblioteca amplia y actualizada regularmente de parsers para ayudar a los equipos de seguridad a ingerir datos.  Sin embargo, a veces los usuarios tienen una herramienta que los parsers no admiten, o quieren importar datos al modelo de DefectDojo de una manera distinta a la que usa el parser.

El Universal Parser de DefectDojo está pensado para ofrecer a los usuarios con tipos de informes no admitidos una vía para avanzar, permitiéndoles importar y mapear **cualquier archivo JSON, CSV o XML**.

**El Universal Parser es:**

* Una forma rápida de admitir formatos de archivo para los que no contamos con parsers de la Comunidad, como los informes producidos por herramientas internas
* Una herramienta que le ayuda a ingerir datos, incluso si un parser de la Comunidad está desactualizado o no estructura los hallazgos como usted desea
* Una alternativa a la escritura de scripts personalizados para transformar informes de herramientas al formato CSV/JSON que espera el tipo de análisis "Generic Findings Import"
* Diseñado para que cualquiera pueda usarlo fácilmente, sin necesidad de programar y con una configuración mínima

**El Universal Parser no es:**

* Un reemplazo integral de los parsers de código abierto, los Connectors, o los informes "Generic Findings Import" cuidadosamente elaborados
* Capaz de manejar lógica condicional matizada para estructurar hallazgos

La configuración del Universal Parser solo está disponible en la interfaz Pro, aunque aún puede importar análisis mediante un Universal Parser a través de la interfaz antigua o de la API.

## Paso 1: Crear un nuevo Universal Parser

Puede crear un nuevo Universal Parser haciendo clic en el botón "New Universal Parser" en la barra de navegación, dentro de la sección "Import", o desde el enlace en la página "Add Findings".

![image](images/universal_parser.png)

La primera pantalla le pedirá un archivo de análisis y un nombre de parser.

![image](images/universal_parser_2.png)

El archivo debe:

* Tener una extensión reconocida (consulte las extensiones de archivo admitidas más abajo)
* Contener suficientes objetos similares a hallazgos como para ser representativo de informes reales, es decir, uno que incluya valores en todos los campos opcionales
* No superar aproximadamente 1-2MB - más allá de ese punto, en general solo se tardará más en analizar el archivo, sin ningún beneficio adicional

El nombre del parser se usará al crear el Test_Type para este nuevo parser. Encontrará su Universal Parser recién creado en el menú desplegable de tipos de análisis de la página "Add Findings" con un nombre como "Universal Parser - MyCustomParser". Los nombres de los parsers deben ser únicos para evitar confusiones al seleccionar un tipo de análisis para las importaciones.

## Paso 2: Mapear los campos de sus Hallazgos

![image](images/universal_parser_3.png)

Después de cargar un archivo de análisis de ejemplo, seleccionar un nombre de parser y hacer clic en "Next", la siguiente página le permitirá configurar cómo este Universal Parser completará los campos de hallazgo al usar esta configuración para realizar importaciones. A la derecha encontrará una selección de campos de hallazgo de DefectDojo (campos de salida). Los menús desplegables a la izquierda de cada campo de salida le permiten seleccionar qué elemento(s) (campos de entrada) de la estructura de su archivo de análisis deben usarse para completarlos.

Ejemplo:

Si cargó un archivo de análisis en formato JSON con un aspecto como este:

```
{
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345",
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "LOW",
            "CVE": "CVE-2025-54321",
            ...
        },
        ...

    ]
}
```

Verá una representación jerárquica de los campos únicos que detectamos según la estructura del archivo de entrada, con iconos que indican el tipo de cada campo (si podemos determinarlo). A continuación, puede seleccionar el campo de entrada "title" en el menú desplegable que completa el campo de salida "Title", el campo de entrada "description" puede asociarse con el campo de salida "Description", y así sucesivamente. 

Los nombres de los campos de entrada no tienen por qué coincidir con los nombres de los campos de salida, y es posible que su archivo de análisis no tenga un equivalente para todos los campos de salida de DefectDojo.

### Campos de hallazgo asignables

La siguiente tabla enumera todos los campos de hallazgo de DefectDojo (campos de salida) a los que puede asignar un campo de entrada. Su archivo de análisis no necesariamente tendrá un equivalente para todos ellos — asigne solo lo que esté presente.

* **Required** — este campo de salida debe tener al menos un campo de entrada asignado antes de poder guardar el parser.
* **Accepts multiple inputs** — este campo de salida puede completarse a partir de más de un campo de entrada. Cuando asigna varios, cada valor se presenta bajo un encabezado con el nombre de su campo de entrada (consulte [Campos de selección múltiple](#multi-select-fields)).

| Campo de salida | Required | Accepts multiple inputs | Descripción |
|---|:---:|:---:|---|
| Título | ✅ | | Breve descripción de la falla. |
| Severidad | ✅ | | El nivel de severidad de esta falla (Crítica, Alta, Media, Baja, Informativa). El valor predeterminado es "Info" si se desconoce. |
| Descripción | ✅ | ✅ | Información más extensa y descriptiva sobre la falla. |
| Fecha | | | La fecha en que se descubrió la falla. |
| CWE | | | El número CWE asociado con esta falla. |
| Vector CVSS v3 | | | Vector del Common Vulnerability Scoring System versión 3 (CVSSv3) asociado con esta falla. |
| Vector CVSS v4 | | | Vector del Common Vulnerability Scoring System versión 4 (CVSSv4) asociado con esta falla. |
| Mitigación | | ✅ | Texto que describe la mejor forma de corregir la falla. |
| Impacto | | ✅ | Texto que describe el impacto que esta falla tiene sobre sistemas, productos, la empresa, etc. |
| Referencias | | ✅ | La documentación externa disponible para esta falla. |
| Justificación de la severidad | | ✅ | Texto que describe por qué se asoció una determinada severidad a esta falla. |
| Pasos para reproducir | | ✅ | Texto que describe los pasos que deben seguirse para reproducir la falla o el error. |
| Nombre del componente | | | Nombre del componente afectado (nombre de la biblioteca, parte de un sistema, ...). |
| Versión del componente | | | Versión del componente afectado. |
| Ruta del archivo | | | Archivo(s) identificado(s) que contiene(n) la falla. |
| Número de línea | | | Número de línea de origen del vector de ataque. |
| Activo | | | Indica si esta falla está activa o no. El valor predeterminado es true. |
| Verificado | | | Indica si esta falla ha sido verificada manualmente por quien realizó la prueba. El valor predeterminado es false. |
| Falso positivo | | | Indica si esta falla ha sido considerada un falso positivo por quien realizó la prueba. El valor predeterminado es false. |
| Duplicado | | | Indica si esta falla es un duplicado de otras fallas reportadas. El valor predeterminado es false. |
| Puntuación EPSS | | | Puntuación EPSS para el CVE — la probabilidad de que la vulnerabilidad sea explotada en los próximos 30 días. El valor debe estar entre 0.0 y 1.0. |
| Percentil EPSS | | | Percentil EPSS para el CVE — cuántos CVE tienen una puntuación igual o inferior a esta. El valor debe estar entre 0.0 y 1.0. |
| ID único de la herramienta | | | ID técnico de la vulnerabilidad proveniente de la herramienta de origen. Permite el seguimiento de vulnerabilidades únicas. |
| ID de vulnerabilidad de la herramienta | | | ID técnico no único proveniente de la herramienta de origen, asociado con el tipo de vulnerabilidad. |
| Etiquetas | | | Etiquetas de texto que ayudan a describir este hallazgo. |
| Endpoints | | | Los hosts/URL dentro del producto que son susceptibles a esta falla. |
| IDs de vulnerabilidad | | | Uno o más identificadores de aviso de vulnerabilidad asociados con este hallazgo (más comúnmente, CVEs). |

> **Nota:** En el ejemplo anterior, un campo de entrada `CVE` se asignaría al campo de salida **IDs de vulnerabilidad** — DefectDojo no tiene un campo de hallazgo llamado literalmente "CVE".

### Campos obligatorios
Los siguientes campos de salida requieren una asignación de campo de entrada:

* Título
* Severidad
* Descripción

### Acerca de las severidades
Un Universal Parser aceptará cualquier variación de mayúsculas/minúsculas de las severidades de DefectDojo - "CRITICAL", "Critical", "cRiTiCaL", etc. - y la aplicará a sus hallazgos. Cualquier valor que no coincida con una severidad de DefectDojo se reemplazará por "Info". Esto refleja el funcionamiento actual de los parsers y los Connectors: los valores desconocidos generalmente se asignan a "Info".

### Campos de selección múltiple
Algunos campos de salida aceptan múltiples campos de entrada. Si decide seleccionar más de un campo de entrada, proporcionaremos el valor de ese campo bajo un encabezado con el nombre de dicho campo de entrada.

Ejemplo

`description`

Esto se extrajo de un campo llamado "description" en el archivo de entrada

`detailed_description`

Esto se extrajo de un campo llamado "detailed_description" en el archivo de entrada

## Paso 3: Vista previa de sus Hallazgos

Una vez que haya seleccionado sus asignaciones de campos de entrada a campos de salida, puede hacer clic en el botón "Next" para ver una vista previa de cómo se verán los Hallazgos de su archivo de entrada una vez importados a DefectDojo con la configuración elegida. Algunos campos tendrán un botón "expand" junto a ellos para permitirle ver el MarkDown completo, ya renderizado, de cómo se verá ese campo. Solo renderizaremos vistas previas de los primeros 25 Hallazgos de su archivo de entrada, pero también podrá ver cuántos hallazgos se detectaron en todo el archivo de análisis.

Si las vistas previas no se ven como esperaba, puede pulsar el botón "Back" para ajustar las asignaciones. Una vez que esté satisfecho con su configuración, haga clic en el botón "Submit" para crear su nuevo Universal Parser. Esto no realizará una importación automáticamente.

Una vez creado su Universal Parser, será redirigido a la página "Add Findings", donde podrá cargar e importar un archivo de análisis que coincida con la estructura del archivo de ejemplo que proporcionó en el Paso 1.

## Notas adicionales sobre la configuración del Universal Parser

### Elegir los campos de entrada correctos

Cada proveedor puede generar formatos de informe de análisis muy diferentes, algunos de los cuales se ajustan más al modelo de hallazgos de DefectDojo que otros. Permitimos una flexibilidad considerable en lo que aceptamos, pero debemos imponer cierta estructura para garantizar que los hallazgos no se distorsionen en la conversión de entrada a salida. Si bien podemos admitir campos de entrada opcionales, no aceptamos campos "globales", ni campos que aparezcan un número de veces distinto al número de objetos de hallazgo.

#### Ejemplo

```
{
    "scan_type": "MyToolScan", // <- There is only one instance of this field, which doesn't match the number of findings
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345", // <- This optional field only appears in Finding 1 - that's okay!
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "CRITICAL",
            ...  // <- While there is no "CVE" field here, we can still query for it and simply default to a null value
        },
        ... 5 more findings ...
    ],
    "global_details": [
        {
            "nested_detail": "Global detail 1"
        },
        {
            "nested_detail": "Global detail 2" // <- The number of "global_details" objects (2) does not match the number of individual finding objects (7)
        }

    ]
}
```

## Después de guardar un Universal Parser

Puede editar el Test_Type asociado con su Universal Parser para cambiar:
* Si está "active" o no. Si no lo está, no aparecerá como opción en el menú desplegable "Scan Type" de la página "Add Findings"
* Si sus hallazgos deben marcarse como "static" o "dynamic"
* Puede ajustar los códigos hash de deduplicación del mismo tipo de herramienta y entre herramientas distintas, así como los códigos hash de reimportación, para su Universal Parser en "Enterprise Settings". De forma predeterminada, solo se completan los códigos hash de deduplicación del mismo tipo de herramienta y de reimportación, con los valores obligatorios Título, Severidad y Descripción.

## Ciclo de vida: crear, desactivar, reactivar

El ciclo de vida de un Universal Parser es de **solo creación**, sin edición ni eliminación desde la interfaz. Una vez creado un parser, la configuración de asignación de campos no se puede modificar, y el parser en sí no se puede eliminar desde la interfaz — esto es intencional, porque las configuraciones del Universal Parser están vinculadas a registros de Test_Type que pueden estar referenciados por Hallazgos, Tests e historial de importación existentes.

Lo que **sí puede** hacer desde la interfaz:

* **Desactivar (Deactivate)** un parser para ocultarlo del menú desplegable "Scan Type" al importar. Abra **Import → Universal Parser** en la barra lateral para ver todos sus Universal Parsers, y desactive el interruptor "Active". (Alternativamente, puede editar el Test_Type subyacente y desmarcar "active"). Los parsers desactivados dejan de aparecer como opción de Scan Type en la página **Add Findings**, pero los Tests existentes que se importaron con este parser no se ven afectados y siguen funcionando.
* **Reactivar (Reactivate)** un parser desde la misma pantalla activando nuevamente el interruptor "Active".
* **Editar los campos de Test_Type** descritos en la sección anterior (activo/inactivo, static/dynamic, códigos hash de deduplicación).

### Flujo de trabajo recomendado cuando cambia el formato del informe de un escáner

Dado que la configuración de asignación de campos queda bloqueada una vez creado un parser, el flujo de trabajo estándar para gestionar un cambio de formato en el escáner subyacente es **avanzar hacia un nuevo parser** en lugar de intentar editar el anterior:

1. **Cree un nuevo Universal Parser** usando una muestra del nuevo formato de informe (consulte el Paso 1). Asígnele un nombre distinto — por ejemplo, agregando `v2` o una fecha al nombre original.
2. **Cambie las nuevas importaciones** en su pipeline de CI/CD o en el flujo de trabajo de la interfaz para usar el tipo de análisis del nuevo parser.
3. **Desactive el parser antiguo** una vez que haya confirmado que el nuevo produce los hallazgos esperados. Los Tests ya importados con el parser antiguo permanecen en DefectDojo y aún pueden ser triados; solo las nuevas importaciones se dirigen al nuevo parser.

Si necesita que se elimine permanentemente una configuración de parser (por ejemplo, porque contiene nombres de campos sensibles), contacte a [Soporte de DefectDojo](mailto:support@defectdojo.com).

## Una nota sobre la asignación de severidad

El Universal Parser **no** cuenta con un campo configurable de asignación de severidad. La severidad se asigna automáticamente con estas reglas:

* Se acepta cualquier variación de mayúsculas/minúsculas de una severidad de DefectDojo — `CRITICAL`, `Critical`, `cRiTiCaL`, `critical` se asignan todas a **Critical**. Lo mismo aplica para `High`, `Medium`, `Low` e `Info`.
* Cualquier valor que **no** coincida con una de las cinco severidades de DefectDojo se asigna a **Info**.

Este comportamiento es el mismo para todos los parsers de DefectDojo (parsers integrados, Connectors y Universal Parsers).

Si un escáner que intenta ingerir usa etiquetas de severidad que no coinciden con las de DefectDojo (por ejemplo, "warning", "note", o puntuaciones CVSS numéricas), el Universal Parser asignará todos esos valores no coincidentes a Info. Si necesita una asignación diferente, la mejor solución alternativa hoy en día es **transformar los valores de severidad previamente** — por ejemplo, en su pipeline de CI antes de cargar el archivo — de modo que los valores que recibe DefectDojo ya sean uno de los cinco nombres de severidad de DefectDojo.
