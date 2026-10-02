---
title: Cómo evitar duplicados excesivos
description: ''
weight: 4
aliases:
- /es/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport
---

Uno de los puntos fuertes de DefectDojo es que su modelo de datos puede adaptarse a muchos casos de uso y aplicaciones diferentes. Es probable que cambie su enfoque a medida que domine el software y descubra formas de optimizar su flujo de trabajo.

De forma predeterminada, DefectDojo no elimina ningún Hallazgo duplicado que se cree. Cada Hallazgo se considera una instancia independiente de una vulnerabilidad. Por lo tanto, en este caso, los **Hallazgos duplicados** pueden ser un indicador de que se necesita un cambio de proceso en su flujo de trabajo.

## ¿Cuándo son aceptables los Hallazgos duplicados?

Los Hallazgos duplicados no siempre indican un problema. Hay muchos casos en los que conservar los duplicados es el enfoque preferido. Por ejemplo:

* Si su equipo usa e informa sobre Compromisos interactivos. Si desea crear un informe independiente sobre un Test en concreto, querrá saber si existe una repetición de un Hallazgo que ya se había descubierto anteriormente.
* Si tiene Compromisos que están contextualmente separados (por ejemplo, porque cubren repositorios diferentes), querrá poder marcar los Hallazgos que se producen en ambos lugares.

## Comprobación de importaciones redundantes

## Paso 1: Depure sus Duplicados excesivos

Afortunadamente, la configuración de Deduplicación de DefectDojo le permite eliminar duplicados de forma masiva una vez que se ha superado un determinado umbral. Esta función facilita el proceso de depuración. Para obtener más información sobre este proceso, consulte nuestro artículo sobre **Deduplicación de Hallazgos** \<\-el enlace se colocará aquí.

### Paso 2: Evalúe sus Compromisos en busca de redundancias

Una vez que haya depurado sus Hallazgos duplicados, es una buena práctica examinar el Producto que los contenía para ver si hay un culpable evidente. Puede que descubra que contiene Compromisos con un contexto redundante.

#### Compromisos duplicados o reutilizados

Los Compromisos almacenan uno o más Tests para un contexto de test determinado. En última instancia, ese contexto lo define usted, pero si observa varios Compromisos dentro de su Producto que deberían compartir el mismo contexto, considere combinarlos en un único compromiso.
​
### Preguntas que debe hacerse al definir el contexto de un Compromiso:

* Si quisiera elaborar un informe sobre este trabajo, ¿contendría el Compromiso toda la información relevante que necesito?
* ¿Estamos creando los Compromisos de forma proactiva y con antelación, o se crean "ad-hoc" mediante mi proceso de importación?
* ¿Estamos usando el tipo correcto de Compromiso: **Interactivo** o **CI/CD**?
* ¿Qué sección del código base están trabajando los tests: es cada repositorio un contexto separado, o podrían varios repositorios formar un contexto compartido para las pruebas?
* ¿Quiénes son las partes interesadas involucradas con el Producto, y cómo compartiré los resultados con ellas?

### Paso 3: Compruebe si hay Tests redundantes

Si descubre que se han creado Tests independientes que capturan el mismo contexto de test, esto puede ser un indicador de que esos tests se pueden consolidar en una única Reimportación.

DefectDojo tiene dos métodos para importar datos de test y crear Hallazgos: **Importación** y **Reimportación**. Ambos métodos son muy similares, pero la diferencia clave entre ellos es que la **Importación** siempre crea un nuevo Test, mientras que la **Reimportación** puede añadir nuevos datos a un Test existente. También vale la pena señalar que la **Reimportación** no crea Hallazgos duplicados dentro de ese Test.

Cada vez que importa nuevos informes de vulnerabilidades a DefectDojo, esos informes se almacenan en un objeto Test. Un usuario puede crear un objeto Test con antelación para alojar una futura **Importación**. Si un usuario desea importar datos sin especificar un Test de destino, se creará un nuevo Test para almacenar el informe entrante.

Los Tests son objetos flexibles y, aunque solo pueden alojar un *tipo* de informe, pueden gestionar múltiples instancias de ese mismo informe mediante el método de **Reimportación**. Para obtener más información sobre la Reimportación, consulte nuestro **[artículo](/import_data/import_intro/reimport/)** sobre este tema.


## Uso de la Reimportación para Tests continuos

Si tiene un pipeline de CI/CD, un proceso de escaneo diario o cualquier tipo de informe entrante repetido, configurar de antemano un proceso de Reimportación es clave para evitar duplicados excesivos. La Reimportación consolida el contexto y los Hallazgos asociados a un test recurrente en una única página de Test, donde puede revisar el historial de importación y hacer seguimiento de los cambios en las vulnerabilidades a lo largo de los escaneos.

1. Cree un Compromiso para almacenar los resultados de CI/CD del objeto sobre el que ejecuta CI/CD. Esto podría ser un repositorio de código en el que tiene configuradas acciones de CI/CD para ejecutarse. Por lo general, conviene tener un Compromiso independiente configurado para cada pipeline, de modo que pueda entender rápidamente de dónde provienen los resultados de los Hallazgos.
​
2. Cada acción de CI/CD importará datos a DefectDojo en un paso independiente, por lo que cada una de ellas debe corresponderse con un Test independiente. Por ejemplo, si cada ejecución del pipeline ejecuta un NPM-audit además de un escaneo de dependencias, cada resultado de escaneo deberá fluir hacia un Test (anidado bajo el Compromiso).
​
3. No es necesario crear un nuevo Test cada vez que se ejecuta la acción de CI/CD. En su lugar, puede **Reimportar** los datos a la misma ubicación de test.

### La Reimportación en acción

DefectDojo comparará los datos del escaneo entrante con los datos del escaneo existente y, a continuación, aplicará cambios a los Hallazgos contenidos en su Test de la siguiente manera:
​
#### Crear Hallazgos

Cualquier vulnerabilidad que no estuviera contenida en la importación anterior se añadirá automáticamente al Test como un nuevo Hallazgo.
​
#### Ignorar Hallazgos existentes

Si algún Hallazgo entrante coincide con Hallazgos que ya existen, los Hallazgos entrantes se descartarán en lugar de registrarse como Duplicados. Estos Hallazgos ya se habían registrado, por lo que no es necesario añadir un nuevo objeto Hallazgo. La página del Test mostrará estos Hallazgos como **Sin modificar**.
​
#### Cerrar Hallazgos

Si existen Hallazgos que ya están presentes en el Test pero que no aparecen en el informe entrante, puede optar por establecer automáticamente esos Hallazgos como Inactivos y Mitigados (bajo el supuesto de que esas vulnerabilidades se han resuelto desde la importación anterior). La página del Test mostrará estos Hallazgos como **Cerrados**.

Si no desea que se cierre ningún Hallazgo, puede desactivar este comportamiento en la Reimportación:

* Desmarque la casilla **Cerrar Hallazgos antiguos** si usa la interfaz
* Establezca **close\_old\_findings** en **False** si usa la API  ​

#### Reabrir Hallazgos

* Si hay Hallazgos Cerrados que vuelven a aparecer en una Reimportación, se Reabrirán automáticamente. Se asume que esas vulnerabilidades han vuelto a producirse, a pesar de la mitigación anterior. La página del Test hará seguimiento de estos Hallazgos como **Reactivados**.

Si usa un escáner sin triaje, o si por algún otro motivo no desea que los Hallazgos Cerrados se reactiven, puede desactivar este comportamiento en la Reimportación:

* Establezca **do\_not\_reactivate** en **True** si usa la API
* Marque la casilla **No reactivar** si usa la interfaz

### Trabajar con el historial de importación

El historial de importación de un test determinado aparece bajo el encabezado **Resumen del Test** en la página del **Test**.

Esta tabla muestra cada Importación o Reimportación como una sola línea con una **Marca de tiempo**, junto con las columnas **Etiqueta de rama, ID de compilación, Hash de commit** y **Versión**, si se especificaron.

![image](images/Avoiding_Duplicates_Reimport_Recurring_Tests.png)

### Acciones

Este encabezado indica las acciones realizadas por una Importación/Reimportación.

* **N.º de creados indica el número de nuevos Hallazgos creados en el momento de la Importación/Reimportación**
* **N.º de cerrados muestra el número de Hallazgos que se cerraron mediante una Reimportación (por no existir en el informe entrante).**
* **N.º de sin modificar muestra el recuento de Hallazgos abiertos que no cambiaron con una Reimportación (porque también existían en el informe entrante).**
* **N.º de reactivados** muestra los Hallazgos Cerrados que se reabrieron mediante una Reimportación entrante.

### ¿Por qué no usar simplemente la Importación?

Aunque ambos métodos son posibles, la Importación debe reservarse para **apariciones nuevas** de Hallazgos y datos, mientras que la Reimportación debe aplicarse para **iteraciones posteriores** de los mismos datos.

Si su pipeline de CI/CD ejecuta una Importación y crea un nuevo objeto Test cada vez, cada Importación le dará una colección de Hallazgos independientes que luego tendrá que gestionar como objetos separados. Usar la Reimportación alivia este problema y elimina la cantidad de "depuración" que tendrá que hacer cuando se resuelva una vulnerabilidad.

Usar la Reimportación le permite almacenar cada informe recurrente en la misma página y mantiene una continuidad de cada momento en que se añadieron nuevos datos al Test.

Sin embargo, si usa la misma herramienta de escaneo en varias ubicaciones o contextos, puede ser más adecuado crear un Test independiente para cada ubicación o contexto. Esto depende de su método de organización preferido.
