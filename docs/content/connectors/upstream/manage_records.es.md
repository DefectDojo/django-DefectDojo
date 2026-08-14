---
title: Gestión de registros
description: Dirija el flujo de datos desde su herramienta hacia DefectDojo
aliases:
- /es/import_data/pro/connectors/manage_records/
- /es/en/connecting_your_tools/connectors/manage_records
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: los conectores Upstream son una función exclusiva de DefectDojo Pro.</span>

Una vez que haya ejecutado su primera operación de Descubrir, debería ver una lista de registros Asignados o No asignados en la página **Administrar registros y operaciones**.

## ¿Qué es un registro?

Un registro es una conexión entre un **Producto** de DefectDojo y un **producto equivalente del proveedor**. Puede usar su lista de registros para controlar el flujo de datos entre su herramienta y DefectDojo.

Los registros se crean y se actualizan durante la operación **[Descubrir](../manage_operations/#discover-operations)**, que DefectDojo ejecuta a diario para buscar nuevos productos equivalentes del proveedor.

![image](images/manage_records.png)

Los registros tienen varios atributos, entre ellos:

* El **Estado** del registro
* El **Producto** al que el registro importa datos
* Cuándo el registro fue **descubierto por primera y última vez** (mediante el proceso de **Descubrir**)
* Cuándo la asignación del registro fue **finalizada** por un usuario
* Un enlace al **Producto** de DefectDojo

## Cómo se asignan los registros

Cada registro debe tener una asignación configurada. La asignación indica a DefectDojo dónde almacenar los datos de escaneo de la herramienta. Un registro asignado vincula el producto equivalente del proveedor con un Producto de DefectDojo, e indica al conector que comience a importar datos de escaneo a esa ubicación (como Compromisos y Tests).

Puede asignar las asignaciones usted mismo, o hacer que DefectDojo las asigne automáticamente. 

### Asignación automática

Si tiene habilitada la **Asignación automática**, los nuevos registros se asignarán a Productos automáticamente. Cada vez que DefectDojo **descubre** un nuevo registro, se crea automáticamente un Producto de DefectDojo correspondiente para cada registro**.** Ese registro se almacenará en **Registros asignados** para indicar que está listo para importar datos a DefectDojo.

Si no tiene habilitada la Asignación automática, puede decidir usted mismo hacia dónde quiere que fluyan los datos. Cada vez que el conector encuentra un nuevo producto equivalente del proveedor (mediante **Descubrir**), añadirá un nuevo registro a su lista de **Registros no asignados**, y luego podrá asignar manualmente ese registro a un Producto nuevo o existente en DefectDojo.

#### Asignación: flujo de trabajo de ejemplo

David acaba de terminar de configurar un conector para su herramienta BurpSuite y ejecuta una operación de Descubrir. David tiene Burp configurado para escanear 4 'Sites' diferentes, y DefectDojo crea un nuevo registro para cada uno de esos Sites.

* Si David decide usar la Asignación automática, DefectDojo creará un nuevo Producto para cada Site. A partir de ese momento, cuando DefectDojo ejecute una operación de Sincronizar, el conector importará los datos de escaneo directamente desde el Site al Producto (mediante la asignación del registro)  
​
* Si David deja desactivada la Asignación automática, DefectDojo igualmente descubrirá esos 4 Sites y creará los registros, pero no importará ningún dato hasta que David cree las asignaciones él mismo.  
​
* David siempre puede cambiar más adelante cómo están configuradas estas asignaciones. Tal vez quiera consolidar la salida de varios Sites de Burp diferentes en un único Producto. O tal vez busque tener un Producto que registre datos de escaneo de varias herramientas distintas, incluido Burp. A David le resulta sencillo cambiar dónde se almacenan los datos de escaneo de Burp en DefectDojo modificando la asignación de estos registros.

## Cómo interactúan los registros con los productos

Una vez que un registro está asignado, DefectDojo estará listo para importar los escaneos de su herramienta mediante una operación de Sincronización. Los conectores pueden funcionar junto con otros procesos de importación de DefectDojo o con pruebas interactivas.

* Las asignaciones de registros están diseñadas para ser no invasivas. Si asigna un Producto a un registro que contiene Compromisos o Hallazgos existentes, esos Compromisos y Hallazgos existentes no se verán afectados ni sobrescritos por el proceso de sincronización de datos.  
​
* Todos los datos creados mediante un conector se almacenarán en un único Compromiso llamado **Global Connectors**. Ese Compromiso creará un Test independiente para cada conector asignado al Producto.

![image](images/manage_records_2.jpg)

Esto permite enviar datos de escaneo de varios conectores al mismo Producto. Todos los datos se almacenarán en el mismo Compromiso, pero cada conector almacenará sus datos en un Test independiente.

Para obtener más información sobre Productos, Compromisos y Tests, consulte nuestra [descripción general de la jerarquía de productos](/asset_modelling/os_hierarchy/product_hierarchy/).

## Estados de los registros: glosario

Cada registro tiene un estado asociado que indica cómo está funcionando.

Se accede a la lista completa de registros de un conector abriéndolo desde **Conectar \> Upstream**; la página se titula **Todos los registros de \<Conector\>**. A pesar de su nombre, muestra todos los registros que pertenecen a **ese conector en particular**, no todos los registros de la instancia.

Esa lista se puede **filtrar por estado** desde la columna **Estado**, y se puede seleccionar más de un estado a la vez. Esta es la forma más rápida de responder a las preguntas que surgen con más frecuencia en una flota grande de conectores: *¿qué está esperando que yo lo asigne?* (**Nuevo**) y *¿qué ha dejado de reportar?* (**Ausente** o **Error**), sin tener que revisar cada registro.

No todos los estados se aplican a todos los conectores. El estado **Obsoleto** lo establece el proceso de importación de hallazgos, por lo que solo se produce en conectores que importan hallazgos; los **conectores de activos** nunca entran en ese estado, y no se ofrece como opción de filtro para ellos.

### Nuevo

Un registro Nuevo es un registro no asignado que DefectDojo ha descubierto. Se puede asignar a un Producto o ignorar. Para asignar un nuevo registro a un Producto, consulte nuestra guía sobre [Edición de registros]().

### Correcto

'Correcto' indica que un registro está asignado y funciona correctamente. Las futuras operaciones de Descubrir comprueban si el producto equivalente del proveedor subyacente todavía existe, para garantizar que la operación de Sincronización se ejecute correctamente.

### Ignorado

Los registros 'Ignorados' se han descubierto correctamente, pero un usuario de DefectDojo ha decidido no asignar los datos a un Producto.

## Estados de advertencia: Obsoleto o Ausente

Si la conexión entre la herramienta y DefectDojo cambia, el estado de un registro cambiará para indicárselo.

### Obsoleto

Una asignación pasa a 'Obsoleto' cuando se elimina de DefectDojo un Producto, Compromiso o Test relacionado. La asignación sigue existiendo, pero ya no hay ningún lugar en DefectDojo al que puedan importarse los datos de la herramienta.

Los registros obsoletos se pueden volver a asignar a un Producto existente, o ignorarse si los datos de escaneo ya no son relevantes.

### Ausente

Si un registro ha sido asignado, pero DefectDojo no detecta los datos de origen (o el producto equivalente del proveedor), el registro se etiquetará como **Ausente**. 

Los conectores de DefectDojo se adaptan a cambios de nombre, cambios de directorio y otras variaciones en los datos, por lo que esto probablemente se deba a que el producto equivalente del proveedor relacionado se eliminó de la herramienta que está utilizando.

Si su intención era eliminar el producto equivalente del proveedor de su herramienta, puede eliminar un registro Ausente. Si no es así, deberá solucionar el problema dentro de la herramienta para que los datos de origen puedan descubrirse correctamente.

### Error

**Error** indica que DefectDojo no pudo procesar el registro. Está disponible en todos los tipos de conector y se puede seleccionar en el filtro **Estado** junto con los estados anteriores, lo que lo convierte en la forma más rápida de comprobar si algo en un conector necesita atención después de una ejecución.

## Editar registros: reasignar, ignorar o eliminar

Los registros se pueden editar, ignorar o eliminar desde la página **Administrar registros y operaciones**.

Aunque los registros asignados y no asignados se encuentran en tablas separadas, ambos se pueden editar de la misma manera.

En la tabla de registros, haga clic en la flecha azul ▼ situada junto a la columna Estado de un registro determinado. Desde allí, puede seleccionar **Editar registro,** o **Eliminar registro.**

![image](images/edit_ignore_delete_records.png)

### Cambiar la asignación de un registro

Al hacer clic en **Editar registro** se abrirá una ventana que le permite cambiar el Producto de destino en DefectDojo. Puede seleccionar un Producto existente en el menú desplegable, o escribir el nombre de un nuevo Producto que desee crear.

![image](images/edit_ignore_delete_records_2.png)

Los datos de escaneo asociados a un registro se pueden dirigir hacia un Producto diferente cambiando la asignación. 

Seleccione, o escriba el nombre de un nuevo Producto, en el menú desplegable de la derecha.

#### Editar el estado de un registro

El Estado de un registro también se puede cambiar desde este menú. Los registros se pueden cambiar de Correcto a Ignorado (o viceversa) eligiendo una opción en la lista desplegable **Estado**.

### Ignorar un registro

Si desea 'desactivar' uno de los registros o descartar los datos que envía a DefectDojo, puede optar por 'Ignorar' el registro. Un registro 'Ignorado' pasará a la lista de registros no asignados y no enviará ningún dato nuevo a DefectDojo. 

Puede ignorar un registro asignado (lo que eliminará la asignación), o un registro Nuevo (desde la lista de registros no asignados).

#### Restaurar un registro ignorado

Si desea quitar el estado Ignorado de un registro, puede volver a cambiarlo a Nuevo con el mismo menú desplegable de Estado. 

* Si la Asignación automática de registros está habilitada, el registro volverá a su asignación original una vez que se vuelva a ejecutar la operación de Descubrir.  
* Si la Asignación automática de registros no está habilitada, DefectDojo no restaurará automáticamente una asignación anterior, por lo que deberá configurar de nuevo la asignación de este registro.

### Eliminar un registro

También puede eliminar registros, lo que los eliminará de la tabla de registros no asignados o asignados. 

Tenga en cuenta que la función Descubrir siempre importará todos los registros de una herramienta, lo que significa que, aunque se elimine un registro de DefectDojo, volverá a descubrirse más adelante (y regresará a la lista de registros por asignar).

* Si tiene previsto eliminar el producto equivalente del proveedor subyacente de su herramienta de escaneo, eliminar el registro es una buena opción. De lo contrario, la próxima operación de Descubrir detectará que faltan los datos asociados, y este registro cambiará su estado a 'Ausente'.  
​
* Sin embargo, si el producto equivalente del proveedor subyacente todavía existe, se volverá a descubrir en una futura operación de Descubrir. Para evitar este comportamiento, puede optar por ignorar el registro.

#### ¿Esto afecta a los datos ya importados?

No. Todos los Hallazgos, Tests y Compromisos creados por un registro de sincronización permanecerán en DefectDojo incluso después de eliminar el registro. Eliminar un registro o una configuración solo eliminará el proceso de flujo de datos, y no eliminará ningún dato de vulnerabilidades de DefectDojo ni de su herramienta.
