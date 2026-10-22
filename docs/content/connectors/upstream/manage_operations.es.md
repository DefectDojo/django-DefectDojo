---
title: Gestión de operaciones
description: Consulte el estado de las operaciones Discover y Sync de su Conector
aliases:
- /es/import_data/pro/connectors/manage_operations/
- /es/en/connecting_your_tools/connectors/manage_operations
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: los Conectores ascendentes son una función exclusiva de DefectDojo Pro.</span>

Una vez configurado un Conector ascendente, este ejecutará dos operaciones de forma recurrente:

* **Discover** aprenderá la estructura de la herramienta conectada, y creará registros en DefectDojo de cualquier dato sin asignar;
* **Sync** importará nuevos Hallazgos de la herramienta según sus asignaciones.

Ambas operaciones se gestionan en la página Operations de un Conector. La tabla también registrará las ejecuciones pasadas de estas operaciones para que pueda asegurarse de que su Conector esté actualizado.

Para acceder a la página Operations de un Conector, abra **Gestionar registros y operaciones** para el Conector con el que desea trabajar, y luego cambie a la pestaña **</\> Operations From (tool)**.

![image](images/operations_discover.png)

La página **Gestionar registros y operaciones** también se puede usar para gestionar Registros; que son las asignaciones de Producto individuales de su herramienta conectada.  Consulte [Gestión de registros](../manage_records) para más información.

## La página Operations

![image](images/operations_page.png)

Cada entrada en la tabla de la página Operations es un registro de un evento de operación, con las siguientes características:

* **Type** describe si el evento fue una operación **Sync** o **Discover**.
* **Status** describe si el evento se ejecutó correctamente.
* **Trigger** describe cómo se activó el evento \- ¿fue una operación **Scheduled** que se ejecutó automáticamente, o una operación **Manual** activada por un usuario de DefectDojo?
* La **Start \& End Time** de cada operación se registra aquí, junto con la **Duration**.

## Operaciones Discover

El primer paso que debe dar un Conector de DefectDojo es ejecutar **Discover** en el entorno de su herramienta, para ver cómo está organizando sus datos de escaneo.

Supongamos que tiene una herramienta BurpSuite configurada para escanear cinco repositorios distintos en busca de vulnerabilidades. Su Conector tomará nota de esta estructura organizativa y configurará **Registros** para ayudarle a traducir esos repositorios independientes a la jerarquía de Producto/Compromiso/Test de DefectDojo.

### Creación de nuevos registros

Cada vez que su Conector ejecuta una operación **Discover**, buscará nuevos **Vendor-Equivalent-Products (VEPs)**. DefectDojo observa cómo está configurada la herramienta del proveedor y creará **Registros** de VEPs según cómo esté organizada su herramienta.

![image](images/operations_discover_2.png)

### Ejecutar Discover manualmente

Las operaciones **Discover** se ejecutan automáticamente de forma periódica, pero también se pueden ejecutar manualmente. Si está configurando este Conector por primera vez, puede hacer clic en el botón **Discover** junto al encabezado **Registros sin asignar**. Después de actualizar la página, verá su lista inicial de **Registros**.

![image](images/operations_discover_3.png)

Para obtener más información sobre cómo trabajar con registros y configurar asignaciones a Productos, consulte nuestra guía de [Gestión de registros](../manage_records).

## Operaciones Sync

Diariamente, DefectDojo revisará cada **Registro asignado** en busca de nuevos datos de escaneo. Luego, DefectDojo ejecutará un **Reimport**, que compara el estado de los datos de escaneo existentes con un informe entrante.

### ¿Dónde se almacenan los datos de vulnerabilidades?

* DefectDojo creará un **Compromiso** anidado bajo el Producto especificado en la **asignación de Registro**. Este Compromiso se llamará **Global Connectors**.
* El Compromiso **Global Connectors** registrará cada Conector independiente asociado con el Producto como un **Test**.
* En esta sincronización, y en cada sincronización posterior, el **Test** almacenará cada vulnerabilidad encontrada por la herramienta como un **Hallazgo**.

### Cómo gestiona Sync los nuevos datos de vulnerabilidades

Cada vez que se ejecuta Sync, comparará los datos de escaneo más recientes con la lista existente de Hallazgos en busca de cambios.

* Si se detectan nuevos Hallazgos, se añadirán al Test como nuevos Hallazgos.
* Si hay Hallazgos que no se detectan en el escaneo más reciente, se marcarán como Inactivos en el Test.

Para obtener más información sobre Productos, Compromisos, Tests y Hallazgos, consulte nuestra [Descripción general de la jerarquía de productos](/asset_modelling/os_hierarchy/product_hierarchy/).

### Ejecutar Sync manualmente

Para hacer que DefectDojo ejecute una operación Sync fuera de programación:

1. Navegue a la página **Gestionar registros y operaciones** del conector que desea usar. Desde la página **Conectores ascendentes**, haga clic en el menú desplegable **Gestionar configuración** del Conector con el que desea trabajar, y seleccione **Gestionar registros y operaciones**.
​
2. Desde esta página, haga clic en el botón **Sync**. Este botón se encuentra junto al encabezado **Registros asignados**.

![image](images/operations_sync.png)
