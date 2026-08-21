---
title: Agregar o editar Conectores ascendentes
description: Conéctese a una herramienta de seguridad compatible
aliases:
- /es/import_data/pro/connectors/add_edit_connectors/
- /es/en/connecting_your_tools/connectors/add_edit_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: los Conectores ascendentes son una función exclusiva de DefectDojo Pro.</span>

El proceso para agregar y configurar un Conector ascendente es similar, sin importar la herramienta que intente conectar. Sin embargo, algunas herramientas pueden requerir que cree claves de API o complete pasos adicionales.

Antes de comenzar este proceso, le recomendamos consultar nuestra [Referencia específica por herramienta](../../toolreference/upstream/) para encontrar los recursos de API de la herramienta que intenta conectar.

1. Si aún no lo ha hecho, comience **cambiando a la interfaz Pro** en DefectDojo.
2. En el menú del lado izquierdo, abra el grupo **Conectores** anidado bajo el encabezado **Importar**, y haga clic en **Conectores ascendentes**.
​
![image](images/add_edit_connectors.png)

3. Elija un nuevo Conector que desee agregar a DefectDojo en **Conectores disponibles**, y haga clic en el botón **Agregar configuración** de la tarjeta de la herramienta. Puede usar el cuadro **Buscar conectores** para filtrar cada sección por nombre de herramienta, o el interruptor **All / Asset / Finding** en el encabezado de la página para filtrar por tipo de conector.
​
También puede editar un Conector existente en el encabezado **Conectores configurados**. Haga clic en **Gestionar configuración \> Editar configuración** para el Conector configurado que desea editar.
​
![image](images/add_edit_connectors_2.png)

4. Necesitará una **URL de ubicación** accesible para la herramienta, junto con una clave **Secret** de API. La ubicación de la clave de API dependerá de la herramienta que esté intentando configurar. Consulte nuestra [Referencia específica por herramienta](../../toolreference/upstream/) para más detalles.
​
5. Establezca una **Etiqueta** para esta conexión que le ayude a identificarla en DefectDojo.
​
6. Programe el descubrimiento y la sincronización automáticos del Conector usando las programaciones **Configuración de descubrimiento** y **Configuración de sincronización**. Estas se pueden cambiar más adelante.
​
7. Seleccione si desea **habilitar Auto-Mapping**. Al habilitar Auto-Mapping se creará un nuevo Producto en DefectDojo para almacenar los datos de este conector. Auto-Mapping se puede activar o desactivar en cualquier momento.
​
8. Haga clic en **Enviar.**

![image](images/add_edit_connectors_3.png)

## Próximos pasos

* Ahora que ha agregado un conector, puede confirmar que todo esté configurado correctamente ejecutando una operación de [Discover](../manage_operations/#discover-operations).
