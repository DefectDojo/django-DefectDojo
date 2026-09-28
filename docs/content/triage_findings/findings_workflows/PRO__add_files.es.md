---
title: Adjuntar archivos
description: Cargue capturas de pantalla, informes u otros archivos de respaldo a
  un Hallazgo, Compromiso o Test en DefectDojo Pro
audience: pro
weight: 3
---

Puede adjuntar archivos a un **Hallazgo**, un **Compromiso** o un **Test** para aportar
contexto de respaldo — por ejemplo, una captura de pantalla de prueba de concepto, un informe sin procesar del escáner, un
diagrama de red o una hoja de cálculo que respalde un resultado.

Cada objeto mantiene su propio conjunto de archivos, y puede adjuntar **hasta 10 archivos** a un solo
objeto.

## Tipos de archivo admitidos

De forma predeterminada se aceptan las siguientes extensiones:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Los administradores pueden cambiar esta lista con la variable de entorno `DD_FILE_UPLOAD_TYPES`.
Se rechaza la carga de un archivo cuya extensión no esté en la lista.

## Cómo adjuntar un archivo a un Hallazgo

1. Abra el Hallazgo al que desea adjuntar un archivo.
2. Haga clic en el **menú de engranaje (⚙)** en la parte superior derecha del Hallazgo y elija **Agregar archivo**.
3. Ingrese un **Título** para el archivo y selecciónelo desde su computadora, luego guarde.

   ![La acción Agregar archivo en el menú de engranaje del Hallazgo, con la pestaña Archivos debajo](images/PRO_attach_files_menu.png)

El mismo menú de engranaje está disponible en las páginas de Compromiso y Test, por lo que los archivos pueden
adjuntarse a cualquiera de estos objetos de la misma manera.

## Ver y descargar archivos

Los archivos adjuntos se enumeran en la pestaña **Archivos** del **resumen del Hallazgo** (y en la
sección equivalente en Compromisos y Tests). Haga clic en el título de un archivo para descargarlo.

![La pestaña Archivos en un Hallazgo, mostrando un archivo adjunto](images/PRO_finding_files_tab.png)

El acceso está sujeto a verificación de permisos: un usuario debe tener permiso de **visualización** sobre el Hallazgo padre,
Compromiso o Test para descargar sus archivos.

## Eliminar archivos

Para eliminar un archivo, abra el menú de la fila del archivo (el icono **⋮**) en la pestaña **Archivos** y elija
**Eliminar archivo**. El mismo menú también ofrece **Editar nombre de archivo** para cambiar el nombre de un archivo adjunto.
