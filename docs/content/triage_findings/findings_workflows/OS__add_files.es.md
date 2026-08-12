---
title: Adjuntar archivos
description: Cargue capturas de pantalla, informes u otros archivos de respaldo a
  un Hallazgo, Compromiso o Test en DefectDojo OS
audience: opensource
weight: 3
aliases:
- /es/triage_findings/findings_workflows/add_files/
---

Puede adjuntar archivos a un **Hallazgo**, un **Compromiso** o un **Test** para aportar contexto de respaldo — por ejemplo, una captura de pantalla de una prueba de concepto, un informe sin procesar de un escáner, un diagrama de red o una hoja de cálculo que respalde un resultado.

Cada objeto mantiene su propio conjunto de archivos, y puede adjuntar **hasta 10 archivos** a un mismo objeto.

## Tipos de archivo admitidos

De forma predeterminada, se aceptan las siguientes extensiones:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Los administradores pueden cambiar esta lista con la variable de entorno `DD_FILE_UPLOAD_TYPES`.
El formulario rechaza la carga de un archivo cuya extensión no esté en la lista.

Los archivos de imagen (como `.png` y `.jpeg`) se muestran como una vista previa en miniatura, mientras que los demás
tipos de archivo se muestran con un ícono genérico. En ambos casos, al hacer clic en el archivo se descarga.

## Cómo adjuntar un archivo a un Hallazgo

1. Abra el Hallazgo al que desea adjuntar un archivo.
2. Abra el menú de acciones (el botón **☰** en la parte superior derecha del Hallazgo) y haga clic en
   **Manage Files**.

   ![Manage Files en el menú de acciones del Hallazgo](images/OS_manage_files_menu.png)

3. En la página **Add files**, ingrese un **Title** para el archivo y elija el archivo desde su
   computadora. Puede agregar hasta tres archivos a la vez; guarde y vuelva a ingresar para agregar más si es necesario.

   ![El formulario de carga de Manage Files](images/OS_manage_files_form.png)

4. Haga clic en **Save**.

El archivo aparece entonces en el panel **Files** del Hallazgo. Los archivos de imagen se muestran como una
miniatura:

![Panel Files en un Hallazgo mostrando una captura de pantalla adjunta](images/OS_finding_files_panel.png)

## Adjuntar archivos a Compromisos y Tests

Los Compromisos y los Tests usan el mismo flujo de trabajo de **Manage Files**:

- En la página de detalle de un **Compromiso** o **Test**, abra el panel **Files** y haga clic en su botón de edición
  (el lápiz), y luego agregue archivos exactamente como lo haría con un Hallazgo.

Al igual que con los Hallazgos, los archivos adjuntos de imagen se muestran como una miniatura y los demás tipos de archivo muestran un
ícono genérico.

## Ver y descargar archivos

Los archivos adjuntos aparecen en el panel **Files** de la página de detalle del objeto. Haga clic en cualquier archivo para
descargarlo. El acceso se verifica según los permisos: un usuario debe tener permiso de **view** sobre el
Hallazgo, Compromiso o Test superior para poder descargar sus archivos.

## Eliminar archivos

Para eliminar un archivo, abra **Manage Files** para el objeto, marque la casilla **Delete** debajo de
el archivo que desea eliminar, y haga clic en **Save**.
