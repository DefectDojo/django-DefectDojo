---
title: Análisis de infraestructura / Smart Upload
description: Enruta automáticamente los Hallazgos entrantes al Producto correcto
weight: 3
audience: pro
aliases:
- /es/en/connecting_your_tools/import_scan_files/smart_upload
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Smart Upload solo está disponible en DefectDojo Pro.</span>

Smart Upload es un importador especializado que ingiere informes de **herramientas de análisis de infraestructura**, entre ellas:

* Nexpose
* NMap
* OpenVas
* Qualys
* Tenable

Smart Upload es único porque puede dividir los Hallazgos de un archivo de análisis en Productos independientes. Esto es relevante en un contexto de análisis de infraestructura, donde los Hallazgos pueden aplicarse a muchos equipos distintos, tener SLA implícitos diferentes, o necesitar incluirse en informes separados según el lugar de la infraestructura donde se descubrieron.

Smart Upload resuelve esto clasificando los hallazgos entrantes según los Endpoints descubiertos en el análisis. Al principio, esos Hallazgos deberán asignarse manualmente, o dirigirse al Producto correcto desde una lista de Hallazgos sin asignar. Sin embargo, una vez que un Hallazgo se ha asignado a un Producto, todos los Hallazgos posteriores que compartan un Endpoint o Host se enviarán a ese mismo Producto. Si ese Host está asociado a más de un Producto, el Hallazgo se envía a cada uno de ellos (consulte más abajo).

## Opciones del menú de Smart Upload

El menú de Smart Upload se encuentra en una sección plegable de la barra lateral.

* **Add Findings le permite importar un nuevo archivo de análisis, de forma similar al método Import Scan de DefectDojo**
* **Unassigned Findings enumera todos los Hallazgos de Smart Upload que aún no se han asignado a un Producto.**

![image](images/smart_upload.png)

### El formulario de Smart Upload

El formulario Smart Upload Import Scan es esencialmente igual al formulario Import Scan. Consulte nuestras notas sobre el **Import Scan Form** para más detalles.

![image](images/smart_upload_2.png)

## Unassigned Findings

Una vez completado un Smart Upload, cualquier Hallazgo que no se asigne automáticamente a un Producto (según su Endpoint) se colocará en la lista **Unassigned Findings**. El primer Smart Upload para una herramienta determinada aún no cuenta con ningún método para asignar Hallazgos, por lo que cada Hallazgo de ese archivo se enviará a esta página para su clasificación.

Los Hallazgos sin asignar no se incluyen en la Jerarquía de Productos y no aparecerán en informes, filtros ni métricas hasta que se hayan asignado.

### Trabajar con Hallazgos sin asignar

![image](images/smart_upload_3.png)

Puede seleccionar uno o más Hallazgos sin asignar para clasificarlos mediante la casilla de verificación, y realizar una de las siguientes acciones:

* **Assign to New Product, que creará un nuevo Producto**
* **Assign to Existing Product que moverá el Hallazgo a un Producto existente**
* **Disregard Selected Findings**, que eliminará el Hallazgo de la lista

Cuando un Hallazgo se asigna a un Producto nuevo o existente, se colocará en un Compromiso dedicado llamado ‘Smart Upload’. Este Compromiso contendrá un Test con el nombre correspondiente al Scan Type (por ejemplo, Tenable Scan). Los Hallazgos posteriores cargados mediante Smart Upload que coincidan con esos Endpoints se colocarán bajo ese Compromiso \> Test.

### Hallazgos descartados

Si un Hallazgo se descarta (Disregard), se eliminará de la lista Unassigned Findings. Sin embargo, el Hallazgo no quedará registrado en memoria, por lo que las cargas de análisis posteriores pueden hacer que el Hallazgo vuelva a aparecer en la lista Unassigned Findings.

## Hallazgos que coinciden con más de un Producto

Un mismo Host o Endpoint puede pertenecer a más de un Producto, por ejemplo un balanceador de carga compartido o un host que dos equipos rastrean. Cuando Smart Upload hace coincidir el Host de un Hallazgo entrante con varios Productos, no elige uno solo: crea una copia de ese Hallazgo en **cada** Producto coincidente, colocando cada copia en el Compromiso y el Test de Smart Upload propios de ese Producto.

Esto es intencionado. Cada Producto conserva una imagen completa de las vulnerabilidades que afectan a los hosts que posee, y los informes, los SLA y las métricas de cada Producto permanecen independientes.

La coincidencia se basa en el valor de Host descubierto en el análisis (el nombre de dominio completo y, en su defecto, la dirección IP), de modo que cualquier Producto que ya posea ese Host recibe una copia del Hallazgo.
